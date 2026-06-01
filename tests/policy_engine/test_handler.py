"""Tests for the policy engine (decision logic + dispatch), moto-backed."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from boto3.dynamodb.types import TypeSerializer
from moto import mock_aws

from policy_engine import handler as pe
from shared import rule_loader
from shared.models import Finding, FindingStatus, PolicyAction, Rule, Severity

REGION = "us-east-1"
FINDINGS_TABLE = "findings-test"
APPROVALS_TABLE = "approvals-test"
RULES_BUCKET = "rules-test"
PK = "111#us-east-1#iam"
SK = "arn:aws:iam::111:role/r#iam.unused_role"
ARN = "arn:aws:iam::111:role/r"

RULE_YAML = """\
rule: iam.unused_role
enabled: true
threshold:
  idle_days: 7
grace_period_days: 0
policy:
  default: prompt
  overrides:
    - match: { Environment: nonprod }
      action: auto
    - match: { tidewater-skip: "true" }
      action: skip
"""

_serializer = TypeSerializer()


def _rule(grace_days: int = 0, overrides: list[dict[str, Any]] | None = None) -> Rule:
    return Rule.model_validate(
        {
            "rule": "iam.unused_role",
            "threshold": {"idle_days": 7},
            "grace_period_days": grace_days,
            "policy": {
                "default": "prompt",
                "overrides": overrides
                if overrides is not None
                else [
                    {"match": {"Environment": "nonprod"}, "action": "auto"},
                    {"match": {"tidewater-skip": "true"}, "action": "skip"},
                ],
            },
        }
    )


def _finding(tags: dict[str, str], detected_at: datetime | None = None) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        account="111",
        region=REGION,
        service="iam",
        resource_arn=ARN,
        rule_id="iam.unused_role",
        severity=Severity.HIGH,
        detected_at=detected_at or now,
        last_seen_at=now,
        details={"role_name": "r", "tags": tags},
    )


# --------------------------------------------------------------- evaluate() (pure)
def test_default_action_when_no_override_matches() -> None:
    action, _ = pe.evaluate(_rule(), _finding(tags={}), datetime.now(UTC))
    assert action is PolicyAction.PROMPT


def test_tag_override_changes_action() -> None:
    action, reason = pe.evaluate(
        _rule(), _finding(tags={"Environment": "nonprod"}), datetime.now(UTC)
    )
    assert action is PolicyAction.AUTO
    assert "override" in reason


def test_multi_key_match_requires_all_keys() -> None:
    rule = _rule(overrides=[{"match": {"a": "1", "b": "2"}, "action": "auto"}])
    # `now` is computed per call (after the finding) so it's >= detected_at, as in
    # production — otherwise a 0-day grace check would see a negative interval.
    one_key = _finding(tags={"a": "1"})
    assert pe.evaluate(rule, one_key, datetime.now(UTC))[0] is PolicyAction.PROMPT
    both_keys = _finding(tags={"a": "1", "b": "2"})
    assert pe.evaluate(rule, both_keys, datetime.now(UTC))[0] is PolicyAction.AUTO


def test_grace_period_downgrades_auto_to_prompt() -> None:
    rule = _rule(grace_days=14)
    recent = datetime.now(UTC) - timedelta(days=2)
    action, reason = pe.evaluate(
        rule, _finding(tags={"Environment": "nonprod"}, detected_at=recent), datetime.now(UTC)
    )
    assert action is PolicyAction.PROMPT
    assert "grace" in reason


def test_zero_grace_allows_immediate_auto() -> None:
    action, _ = pe.evaluate(
        _rule(grace_days=0), _finding(tags={"Environment": "nonprod"}), datetime.now(UTC)
    )
    assert action is PolicyAction.AUTO


# --------------------------------------------------------------- handler (moto)
@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("FINDINGS_TABLE", FINDINGS_TABLE)
    monkeypatch.setenv("APPROVALS_TABLE", APPROVALS_TABLE)
    monkeypatch.setenv("RULES_BUCKET", RULES_BUCKET)
    monkeypatch.setenv("REMEDIATOR_FUNCTION_NAME", "remediator-fn")
    rule_loader.clear_cache()
    # Isolate side effects — these are covered by their own modules/tests.
    monkeypatch.setattr(pe, "emit_event", _spy())
    monkeypatch.setattr(pe, "write_audit_event", _spy())
    monkeypatch.setattr(pe, "_invoke_remediator", _spy())
    with mock_aws():
        _make_findings_table()
        _make_approvals_table()
        _seed_rule()
        yield SimpleNamespace(
            findings=boto3.resource("dynamodb", region_name=REGION).Table(FINDINGS_TABLE),
            approvals=boto3.resource("dynamodb", region_name=REGION).Table(APPROVALS_TABLE),
        )


class _Spy:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append((args, kwargs))


def _spy() -> _Spy:
    return _Spy()


def _context() -> Any:
    return SimpleNamespace(
        function_name="policy-engine",
        memory_limit_in_mb=512,
        invoked_function_arn="arn:aws:lambda:us-east-1:111:function:policy-engine",
        aws_request_id="req-1",
    )


def _make_findings_table() -> None:
    boto3.client("dynamodb", region_name=REGION).create_table(
        TableName=FINDINGS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
    )


def _make_approvals_table() -> None:
    boto3.client("dynamodb", region_name=REGION).create_table(
        TableName=APPROVALS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "approval_id", "AttributeType": "S"},
            {"AttributeName": "metadata", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "approval_id", "KeyType": "HASH"},
            {"AttributeName": "metadata", "KeyType": "RANGE"},
        ],
    )


def _seed_rule() -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=RULES_BUCKET)
    s3.put_object(Bucket=RULES_BUCKET, Key="rules/iam.unused_role.yaml", Body=RULE_YAML.encode())


def _put_finding(table: Any, tags: dict[str, str], *, decision: str = "dry_run") -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    item = {
        "pk": PK,
        "sk": SK,
        "account": "111",
        "region": REGION,
        "service": "iam",
        "resource_arn": ARN,
        "rule_id": "iam.unused_role",
        "status": "open",
        "severity": "high",
        "detected_at": now,
        "last_seen_at": now,
        "details": {"role_name": "r", "tags": tags},
        "policy_decision": decision,
    }
    table.put_item(Item=item)
    return item


def _stream_event(item: dict[str, Any], event_name: str = "INSERT") -> dict[str, Any]:
    image = {k: _serializer.serialize(v) for k, v in item.items()}
    return {
        "Records": [
            {
                "eventID": "1",
                "eventName": event_name,
                "eventSource": "aws:dynamodb",
                "dynamodb": {
                    "Keys": {"pk": image["pk"], "sk": image["sk"]},
                    "NewImage": image,
                    "StreamViewType": "NEW_AND_OLD_IMAGES",
                },
            }
        ]
    }


def test_prompt_path_creates_approval(aws: Any) -> None:
    item = _put_finding(aws.findings, tags={})  # no override → default prompt
    resp = pe.handler(_stream_event(item), _context())
    assert resp == {"batchItemFailures": []}

    approvals = aws.approvals.scan()["Items"]
    assert len(approvals) == 1
    assert approvals[0]["finding_sk"] == SK
    assert approvals[0]["status"] == "pending"
    assert pe.emit_event.calls and pe.emit_event.calls[0][0][0] == "approval.requested"
    finding = aws.findings.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert finding["policy_decision"] == "prompt"


def test_auto_path_invokes_remediator(aws: Any) -> None:
    item = _put_finding(aws.findings, tags={"Environment": "nonprod"})
    pe.handler(_stream_event(item), _context())

    assert pe._invoke_remediator.calls == [((PK, SK, "iam.unused_role"), {})]
    assert aws.approvals.scan()["Count"] == 0
    finding = aws.findings.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert finding["policy_decision"] == "auto"


def test_skip_path_marks_finding_skipped(aws: Any) -> None:
    item = _put_finding(aws.findings, tags={"tidewater-skip": "true"})
    pe.handler(_stream_event(item), _context())

    finding = aws.findings.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert finding["policy_decision"] == "skip"
    assert finding["status"] == FindingStatus.SKIPPED.value
    assert pe.emit_event.calls[0][0][0] == "finding.skipped"


def test_reevaluation_of_unchanged_prompt_ensures_single_approval(aws: Any) -> None:
    # Finding already carries the decision the engine would compute (prompt).
    item = _put_finding(aws.findings, tags={}, decision="prompt")
    pe.handler(_stream_event(item, event_name="MODIFY"), _context())

    # Decide and dispatch are separate: an unchanged decision still dispatches, so
    # the (single, idempotent) approval is ensured — but the remediator is never
    # invoked for a prompt decision.
    assert aws.approvals.scan()["Count"] == 1
    assert pe._invoke_remediator.calls == []
