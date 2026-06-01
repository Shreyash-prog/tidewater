"""Idempotency tests for policy-engine approval creation (moto-backed).

Regression for the bug where re-processing a `prompt` finding created a fresh
approval each time (the detector resets policy_decision to dry_run on every run,
so the policy engine re-dispatches PROMPT). With a deterministic approval_id
keyed on the finding's identity, at most one approval exists per finding.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from boto3.dynamodb.types import TypeSerializer
from moto import mock_aws

from policy_engine import handler as pe
from shared import rule_loader

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
"""

_serializer = TypeSerializer()


def test_approval_id_is_deterministic() -> None:
    first = pe.approval_id_for(PK, SK)
    assert first == pe.approval_id_for(PK, SK)  # same input → same id
    assert first.startswith("appr_")
    assert pe.approval_id_for(PK, "arn:aws:iam::111:role/other#iam.unused_role") != first


class _Spy:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        self.calls += 1


def _context() -> Any:
    return SimpleNamespace(
        function_name="policy-engine",
        memory_limit_in_mb=512,
        invoked_function_arn="arn:aws:lambda:us-east-1:111:function:policy-engine",
        aws_request_id="req-1",
    )


def _make_table(name: str, pk: str, sk: str) -> None:
    boto3.client("dynamodb", region_name=REGION).create_table(
        TableName=name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": pk, "AttributeType": "S"},
            {"AttributeName": sk, "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": pk, "KeyType": "HASH"},
            {"AttributeName": sk, "KeyType": "RANGE"},
        ],
    )


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("FINDINGS_TABLE", FINDINGS_TABLE)
    monkeypatch.setenv("APPROVALS_TABLE", APPROVALS_TABLE)
    monkeypatch.setenv("RULES_BUCKET", RULES_BUCKET)
    monkeypatch.setenv("REMEDIATOR_FUNCTION_NAME", "remediator-fn")
    rule_loader.clear_cache()
    # Isolate EventBridge / audit side effects; the approval write stays real.
    monkeypatch.setattr(pe, "emit_event", _Spy())
    monkeypatch.setattr(pe, "write_audit_event", _Spy())
    with mock_aws():
        _make_table(FINDINGS_TABLE, "pk", "sk")
        _make_table(APPROVALS_TABLE, "approval_id", "metadata")
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=RULES_BUCKET)
        s3.put_object(
            Bucket=RULES_BUCKET, Key="rules/iam.unused_role.yaml", Body=RULE_YAML.encode()
        )
        yield SimpleNamespace(
            findings=boto3.resource("dynamodb", region_name=REGION).Table(FINDINGS_TABLE),
            approvals=boto3.resource("dynamodb", region_name=REGION).Table(APPROVALS_TABLE),
        )


def _finding_item(last_seen_at: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {
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
        "last_seen_at": last_seen_at,
        # Detector resets this to dry_run on every run — the cause of the dup bug.
        "details": {"role_name": "r", "tags": {}},
        "policy_decision": "dry_run",
    }


def _event(item: dict[str, Any]) -> dict[str, Any]:
    image = {k: _serializer.serialize(v) for k, v in item.items()}
    return {
        "Records": [
            {
                "eventID": "1",
                "eventName": "MODIFY",
                "eventSource": "aws:dynamodb",
                "dynamodb": {
                    "Keys": {"pk": image["pk"], "sk": image["sk"]},
                    "NewImage": image,
                    "StreamViewType": "NEW_AND_OLD_IMAGES",
                },
            }
        ]
    }


def _approval_count(table: Any) -> int:
    return int(table.scan(Select="COUNT")["Count"])


def test_at_most_one_approval_per_finding_across_reruns(aws: Any) -> None:
    item = _finding_item(last_seen_at=datetime.now(UTC).isoformat())
    aws.findings.put_item(Item=item)

    # First run → one approval.
    pe.handler(_event(item), _context())
    assert _approval_count(aws.approvals) == 1
    first_id = aws.approvals.scan()["Items"][0]["approval_id"]
    assert first_id.startswith("appr_")

    # Re-run with the identical finding (no change) → still one approval.
    pe.handler(_event(item), _context())
    assert _approval_count(aws.approvals) == 1

    # Finding modified (new last_seen_at) → still one approval, same id.
    modified = _finding_item(last_seen_at="2099-01-01T00:00:00+00:00")
    aws.findings.put_item(Item=modified)
    pe.handler(_event(modified), _context())
    assert _approval_count(aws.approvals) == 1
    assert aws.approvals.scan()["Items"][0]["approval_id"] == first_id


def test_dispatch_runs_when_decision_unchanged_recreates_missing_approval(aws: Any) -> None:
    # The PR #15 bug: finding already in `prompt`, approvals purged. Re-processing
    # must still dispatch and create the approval — decide and dispatch are separate.
    item = _finding_item(last_seen_at=datetime.now(UTC).isoformat())
    item["policy_decision"] = "prompt"  # decision already recorded
    aws.findings.put_item(Item=item)
    assert _approval_count(aws.approvals) == 0

    pe.handler(_event(item), _context())

    assert _approval_count(aws.approvals) == 1  # dispatch ran despite no decision change


def test_unchanged_decision_does_not_rewrite_but_still_dispatches(
    aws: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_spy = _Spy()
    monkeypatch.setattr(pe, "_write_decision", write_spy)

    item = _finding_item(last_seen_at=datetime.now(UTC).isoformat())
    item["policy_decision"] = "prompt"  # matches the computed decision → no rewrite
    aws.findings.put_item(Item=item)

    pe.handler(_event(item), _context())

    assert write_spy.calls == 0  # unchanged decision → no duplicate write/audit
    assert _approval_count(aws.approvals) == 1  # but dispatch still happened


def test_reprocessing_prompt_still_calls_ensure_approval(
    aws: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = _finding_item(last_seen_at=datetime.now(UTC).isoformat())  # stored dry_run
    aws.findings.put_item(Item=item)
    pe.handler(_event(item), _context())  # dry_run -> prompt: creates the approval
    assert _approval_count(aws.approvals) == 1

    calls: list[tuple[str, str]] = []
    original = pe._ensure_approval

    def _recording_ensure(finding: Any, pk: str, sk: str) -> None:
        calls.append((pk, sk))
        original(finding, pk, sk)

    monkeypatch.setattr(pe, "_ensure_approval", _recording_ensure)

    # Re-process with the decision already `prompt`: dispatch must still invoke
    # _ensure_approval (which no-ops because the row exists), not skip it.
    item["policy_decision"] = "prompt"
    pe.handler(_event(item), _context())
    assert calls == [(PK, SK)]
    assert _approval_count(aws.approvals) == 1  # idempotent: no duplicate
