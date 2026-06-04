"""Tests for the remediator Lambda (moto-backed; SSM start mocked)."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from moto import mock_aws

from remediator import handler as rm
from shared.models import FindingStatus

REGION = "us-east-1"
FINDINGS_TABLE = "findings-test"
PK = "111#us-east-1#iam"


class _Spy:
    def __init__(self, return_value: Any = None) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self._return = return_value

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self._return


def _context() -> Any:
    return SimpleNamespace(
        function_name="remediator",
        memory_limit_in_mb=256,
        invoked_function_arn="arn:aws:lambda:us-east-1:111:function:remediator",
        aws_request_id="req-1",
    )


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> Any:
    for key, value in {
        "AWS_DEFAULT_REGION": REGION,
        "FINDINGS_TABLE": FINDINGS_TABLE,
        "SNAPSHOT_BUCKET": "snapshots-test",
        "AUDIT_BUCKET": "audit-test",
        "EVENT_BUS_NAME": "tidewater-events",
        "SSM_EXECUTION_ROLE_ARN": "arn:aws:iam::111:role/TidewaterSsmExecutionRole",
    }.items():
        monkeypatch.setenv(key, value)
    # Isolate side effects.
    monkeypatch.setattr(rm, "_start_automation", _Spy(return_value="exec-123"))
    monkeypatch.setattr(rm, "write_audit_event", _Spy())
    monkeypatch.setattr(rm, "emit_event", _Spy())
    with mock_aws():
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
        yield boto3.resource("dynamodb", region_name=REGION).Table(FINDINGS_TABLE)


def _put_finding(
    table: Any, *, rule_id: str, resource_arn: str, details: dict[str, Any] | None = None
) -> str:
    sk = f"{resource_arn}#{rule_id}"
    now = datetime.now(UTC).isoformat()
    table.put_item(
        Item={
            "pk": PK,
            "sk": sk,
            "rule_id": rule_id,
            "resource_arn": resource_arn,
            "status": "open",
            "detected_at": now,
            "last_seen_at": now,
            "details": details or {},
        }
    )
    return sk


def test_selects_correct_ssm_document_and_parameters(aws: Any) -> None:
    arn = "arn:aws:iam::111:role/my-unused-role"
    sk = _put_finding(aws, rule_id="iam.unused_role", resource_arn=arn)

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "started"
    assert result["execution_id"] == "exec-123"
    ((args, _),) = rm._start_automation.calls
    document_name, parameters = args
    assert document_name == "TidewaterDeleteIamRole"
    assert parameters["RoleName"] == ["my-unused-role"]
    assert parameters["SnapshotBucket"] == ["snapshots-test"]
    assert parameters["FindingPk"] == [PK]
    assert parameters["FindingSk"] == [sk]
    # Finding moved to in_remediation.
    assert aws.get_item(Key={"pk": PK, "sk": sk})["Item"]["status"] == (
        FindingStatus.IN_REMEDIATION.value
    )


def test_stale_access_key_builds_user_and_key_params(aws: Any) -> None:
    arn = "arn:aws:iam::111:user/alice#accesskey/AKIAEXAMPLE"
    sk = _put_finding(
        aws,
        rule_id="iam.stale_access_key",
        resource_arn=arn,
        details={"user_name": "alice", "access_key_id": "AKIAEXAMPLE"},
    )

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "started"
    ((args, _),) = rm._start_automation.calls
    document_name, parameters = args
    assert document_name == "TidewaterDeleteIamAccessKey"
    assert parameters["UserName"] == ["alice"]
    assert parameters["AccessKeyId"] == ["AKIAEXAMPLE"]
    assert "RoleName" not in parameters


def test_orphaned_trust_builds_role_and_principal_list(aws: Any) -> None:
    arn = "arn:aws:iam::111:role/app-role"
    sk = _put_finding(
        aws,
        rule_id="iam.orphaned_trust",
        resource_arn=arn,
        details={
            "role_name": "app-role",
            "orphan_principals": [
                {"type": "arn", "principal": "arn:aws:iam::111:user/gone"},
                {"type": "unique_id", "principal": "AIDASITUILUEC7BNIGN7A"},
            ],
        },
    )

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "started"
    ((args, _),) = rm._start_automation.calls
    document_name, parameters = args
    assert document_name == "TidewaterRemoveTrustPrincipalV2"
    assert parameters["RoleName"] == ["app-role"]
    # Both forms are flattened to the bare principal strings the runbook strips.
    assert parameters["OrphanPrincipals"] == [
        "arn:aws:iam::111:user/gone",
        "AIDASITUILUEC7BNIGN7A",
    ]


def test_unused_policy_builds_policy_arn_param(aws: Any) -> None:
    arn = "arn:aws:iam::111:policy/dangling"
    sk = _put_finding(
        aws,
        rule_id="iam.unused_policy",
        resource_arn=arn,
        details={"policy_arn": arn, "policy_name": "dangling"},
    )

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "started"
    ((args, _),) = rm._start_automation.calls
    document_name, parameters = args
    assert document_name == "TidewaterDeleteUnusedPolicy"
    assert parameters["PolicyArn"] == [arn]


def test_policy_quota_builds_role_name_param(aws: Any) -> None:
    arn = "arn:aws:iam::111:role/overloaded"
    sk = _put_finding(
        aws,
        rule_id="iam.policy_quota",
        resource_arn=arn,
        details={"role_name": "overloaded", "attached_count": 11},
    )

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "started"
    ((args, _),) = rm._start_automation.calls
    document_name, parameters = args
    assert document_name == "TidewaterDetachUnusedPolicy"
    assert parameters["RoleName"] == ["overloaded"]


def test_unused_function_builds_function_and_account_params(aws: Any) -> None:
    arn = "arn:aws:lambda:us-east-1:111:function:idle-fn"
    sk = _put_finding(
        aws,
        rule_id="lambda.unused_function",
        resource_arn=arn,
        details={"function_name": "idle-fn", "runtime": "python3.12"},
    )

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "started"
    ((args, _),) = rm._start_automation.calls
    document_name, parameters = args
    assert document_name == "TidewaterDeleteUnusedFunction"
    assert parameters["FunctionName"] == ["idle-fn"]
    # AccountId is derived from the finding pk (account#region#service).
    assert parameters["AccountId"] == ["111"]


def test_wildcard_policy_is_never_remediated(aws: Any) -> None:
    # Flag-only rule: even if a finding somehow reaches the remediator, there is
    # no runbook and SSM is never started.
    arn = "arn:aws:iam::111:policy/wild"
    sk = _put_finding(aws, rule_id="iam.wildcard_policy", resource_arn=arn)

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "no_runbook"
    assert rm._start_automation.calls == []
    assert aws.get_item(Key={"pk": PK, "sk": sk})["Item"]["status"] == "open"


def test_unknown_rule_id_exits_cleanly(aws: Any) -> None:
    sk = _put_finding(aws, rule_id="iam.something_else", resource_arn="arn:aws:iam::111:role/x")

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "no_runbook"
    assert rm._start_automation.calls == []
    # Status untouched.
    assert aws.get_item(Key={"pk": PK, "sk": sk})["Item"]["status"] == "open"


def test_refuses_protected_role_even_if_invoked(aws: Any) -> None:
    arn = "arn:aws:iam::111:role/aws-service-role/foo.amazonaws.com/AWSServiceRoleForFoo"
    sk = _put_finding(aws, rule_id="iam.unused_role", resource_arn=arn)

    result = rm.handler({"finding_pk": PK, "finding_sk": sk}, _context())

    assert result["status"] == "refused_protected"
    assert rm._start_automation.calls == []  # never started SSM
    assert aws.get_item(Key={"pk": PK, "sk": sk})["Item"]["status"] == "open"
    # An audit record explains the refusal.
    assert rm.write_audit_event.calls
    assert rm.write_audit_event.calls[0][1]["event_type"] == "remediation_failed"


def test_missing_finding_returns_not_found(aws: Any) -> None:
    result = rm.handler({"finding_pk": PK, "finding_sk": "missing#iam.unused_role"}, _context())
    assert result["status"] == "not_found"
    assert rm._start_automation.calls == []
