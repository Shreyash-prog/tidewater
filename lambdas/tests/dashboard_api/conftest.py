"""Shared moto fixtures for the dashboard API route tests."""

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import boto3
import pytest
from moto import mock_aws

REGION = "us-east-1"
FINDINGS_TABLE = "findings-test"
APPROVALS_TABLE = "approvals-test"
RULES_BUCKET = "rules-test"
AUDIT_BUCKET = "audit-test"
SNAPSHOTS_BUCKET = "snapshots-test"
REMEDIATOR_FN = "remediator-test"

RULE_YAML = """\
rule: iam.unused_role
enabled: true
schedule: on-demand
threshold:
  idle_days: 7
forecast:
  enabled: false
policy:
  default: prompt
  overrides:
    - match: { Environment: nonprod }
      action: auto
"""


def _put_finding(table: Any, **overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    item: dict[str, Any] = {
        "pk": "111#us-east-1#iam",
        "sk": "arn:aws:iam::111:role/r#iam.unused_role",
        "account": "111",
        "region": REGION,
        "service": "iam",
        "resource_arn": "arn:aws:iam::111:role/r",
        "rule_id": "iam.unused_role",
        "status": "open",
        "severity": "high",
        "detected_at": now,
        "last_seen_at": now,
        "details": {"role_name": "r", "days_idle": Decimal("42")},
        "policy_decision": "prompt",
    }
    item.update(overrides)
    table.put_item(Item=item)
    return item


def _kv_table(ddb: Any, name: str, pk: str, sk: str) -> None:
    ddb.create_table(
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
    monkeypatch.setenv("AUDIT_LOG_BUCKET", AUDIT_BUCKET)
    monkeypatch.setenv("AUDIT_BUCKET", AUDIT_BUCKET)
    monkeypatch.setenv("SNAPSHOTS_BUCKET", SNAPSHOTS_BUCKET)
    monkeypatch.setenv("EVENT_BUS_NAME", "tidewater-events")
    monkeypatch.setenv("REMEDIATOR_FUNCTION_NAME", REMEDIATOR_FN)
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name=REGION)
        _kv_table(ddb, FINDINGS_TABLE, "pk", "sk")
        _kv_table(ddb, APPROVALS_TABLE, "approval_id", "metadata")
        s3 = boto3.client("s3", region_name=REGION)
        for bucket in (RULES_BUCKET, AUDIT_BUCKET, SNAPSHOTS_BUCKET):
            s3.create_bucket(Bucket=bucket)
        s3.put_object(
            Bucket=RULES_BUCKET, Key="rules/iam.unused_role.yaml", Body=RULE_YAML.encode()
        )
        resource = boto3.resource("dynamodb", region_name=REGION)
        yield type(
            "Ctx",
            (),
            {
                "findings": resource.Table(FINDINGS_TABLE),
                "approvals": resource.Table(APPROVALS_TABLE),
                "s3": s3,
                "put_finding": staticmethod(_put_finding),
            },
        )
