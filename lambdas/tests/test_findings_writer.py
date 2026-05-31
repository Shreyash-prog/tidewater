"""Tests for the idempotent findings writer (moto DynamoDB)."""

from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from moto import mock_aws

from shared.findings_writer import FindingsTableWriter, finding_pk, finding_sk
from shared.models import Finding, PolicyAction, Severity

REGION = "us-east-1"
TABLE = "tidewater-findings-test"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("FINDINGS_TABLE", TABLE)


def _create_table() -> Any:
    ddb: Any = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName=TABLE,
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
    return boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def _finding(arn: str = "arn:aws:iam::123456789012:role/example") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        account="123456789012",
        region=REGION,
        service="iam",
        resource_arn=arn,
        rule_id="iam.unused_role",
        severity=Severity.HIGH,
        detected_at=now,
        last_seen_at=now,
        details={"days_idle": 30, "threshold_idle_days": 7},
        policy_decision=PolicyAction.DRY_RUN,
    )


@mock_aws
def test_write_creates_then_updates() -> None:
    table = _create_table()
    writer = FindingsTableWriter()
    finding = _finding()

    first = writer.write_batch([finding])
    assert len(first.created) == 1 and len(first.updated) == 0

    second = writer.write_batch([finding])
    assert len(second.created) == 0 and len(second.updated) == 1

    item = table.get_item(Key={"pk": finding_pk(finding), "sk": finding_sk(finding)})["Item"]
    assert item["severity"] == "high"
    assert item["policy_decision"] == "dry_run"
    assert item["status"] == "open"


@mock_aws
def test_idempotent_no_duplicate_rows_across_runs() -> None:
    table = _create_table()
    writer = FindingsTableWriter()
    findings = [
        _finding("arn:aws:iam::123456789012:role/a"),
        _finding("arn:aws:iam::123456789012:role/b"),
    ]

    writer.write_batch(findings)
    writer.write_batch(findings)  # second run must not duplicate

    count = table.scan(Select="COUNT")["Count"]
    assert count == 2


@mock_aws
def test_detected_at_is_preserved_on_update() -> None:
    table = _create_table()
    writer = FindingsTableWriter()
    finding = _finding()

    writer.write_batch([finding])
    key = {"pk": finding_pk(finding), "sk": finding_sk(finding)}
    original_detected_at = table.get_item(Key=key)["Item"]["detected_at"]

    writer.write_batch([finding])
    after = table.get_item(Key=key)["Item"]
    assert after["detected_at"] == original_detected_at
    assert after["last_seen_at"] >= original_detected_at
