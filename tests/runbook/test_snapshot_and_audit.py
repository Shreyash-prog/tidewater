"""Unit tests for the shared runbook helpers (runbooks/_shared/snapshot_and_audit.py).

The SSM runbooks inline equivalent logic; these tests validate the canonical
implementation against moto so the behaviour is covered somewhere.
"""

import importlib.util
import json
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

_MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "runbooks" / "_shared" / "snapshot_and_audit.py"
)
REGION = "us-east-1"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("snapshot_and_audit", _MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sa = _load()


@pytest.fixture(autouse=True)
def _region(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def test_protected_patterns_come_from_role_guard() -> None:
    from shared.role_guard import PROTECTED_NAME_PREFIXES

    assert sa.ROLE_PROTECTED_PATTERNS == PROTECTED_NAME_PREFIXES


@mock_aws
def test_write_snapshot_includes_metadata() -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="snaps")
    key = sa.write_snapshot(
        s3,
        "snaps",
        "iam/role/r/ts.json",
        {"role": "r"},
        finding_pk="pk",
        finding_sk="sk",
        taken_by="Doc",
    )
    body = json.loads(s3.get_object(Bucket="snaps", Key=key)["Body"].read())
    assert body["role"] == "r"
    assert body["snapshot_metadata"]["finding_pk"] == "pk"
    assert body["snapshot_metadata"]["taken_by"] == "Doc"


@mock_aws
def test_update_finding_resolved() -> None:
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName="findings",
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
    ddb.put_item(
        TableName="findings",
        Item={"pk": {"S": "p"}, "sk": {"S": "s"}, "status": {"S": "in_remediation"}},
    )

    sa.update_finding_resolved(ddb, "findings", "p", "s", "iam/role/r/ts.json", note="deactivated")

    item = ddb.get_item(TableName="findings", Key={"pk": {"S": "p"}, "sk": {"S": "s"}})["Item"]
    assert item["status"]["S"] == "resolved"
    assert item["snapshot_s3_key"]["S"] == "iam/role/r/ts.json"
    assert item["resolution_note"]["S"] == "deactivated"


@mock_aws
def test_write_final_audit() -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="audit")
    key = sa.write_final_audit(
        s3,
        "audit",
        execution_id="exec-1",
        finding_pk="p",
        finding_sk="s",
        rule_id="iam.unused_policy",
        resource_arn="arn:aws:iam::111:policy/x",
        actor="ssm_automation",
        success=True,
        snapshot_s3_key="iam/policy/x/ts.json",
    )
    record = json.loads(s3.get_object(Bucket="audit", Key=key)["Body"].read())
    assert record["event_type"] == "remediation_completed"
    assert record["execution_id"] == "exec-1"


@mock_aws
def test_emit_remediation_event() -> None:
    events = boto3.client("events", region_name=REGION)
    events.create_event_bus(Name="tidewater-events")
    # Should not raise; moto accepts the put.
    sa.emit_remediation_event(
        events,
        "tidewater-events",
        finding_pk="p",
        finding_sk="s",
        event_type="finding.remediated",
        detail={"role_name": "r"},
    )
