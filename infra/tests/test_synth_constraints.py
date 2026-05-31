"""Guardrail tests over the synthesized CoreStack template.

These encode the Phase 2 safety rules so a future change can't silently regress
them: log retention, on-demand DynamoDB, bucket removal policies, no NAT
gateways, and a SecureString bearer-token parameter.
"""

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

from infra.stacks.core_stack import RETAIN_BUCKETS, CoreStack

ENV = cdk.Environment(account="123456789012", region="us-east-1")

# Logical-id substrings that identify each bucket's intended removal policy.
_RETAIN_BUCKET_IDS = ("AuditLogBucket", "SnapshotsBucket")
_DESTROY_BUCKET_IDS = ("RulesYamlBucket", "DashboardSpaBucket")


@pytest.fixture(scope="module")
def resources() -> dict[str, dict]:
    app = cdk.App()
    stack = CoreStack(app, "TestCore", env=ENV, notification_email="test@example.com")
    return assertions.Template.from_stack(stack).to_json()["Resources"]


def _of_type(resources: dict[str, dict], type_name: str) -> dict[str, dict]:
    return {k: v for k, v in resources.items() if v["Type"] == type_name}


def test_every_log_group_has_one_day_retention(resources: dict[str, dict]) -> None:
    log_groups = _of_type(resources, "AWS::Logs::LogGroup")
    assert log_groups, "expected at least one explicit log group"
    for name, lg in log_groups.items():
        assert lg["Properties"].get("RetentionInDays") == 1, name


def test_every_dynamodb_table_is_on_demand(resources: dict[str, dict]) -> None:
    tables = _of_type(resources, "AWS::DynamoDB::Table")
    assert len(tables) == 5
    for name, table in tables.items():
        assert table["Properties"].get("BillingMode") == "PAY_PER_REQUEST", name


def test_audit_and_snapshot_buckets_are_retained(resources: dict[str, dict]) -> None:
    assert sorted(RETAIN_BUCKETS) == ["audit-log", "snapshots"]
    for name, bucket in _of_type(resources, "AWS::S3::Bucket").items():
        if name.startswith(_RETAIN_BUCKET_IDS):
            assert bucket.get("DeletionPolicy") == "Retain", name
        elif name.startswith(_DESTROY_BUCKET_IDS):
            assert bucket.get("DeletionPolicy") == "Delete", name
        else:
            raise AssertionError(f"unexpected bucket logical id: {name}")


def test_no_nat_gateways(resources: dict[str, dict]) -> None:
    assert _of_type(resources, "AWS::EC2::NatGateway") == {}


def test_bearer_token_parameter_is_securestring(resources: dict[str, dict]) -> None:
    bearer = _of_type(resources, "Custom::BearerToken")
    assert len(bearer) == 1
    (cr,) = bearer.values()
    assert cr["Properties"]["ParameterType"] == "SecureString"


def test_findings_table_has_a_stream(resources: dict[str, dict]) -> None:
    streamed = [
        name
        for name, t in _of_type(resources, "AWS::DynamoDB::Table").items()
        if "StreamSpecification" in t["Properties"]
    ]
    assert len(streamed) == 1 and streamed[0].startswith("FindingsTable")
