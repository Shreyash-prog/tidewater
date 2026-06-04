"""Unit tests for shared.metrics.write_metric_history (moto-backed)."""

import json
import time
from decimal import Decimal
from typing import Any

import boto3
import pytest
from moto import mock_aws

from shared.metrics import metric_history_pk, write_metric_history

REGION = "us-east-1"
TABLE = "metric-history-test"


@pytest.fixture
def table() -> Any:
    with mock_aws():
        boto3.client("dynamodb", region_name=REGION).create_table(
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
        yield boto3.resource("dynamodb", region_name=REGION).Table(TABLE)


def test_writes_expected_shape(table: Any) -> None:
    write_metric_history(
        table,
        account="111",
        region=REGION,
        service="iam",
        resource_arn="arn:aws:iam::111:role/r",
        rule_id="iam.policy_quota",
        value=8,
        metadata={"attached_count": 8},
    )
    items = table.scan()["Items"]
    assert len(items) == 1
    item = items[0]
    assert item["pk"] == metric_history_pk("111", REGION, "iam", "arn:aws:iam::111:role/r")
    assert item["pk"] == "111#us-east-1#iam#arn:aws:iam::111:role/r"
    assert item["rule_id"] == "iam.policy_quota"
    assert item["value"] == Decimal("8")
    assert json.loads(item["metadata"]) == {"attached_count": 8}
    # sk is an ISO timestamp.
    assert item["sk"].endswith("+00:00")


def test_ttl_is_about_thirty_days_out(table: Any) -> None:
    write_metric_history(
        table,
        account="111",
        region=REGION,
        service="iam",
        resource_arn="arn:aws:iam::111:role/r",
        rule_id="iam.policy_quota",
        value=8,
    )
    item = table.scan()["Items"][0]
    expected = time.time() + 30 * 86400
    assert abs(int(item["ttl"]) - expected) < 120  # within ~2 minutes
    assert "metadata" not in item  # omitted when not provided


def test_value_stored_as_decimal_not_float(table: Any) -> None:
    # A float would raise inside boto3; the helper must convert to Decimal.
    write_metric_history(
        table,
        account="111",
        region=REGION,
        service="iam",
        resource_arn="arn:aws:iam::111:role/r",
        rule_id="iam.policy_quota",
        value=9.0,
    )
    assert isinstance(table.scan()["Items"][0]["value"], Decimal)
