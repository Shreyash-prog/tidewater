"""Dedupe (notification-slot claim) tests."""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from notifier.dedupe import claim_notification_slot

REGION = "us-east-1"
TABLE = "findings-test"
PK = "111#us-east-1#iam"
SK = "arn:aws:iam::111:role/r#iam.wildcard_policy"


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
        t = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
        t.put_item(Item={"pk": PK, "sk": SK, "status": "open"})
        yield t


def test_no_prior_notification_claims_slot(table: Any) -> None:
    assert claim_notification_slot(table, PK, SK) is True
    item = table.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert "notified_at" in item


def test_recent_notification_not_claimed(table: Any) -> None:
    table.update_item(
        Key={"pk": PK, "sk": SK},
        UpdateExpression="SET notified_at = :n",
        ExpressionAttributeValues={":n": datetime.now(UTC).isoformat()},
    )
    assert claim_notification_slot(table, PK, SK) is False


def test_stale_notification_claims_slot(table: Any) -> None:
    old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    table.update_item(
        Key={"pk": PK, "sk": SK},
        UpdateExpression="SET notified_at = :n",
        ExpressionAttributeValues={":n": old},
    )
    assert claim_notification_slot(table, PK, SK, staleness_days=7) is True
    item = table.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert item["notified_at"] > old  # refreshed


def test_conditional_check_failure_returns_false() -> None:
    fake = MagicMock()
    fake.update_item = MagicMock(
        side_effect=ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}}, "UpdateItem"
        )
    )
    assert claim_notification_slot(fake, PK, SK) is False


def test_other_client_errors_propagate() -> None:
    fake = MagicMock()
    fake.update_item = MagicMock(
        side_effect=ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "x"}},
            "UpdateItem",
        )
    )
    with pytest.raises(ClientError):
        claim_notification_slot(fake, PK, SK)


def test_concurrent_claims_only_one_wins(table: Any) -> None:
    # Two invocations race for the same fresh finding; exactly one claims.
    results = [claim_notification_slot(table, PK, SK), claim_notification_slot(table, PK, SK)]
    assert results.count(True) == 1
    assert results.count(False) == 1
