"""Tests for the iam.policy_quota detector (current-state + forecasting)."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from boto3.dynamodb.conditions import Key
from moto import mock_aws

from detectors.iam.detectors.policy_quota import PolicyQuotaDetector
from shared.metrics import metric_history_pk
from shared.models import Severity

ACCOUNT = "111111111111"
REGION = "us-east-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/r"


def _detector(
    make_iam: Callable[..., MagicMock], attached_count: int, threshold: int = 8
) -> PolicyQuotaDetector:
    attached = [
        {"PolicyName": f"p{i:02d}", "PolicyArn": f"arn:aws:iam::aws:policy/p{i:02d}"}
        for i in range(attached_count)
    ]
    client = make_iam(
        pages={
            "list_roles": [{"Roles": [{"RoleName": "r", "Arn": ROLE_ARN}]}],
            "list_attached_role_policies": [{"AttachedPolicies": attached}],
        },
        list_role_tags={"Tags": []},
    )
    return PolicyQuotaDetector(
        ACCOUNT, REGION, {"attached_count_threshold": threshold}, iam_client=client
    )


def test_seven_attached_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    assert list(_detector(make_iam, attached_count=7).scan()) == []


def test_eight_attached_flagged_medium(make_iam: Callable[..., MagicMock]) -> None:
    findings = list(_detector(make_iam, attached_count=8).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].details["attached_count"] == 8
    assert findings[0].details["attached_policy_names"] == sorted(
        findings[0].details["attached_policy_names"]
    )


def test_nine_attached_flagged_medium(make_iam: Callable[..., MagicMock]) -> None:
    findings = list(_detector(make_iam, attached_count=9).scan())
    assert len(findings) == 1 and findings[0].severity is Severity.MEDIUM


def test_ten_attached_flagged_high(make_iam: Callable[..., MagicMock]) -> None:
    findings = list(_detector(make_iam, attached_count=10).scan())
    assert len(findings) == 1 and findings[0].severity is Severity.HIGH


def test_missing_threshold_skips_run(make_iam: Callable[..., MagicMock]) -> None:
    client = make_iam(pages={"list_roles": [{"Roles": [{"RoleName": "r", "Arn": ROLE_ARN}]}]})
    detector = PolicyQuotaDetector(ACCOUNT, REGION, {}, iam_client=client)
    assert list(detector.scan()) == []


# ----------------------------------------------------------------- forecasting
@pytest.fixture
def metric_table() -> Iterator[Any]:
    with mock_aws():
        boto3.client("dynamodb", region_name=REGION).create_table(
            TableName="metric-history-test",
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
        yield boto3.resource("dynamodb", region_name=REGION).Table("metric-history-test")


def _seed(table: Any, values: list[float]) -> None:
    """Seed daily history (value[0] oldest) ending yesterday; pk matches ROLE_ARN."""
    pk = metric_history_pk(ACCOUNT, REGION, "iam", ROLE_ARN)
    now = datetime.now(UTC)
    n = len(values)
    with table.batch_writer() as batch:
        for i, v in enumerate(values):
            ts = now - timedelta(days=(n - i))  # oldest .. yesterday
            batch.put_item(Item={"pk": pk, "sk": ts.isoformat(), "value": Decimal(str(v))})


def _forecast_detector(
    make_iam: Callable[..., MagicMock],
    table: Any,
    *,
    attached_count: int,
    threshold: int = 8,
    alert_at_days: int | None = 14,
) -> PolicyQuotaDetector:
    attached = [
        {"PolicyName": f"p{i:02d}", "PolicyArn": f"arn:aws:iam::aws:policy/p{i:02d}"}
        for i in range(attached_count)
    ]
    client = make_iam(
        pages={
            "list_roles": [{"Roles": [{"RoleName": "r", "Arn": ROLE_ARN}]}],
            "list_attached_role_policies": [{"AttachedPolicies": attached}],
        },
        list_role_tags={"Tags": []},
    )
    rule_threshold: dict[str, Any] = {
        "attached_count_threshold": threshold,
        "forecast_enabled": True,
    }
    if alert_at_days is not None:
        rule_threshold["alert_at_days_remaining"] = alert_at_days
    return PolicyQuotaDetector(
        ACCOUNT, REGION, rule_threshold, iam_client=client, metric_history_table=table
    )


def _by_rule(findings: list[Any]) -> dict[str, Any]:
    return {f.rule_id: f for f in findings}


def test_rising_trend_emits_forecast_alert_only(
    make_iam: Callable[..., MagicMock], metric_table: Any
) -> None:
    # Clean +1/day history, current count 7 (below threshold 8): no current-state
    # finding, but a forecast breach within the alert window.
    _seed(metric_table, [1, 2, 3, 4, 5, 6])
    detector = _forecast_detector(make_iam, metric_table, attached_count=7, threshold=8)
    findings = _by_rule(list(detector.scan()))
    assert set(findings) == {"iam.policy_quota.forecast_alert"}
    alert = findings["iam.policy_quota.forecast_alert"]
    assert alert.severity is Severity.MEDIUM
    assert alert.details["forecast"]["status"] == "numeric"
    assert alert.details["current_count"] == 7
    assert alert.details["quota"] == 10


def test_stable_trend_emits_no_forecast_alert(
    make_iam: Callable[..., MagicMock], metric_table: Any
) -> None:
    _seed(metric_table, [7, 7, 7, 7, 7, 7])
    detector = _forecast_detector(make_iam, metric_table, attached_count=7, threshold=8)
    assert list(detector.scan()) == []


def test_current_breach_and_forecast_coexist(
    make_iam: Callable[..., MagicMock], metric_table: Any
) -> None:
    # Count 10 (HIGH current-state breach) AND a rising trend → both findings.
    _seed(metric_table, [4, 5, 6, 7, 8, 9])
    detector = _forecast_detector(make_iam, metric_table, attached_count=10, threshold=8)
    findings = _by_rule(list(detector.scan()))
    assert set(findings) == {"iam.policy_quota", "iam.policy_quota.forecast_alert"}
    assert findings["iam.policy_quota"].severity is Severity.HIGH


def test_metric_written_every_scan_even_below_threshold(
    make_iam: Callable[..., MagicMock], metric_table: Any
) -> None:
    # Count 3, well below threshold, no forecast yet — but the data point is still
    # recorded so history can accumulate.
    detector = _forecast_detector(make_iam, metric_table, attached_count=3, threshold=8)
    list(detector.scan())
    pk = metric_history_pk(ACCOUNT, REGION, "iam", ROLE_ARN)
    items = metric_table.query(KeyConditionExpression=Key("pk").eq(pk))["Items"]
    assert len(items) == 1
    assert items[0]["value"] == Decimal("3")


def test_forecast_skipped_when_not_enabled(
    make_iam: Callable[..., MagicMock], metric_table: Any
) -> None:
    # forecast_enabled defaults off (not injected) → no forecast even with history.
    _seed(metric_table, [1, 2, 3, 4, 5, 6])
    attached = [
        {"PolicyName": f"p{i:02d}", "PolicyArn": f"arn:aws:iam::aws:policy/p{i:02d}"}
        for i in range(7)
    ]
    client = make_iam(
        pages={
            "list_roles": [{"Roles": [{"RoleName": "r", "Arn": ROLE_ARN}]}],
            "list_attached_role_policies": [{"AttachedPolicies": attached}],
        },
        list_role_tags={"Tags": []},
    )
    detector = PolicyQuotaDetector(
        ACCOUNT,
        REGION,
        {"attached_count_threshold": 8},
        iam_client=client,
        metric_history_table=metric_table,
    )
    assert list(detector.scan()) == []


def test_metric_write_failure_does_not_block_detection(
    make_iam: Callable[..., MagicMock],
) -> None:
    # A broken metric table must not stop the current-state finding from emitting.
    broken = MagicMock()
    broken.put_item = MagicMock(side_effect=RuntimeError("ddb down"))
    broken.query = MagicMock(side_effect=RuntimeError("ddb down"))
    attached = [
        {"PolicyName": f"p{i:02d}", "PolicyArn": f"arn:aws:iam::aws:policy/p{i:02d}"}
        for i in range(10)
    ]
    client = make_iam(
        pages={
            "list_roles": [{"Roles": [{"RoleName": "r", "Arn": ROLE_ARN}]}],
            "list_attached_role_policies": [{"AttachedPolicies": attached}],
        },
        list_role_tags={"Tags": []},
    )
    detector = PolicyQuotaDetector(
        ACCOUNT,
        REGION,
        {"attached_count_threshold": 8, "forecast_enabled": True, "alert_at_days_remaining": 14},
        iam_client=client,
        metric_history_table=broken,
    )
    findings = _by_rule(list(detector.scan()))
    # Current-state finding still emitted despite the metric write raising.
    assert "iam.policy_quota" in findings
