"""Tests for the demo seed utility tools/seed_metric_history.py."""

import time
from decimal import Decimal

from tools.seed_metric_history import build_items, parse_values


def test_parse_values_handles_whitespace_and_floats() -> None:
    assert parse_values("5,5,6, 7 ,10") == [5.0, 5.0, 6.0, 7.0, 10.0]
    assert parse_values("1.5, 2.5") == [1.5, 2.5]
    assert parse_values("3,") == [3.0]  # trailing empty segment ignored


def test_build_items_writes_one_per_value() -> None:
    values = [5, 6, 7, 8, 9]
    items = build_items(
        account="111",
        region="us-east-1",
        service="iam",
        resource_arn="arn:aws:iam::111:role/r",
        rule_id="iam.policy_quota",
        values=values,
        days_ago=4,
    )
    assert len(items) == len(values)
    assert all(item["pk"] == "111#us-east-1#iam#arn:aws:iam::111:role/r" for item in items)
    assert [item["value"] for item in items] == [Decimal(str(v)) for v in values]
    # Sort keys are strictly increasing (one per day, oldest first).
    sks = [item["sk"] for item in items]
    assert sks == sorted(sks)


def test_build_items_sets_ttl_on_each_item() -> None:
    items = build_items(
        account="111",
        region="us-east-1",
        service="iam",
        resource_arn="arn:aws:iam::111:role/r",
        rule_id="iam.policy_quota",
        values=[5, 6, 7],
        days_ago=2,
        ttl_days=30,
    )
    now = time.time()
    for item in items:
        assert "ttl" in item
        # TTL is ~30 days past that point's (recent) timestamp.
        assert now < int(item["ttl"]) < now + 31 * 86400
