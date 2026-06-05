"""Rules route tests (moto-backed)."""

from typing import Any

from dashboard_api.routes import rules as rr


def test_list_rules(aws: Any) -> None:
    result = rr.list_rules({})
    assert result["count"] == 1
    rule = result["items"][0]
    assert rule["rule_id"] == "iam.unused_role"
    assert rule["enabled"] is True
    assert rule["policy_default"] == "prompt"
    assert rule["has_overrides"] is True


def test_get_rule_returns_full_yaml(aws: Any) -> None:
    result = rr.get_rule({"pathParameters": {"rule_id": "iam.unused_role"}})
    assert result["rule"] == "iam.unused_role"
    assert result["threshold"]["idle_days"] == 7
    assert result["policy"]["overrides"][0]["action"] == "auto"


def test_get_rule_not_found(aws: Any) -> None:
    result = rr.get_rule({"pathParameters": {"rule_id": "iam.nonexistent"}})
    assert result == {"error": "rule not found"}
