"""Notification-worthiness filter tests."""

from notifier.handler import _is_notification_worthy


def test_remediation_failed_always_notifies() -> None:
    assert _is_notification_worthy("remediation.failed", {"rule_id": "iam.unused_role"}) is True


def test_high_prompt_notifies() -> None:
    detail = {"rule_id": "iam.wildcard_policy", "severity": "high", "policy_decision": "prompt"}
    assert _is_notification_worthy("Finding.updated", detail) is True


def test_high_auto_does_not_notify() -> None:
    detail = {"rule_id": "iam.unused_role", "severity": "high", "policy_decision": "auto"}
    assert _is_notification_worthy("Finding.updated", detail) is False


def test_high_dry_run_does_not_notify() -> None:
    # The detector's original event carries dry_run — must not notify.
    detail = {"rule_id": "iam.wildcard_policy", "severity": "high", "policy_decision": "dry_run"}
    assert _is_notification_worthy("Finding.created", detail) is False


def test_medium_prompt_does_not_notify() -> None:
    detail = {"rule_id": "iam.orphaned_trust", "severity": "medium", "policy_decision": "prompt"}
    assert _is_notification_worthy("Finding.updated", detail) is False


def test_low_prompt_does_not_notify() -> None:
    detail = {"rule_id": "iam.unused_policy", "severity": "low", "policy_decision": "prompt"}
    assert _is_notification_worthy("Finding.updated", detail) is False


def test_forecast_alert_notifies_regardless_of_severity_or_decision() -> None:
    detail = {
        "rule_id": "iam.policy_quota.forecast_alert",
        "severity": "medium",
        "policy_decision": "dry_run",
    }
    assert _is_notification_worthy("Finding.created", detail) is True


def test_unknown_event_type_does_not_notify() -> None:
    detail = {"rule_id": "iam.wildcard_policy", "severity": "high", "policy_decision": "prompt"}
    assert _is_notification_worthy("finding.remediation_started", detail) is False
    assert _is_notification_worthy("dispatch_deferred", detail) is False


def test_missing_fields_do_not_notify() -> None:
    assert _is_notification_worthy("Finding.created", {}) is False
    assert _is_notification_worthy("Finding.updated", {"severity": "high"}) is False
