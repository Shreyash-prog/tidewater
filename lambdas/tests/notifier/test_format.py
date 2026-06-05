"""Message formatter tests."""

from notifier.format import format_event

PROMPT_DETAIL = {
    "rule_id": "iam.wildcard_policy",
    "resource_arn": "arn:aws:iam::155936382216:policy/example-policy",
    "severity": "high",
    "detected_at": "2026-06-05T12:34:56+00:00",
    "policy_decision": "prompt",
    "details": {"statement_index": 0, "tags": {"Environment": "production"}},
}

FORECAST_DETAIL = {
    "rule_id": "iam.policy_quota.forecast_alert",
    "resource_arn": "arn:aws:iam::155936382216:role/data-pipeline-role",
    "severity": "medium",
    "details": {
        "current_count": 8,
        "quota": 10,
        "forecast": {
            "days_to_breach": 6.2,
            "confidence": "high",
            "projected_breach_at": "2026-06-11T00:00:00+00:00",
        },
    },
}

FAILED_DETAIL = {
    "rule_id": "iam.unused_policy",
    "resource_arn": "arn:aws:iam::155936382216:policy/legacy-bucket-policy",
    "reason": "protected role — remediation refused",
}


def test_prompt_subject_and_body() -> None:
    subject, body = format_event("Finding.updated", PROMPT_DETAIL)
    assert len(subject) <= 100
    assert subject.startswith("[Tidewater] HIGH: iam.wildcard_policy")
    assert "example-policy" in subject
    assert "iam.wildcard_policy" in body
    assert "arn:aws:iam::155936382216:policy/example-policy" in body
    assert "HIGH" in body
    assert "approval" in body.lower()


def test_forecast_subject_and_body_include_days() -> None:
    subject, body = format_event("Finding.created", FORECAST_DETAIL)
    assert len(subject) <= 100
    assert "Forecast" in subject
    assert "data-pipeline-role" in subject
    assert "6 days" in subject  # 6.2 rounded
    assert "Confidence: high" in body
    assert "8 of 10" in body


def test_remediation_failed_subject_and_body_include_reason() -> None:
    subject, body = format_event("remediation.failed", FAILED_DETAIL)
    assert len(subject) <= 100
    assert subject.startswith("[Tidewater] Remediation failed: iam.unused_policy")
    assert "legacy-bucket-policy" in subject
    assert "protected role — remediation refused" in body
    assert "intervention" in body.lower()


def test_long_resource_name_subject_truncated_under_100() -> None:
    detail = dict(PROMPT_DETAIL)
    detail["resource_arn"] = "arn:aws:iam::111:policy/" + ("x" * 200)
    subject, _ = format_event("Finding.updated", detail)
    assert len(subject) <= 100
