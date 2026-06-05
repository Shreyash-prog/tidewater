"""Plain-text message formatters for notifications (one per event category).

Each returns ``(subject, body)``. Subjects are kept under 100 chars (SNS truncates
there). Bodies are email-safe plain text, readable on a phone — no HTML, no
templating libraries, just f-strings. Future phases add richer formatting and
dashboard links.
"""

from typing import Any

_SUBJECT_MAX = 100


def _truncate(text: str, limit: int = _SUBJECT_MAX) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _resource_name(resource_arn: str) -> str:
    """Last meaningful segment of an ARN (role/policy/function name)."""
    return resource_arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1] or resource_arn


def format_event(event_type: str, detail: dict[str, Any]) -> tuple[str, str]:
    if event_type == "remediation.failed":
        return _format_remediation_failed(detail)
    rule_id = str(detail.get("rule_id", ""))
    if rule_id.endswith(".forecast_alert"):
        return _format_forecast_alert(detail)
    return _format_prompt_finding(detail)


def _format_prompt_finding(detail: dict[str, Any]) -> tuple[str, str]:
    rule_id = str(detail.get("rule_id", "unknown"))
    resource_arn = str(detail.get("resource_arn", "unknown"))
    severity = str(detail.get("severity", "")).upper()
    detected_at = str(detail.get("detected_at", "unknown"))
    details = detail.get("details", {})

    subject = _truncate(f"[Tidewater] {severity}: {rule_id} on {_resource_name(resource_arn)}")
    body = (
        "A Tidewater detection requires your review.\n\n"
        f"Rule: {rule_id}\n"
        f"Resource: {resource_arn}\n"
        f"Severity: {severity}\n"
        f"Detected at: {detected_at}\n\n"
        f"Details:\n{_indent_details(details)}\n\n"
        "This finding requires human approval because the rule's policy decision is\n"
        '"prompt" (no auto-remediation override matched).\n\n'
        "To act on it, review the snapshot in S3 and approve/reject via the approvals\n"
        "table or the (future) dashboard."
    )
    return subject, body


def _format_forecast_alert(detail: dict[str, Any]) -> tuple[str, str]:
    resource_arn = str(detail.get("resource_arn", "unknown"))
    details = detail.get("details", {})
    forecast = details.get("forecast", {}) if isinstance(details, dict) else {}
    days_raw = forecast.get("days_to_breach")
    days = round(float(days_raw)) if isinstance(days_raw, (int, float)) else "?"
    current = details.get("current_count", "?")
    quota = details.get("quota", "?")
    confidence = forecast.get("confidence", "?")
    projected = forecast.get("projected_breach_at", "?")

    subject = _truncate(
        f"[Tidewater] Forecast: {_resource_name(resource_arn)} will hit policy limit in {days} days"
    )
    body = (
        "A Tidewater forecast projects an upcoming quota breach.\n\n"
        f"Rule: {detail.get('rule_id', 'unknown')}\n"
        f"Resource: {resource_arn}\n"
        f"Current count: {current} of {quota}\n"
        f"Projected breach in: {days} days ({projected})\n"
        f"Confidence: {confidence}\n\n"
        "This is a projection, not a current breach — it is surfaced for review and is\n"
        "never auto-remediated. Consider trimming attachments before the limit is hit."
    )
    return subject, body


def _format_remediation_failed(detail: dict[str, Any]) -> tuple[str, str]:
    rule_id = str(detail.get("rule_id", "unknown"))
    resource_arn = str(detail.get("resource_arn", "unknown"))
    reason = str(detail.get("reason", detail.get("error", "unknown")))

    subject = _truncate(
        f"[Tidewater] Remediation failed: {rule_id} on {_resource_name(resource_arn)}"
    )
    body = (
        "A Tidewater remediation FAILED and needs human intervention.\n\n"
        f"Rule: {rule_id}\n"
        f"Resource: {resource_arn}\n"
        f"Reason: {reason}\n\n"
        "The framework attempted a remediation that did not complete. Review the audit\n"
        "log and the resource's current state before acting."
    )
    return subject, body


def _indent_details(details: Any) -> str:
    if not isinstance(details, dict) or not details:
        return "  (none)"
    lines = []
    for key, value in details.items():
        if key == "tags" and not value:
            continue
        lines.append(f"  {key}: {value}")
    return "\n".join(lines) if lines else "  (none)"
