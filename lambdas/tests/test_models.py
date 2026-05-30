"""Placeholder test for shared Lambda code.

Exercises the shared Pydantic models so pytest has something real to collect
until detector tests arrive in Phase 3.
"""

from datetime import UTC, datetime

from shared.models import Finding, FindingStatus, Severity


def test_finding_defaults_to_open() -> None:
    now = datetime.now(UTC)
    finding = Finding(
        account="123456789012",
        region="us-east-1",
        service="iam",
        resource_arn="arn:aws:iam::123456789012:role/example",
        rule_id="iam.unused_role",
        severity=Severity.MEDIUM,
        detected_at=now,
        last_seen_at=now,
        details={},
    )
    assert finding.status is FindingStatus.OPEN
    assert finding.policy_decision is None
