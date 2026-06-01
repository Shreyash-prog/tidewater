"""Tests for the iam.unused_role detector.

moto does NOT model iam:GetServiceLastAccessedDetails or return meaningful
RoleLastUsed timestamps, so for time-based logic we create roles with moto (so
list_roles paginates them) but patch the client's `get_role` to return controlled
CreateDate / RoleLastUsed values. AWS-managed skip patterns are exercised both
end-to-end (by name) and directly against the static helper (for paths).
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from moto import mock_aws

from detectors.iam.detectors.unused_role import UnusedRoleDetector
from shared.models import Severity

ACCOUNT = "123456789012"
REGION = "us-east-1"
TRUST_DOC = json.dumps({"Version": "2012-10-17", "Statement": []})


def _ago(days: float) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


def _make_role(client: Any, name: str, path: str = "/", tags: dict[str, str] | None = None) -> None:
    kwargs: dict[str, Any] = {"RoleName": name, "Path": path, "AssumeRolePolicyDocument": TRUST_DOC}
    if tags:
        kwargs["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    client.create_role(**kwargs)


def _fake_get_role(specs: dict[str, dict[str, Any]]) -> Any:
    """Return a get_role replacement driven by per-role timing specs.

    Timestamps are resolved eagerly here (before scan() captures its `now`), so a
    spec of N days idle yields a delta of N days + a few µs — which truncates to
    exactly N, keeping boundary assertions deterministic.
    """
    resolved: dict[str, dict[str, Any]] = {}
    for name, spec in specs.items():
        role: dict[str, Any] = {
            "RoleName": name,
            "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
            "CreateDate": _ago(spec["create_days"]),
        }
        if spec.get("last_used_days") is not None:
            role["RoleLastUsed"] = {"LastUsedDate": _ago(spec["last_used_days"]), "Region": REGION}
        resolved[name] = {"Role": role}

    def _get_role(RoleName: str, **_: Any) -> dict[str, Any]:
        return resolved[RoleName]

    return _get_role


def _detector(client: Any, idle_days: int = 7) -> UnusedRoleDetector:
    return UnusedRoleDetector(ACCOUNT, REGION, {"idle_days": idle_days}, iam_client=client)


@mock_aws
def test_never_used_old_role_flagged_high() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "old-unused")
    client.get_role = _fake_get_role({"old-unused": {"create_days": 30, "last_used_days": None}})

    findings = list(_detector(client).scan())

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].details["days_idle"] == 30
    assert findings[0].details["last_used_date"] is None


@mock_aws
def test_never_used_recent_role_not_flagged() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "new-unused")
    client.get_role = _fake_get_role({"new-unused": {"create_days": 3, "last_used_days": None}})

    assert list(_detector(client).scan()) == []


@mock_aws
def test_recently_used_role_not_flagged() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "active")
    client.get_role = _fake_get_role({"active": {"create_days": 100, "last_used_days": 2}})

    assert list(_detector(client).scan()) == []


@mock_aws
def test_stale_used_role_flagged_medium() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "stale")
    client.get_role = _fake_get_role({"stale": {"create_days": 100, "last_used_days": 30}})

    findings = list(_detector(client).scan())

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].details["days_idle"] == 30
    assert findings[0].details["last_used_date"] is not None


@mock_aws
def test_boundary_exactly_at_threshold_not_flagged() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "edge")
    client.get_role = _fake_get_role({"edge": {"create_days": 100, "last_used_days": 7}})

    assert list(_detector(client, idle_days=7).scan()) == []


@mock_aws
def test_boundary_one_day_past_threshold_flagged() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "edge-plus-one")
    client.get_role = _fake_get_role({"edge-plus-one": {"create_days": 100, "last_used_days": 8}})

    findings = list(_detector(client, idle_days=7).scan())
    assert len(findings) == 1


@mock_aws
def test_skips_aws_managed_roles_by_name() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "AWSReservedSSO_Admin")
    _make_role(client, "cdk-hnb659fds-assets")
    _make_role(client, "real-old-role")
    # Only the non-managed role should ever be looked up / flagged.
    client.get_role = _fake_get_role({"real-old-role": {"create_days": 90, "last_used_days": None}})

    findings = list(_detector(client).scan())

    assert len(findings) == 1
    assert findings[0].details["role_name"] == "real-old-role"


def test_is_aws_managed_matches_service_linked_path() -> None:
    assert UnusedRoleDetector._is_aws_managed({"RoleName": "X", "Path": "/aws-service-role/x/"})
    assert UnusedRoleDetector._is_aws_managed({"RoleName": "aws-controltower-Admin", "Path": "/"})
    assert not UnusedRoleDetector._is_aws_managed({"RoleName": "my-role", "Path": "/"})


@mock_aws
def test_details_payload_excludes_trust_policy() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "detailed")
    client.get_role = _fake_get_role({"detailed": {"create_days": 60, "last_used_days": None}})

    finding = next(iter(_detector(client).scan()))

    assert set(finding.details) == {
        "role_name",
        "role_arn",
        "create_date",
        "last_used_date",
        "days_idle",
        "threshold_idle_days",
        "tags",
    }
    # Trust policy must never leak into details.
    assert "AssumeRolePolicyDocument" not in finding.details
    assert finding.resource_arn == f"arn:aws:iam::{ACCOUNT}:role/detailed"


@mock_aws
def test_includes_role_tags_in_details() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "tagged", tags={"Environment": "nonprod", "team": "platform"})
    client.get_role = _fake_get_role({"tagged": {"create_days": 60, "last_used_days": None}})

    finding = next(iter(_detector(client).scan()))

    # Tags drive tag-based policy decisions in the policy engine.
    assert finding.details["tags"] == {"Environment": "nonprod", "team": "platform"}


@mock_aws
def test_threshold_is_loaded_from_rule_not_a_constant() -> None:
    # Same role, last used 5 days ago. The configured idle_days — not any
    # hardcoded default — must decide whether it's flagged.
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "five-days")
    client.get_role = _fake_get_role({"five-days": {"create_days": 100, "last_used_days": 5}})

    # idle_days=3 → 5 > 3 → flagged, and details echo the configured threshold.
    flagged = list(_detector(client, idle_days=3).scan())
    assert len(flagged) == 1
    assert flagged[0].details["threshold_idle_days"] == 3

    # idle_days=10 → 5 <= 10 → not flagged.
    assert list(_detector(client, idle_days=10).scan()) == []


@mock_aws
def test_threshold_idle_days_in_details_matches_config() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "never-used-old")
    client.get_role = _fake_get_role(
        {"never-used-old": {"create_days": 60, "last_used_days": None}}
    )

    finding = next(iter(_detector(client, idle_days=30).scan()))
    assert finding.details["threshold_idle_days"] == 30  # never -1 / never a fallback


@mock_aws
def test_missing_idle_days_skips_run_no_fallback() -> None:
    # No idle_days in the rule threshold → fail closed (no findings), not default-7.
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "old-unused")
    client.get_role = _fake_get_role({"old-unused": {"create_days": 365, "last_used_days": None}})

    detector = UnusedRoleDetector(ACCOUNT, REGION, {}, iam_client=client)
    assert list(detector.scan()) == []


@mock_aws
def test_non_integer_idle_days_skips_run() -> None:
    client: Any = boto3.client("iam", region_name=REGION)
    _make_role(client, "old-unused")
    client.get_role = _fake_get_role({"old-unused": {"create_days": 365, "last_used_days": None}})

    detector = UnusedRoleDetector(ACCOUNT, REGION, {"idle_days": "oops"}, iam_client=client)
    assert list(detector.scan()) == []
