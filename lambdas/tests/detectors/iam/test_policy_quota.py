"""Tests for the iam.policy_quota detector."""

from collections.abc import Callable
from unittest.mock import MagicMock

from detectors.iam.detectors.policy_quota import PolicyQuotaDetector
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
