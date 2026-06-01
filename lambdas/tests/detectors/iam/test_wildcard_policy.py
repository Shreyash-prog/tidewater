"""Tests for the iam.wildcard_policy detector pattern matchers."""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

from detectors.iam.detectors.wildcard_policy import (
    WildcardPolicyDetector,
    _classify_statement,
    _worst_match,
)
from shared.models import Severity

ACCOUNT = "111111111111"
REGION = "us-east-1"


def test_action_star_is_high() -> None:
    sev, pattern = _classify_statement({"Effect": "Allow", "Action": "*", "Resource": "*"})  # type: ignore[misc]
    assert sev is Severity.HIGH and pattern == "action_wildcard"


def test_action_star_star_is_high() -> None:
    sev, _ = _classify_statement({"Effect": "Allow", "Action": ["*:*"], "Resource": ["arn:..."]})  # type: ignore[misc]
    assert sev is Severity.HIGH


def test_resource_star_with_broad_action_is_medium() -> None:
    sev, pattern = _classify_statement({"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"})  # type: ignore[misc]
    assert sev is Severity.MEDIUM and pattern == "resource_wildcard_broad_action"


def test_not_action_is_low() -> None:
    sev, pattern = _classify_statement({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})  # type: ignore[misc]
    assert sev is Severity.LOW and pattern == "not_action"


def test_scoped_statement_is_not_flagged() -> None:
    assert (
        _classify_statement({"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn"})
        is None
    )


def test_deny_wildcard_is_not_flagged() -> None:
    assert _classify_statement({"Effect": "Deny", "Action": "*", "Resource": "*"}) is None


def test_worst_match_picks_highest_severity_and_index() -> None:
    doc = {
        "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"},  # LOW, idx 0
            {"Effect": "Allow", "Action": "*", "Resource": "*"},  # HIGH, idx 1
        ]
    }
    match = _worst_match(doc)
    assert match is not None
    severity, pattern, index = match
    assert severity is Severity.HIGH and index == 1


def _detector(make_iam: Callable[..., MagicMock], **methods: Any) -> WildcardPolicyDetector:
    client = make_iam(**methods)
    return WildcardPolicyDetector(ACCOUNT, REGION, {"enabled": True}, iam_client=client)


def test_end_to_end_flags_managed_wildcard_policy(make_iam: Callable[..., MagicMock]) -> None:
    pages = {
        "list_roles": [{"Roles": [{"RoleName": "r", "Arn": f"arn:aws:iam::{ACCOUNT}:role/r"}]}],
        "list_attached_role_policies": [
            {
                "AttachedPolicies": [
                    {"PolicyName": "admin", "PolicyArn": "arn:aws:iam::111:policy/admin"}
                ]
            }
        ],
        "list_role_policies": [{"PolicyNames": []}],
    }
    detector = _detector(
        make_iam,
        pages=pages,
        get_policy={"Policy": {"DefaultVersionId": "v1"}},
        get_policy_version={
            "PolicyVersion": {
                "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            }
        },
    )
    findings = list(detector.scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].details["policy_type"] == "managed"
    assert findings[0].details["matched_pattern"] == "action_wildcard"


def test_skips_protected_roles(make_iam: Callable[..., MagicMock]) -> None:
    pages = {
        "list_roles": [
            {
                "Roles": [
                    {
                        "RoleName": "AWSReservedSSO_x",
                        "Arn": f"arn:aws:iam::{ACCOUNT}:role/AWSReservedSSO_x",
                    }
                ]
            }
        ]
    }
    detector = _detector(make_iam, pages=pages)
    assert list(detector.scan()) == []
