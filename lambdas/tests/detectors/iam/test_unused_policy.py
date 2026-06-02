"""Tests for the iam.unused_policy detector."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from detectors.iam.detectors.unused_policy import UnusedPolicyDetector
from shared.models import Severity

ACCOUNT = "111111111111"
REGION = "us-east-1"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/lonely"


def _detector(make_iam: Callable[..., MagicMock], entities: dict[str, Any]) -> UnusedPolicyDetector:
    client = make_iam(
        pages={
            "list_policies": [
                {
                    "Policies": [
                        {
                            "PolicyName": "lonely",
                            "Arn": POLICY_ARN,
                            "CreateDate": datetime.now(UTC),
                            "DefaultVersionId": "v1",
                        }
                    ]
                }
            ],
            "list_entities_for_policy": [entities],
        },
        list_policy_tags={"Tags": []},
    )
    return UnusedPolicyDetector(ACCOUNT, REGION, {"enabled": True}, iam_client=client)


def test_zero_attachments_is_flagged(make_iam: Callable[..., MagicMock]) -> None:
    findings = list(
        _detector(make_iam, {"PolicyRoles": [], "PolicyUsers": [], "PolicyGroups": []}).scan()
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].details["policy_arn"] == POLICY_ARN


def test_one_role_attachment_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    entities = {"PolicyRoles": [{"RoleName": "r"}], "PolicyUsers": [], "PolicyGroups": []}
    assert list(_detector(make_iam, entities).scan()) == []


def test_one_group_attachment_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    entities = {"PolicyRoles": [], "PolicyUsers": [], "PolicyGroups": [{"GroupName": "g"}]}
    assert list(_detector(make_iam, entities).scan()) == []
