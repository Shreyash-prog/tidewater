"""Tests for the iam.orphaned_trust detector."""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from detectors.iam.detectors.orphaned_trust import OrphanedTrustDetector
from shared.models import Severity

ACCOUNT = "111111111111"
REGION = "us-east-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/the-role"

_NO_SUCH_ENTITY = ClientError({"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GetRole")


def _trust(*aws_principals: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": list(aws_principals)},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _detector(
    make_iam: Callable[..., MagicMock], trust: dict[str, Any], existing: set[str]
) -> OrphanedTrustDetector:
    def _get_role(RoleName: str) -> dict[str, Any]:
        if RoleName == "the-role":
            return {
                "Role": {"RoleName": "the-role", "Arn": ROLE_ARN, "AssumeRolePolicyDocument": trust}
            }
        if RoleName in existing:
            return {
                "Role": {"RoleName": RoleName, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{RoleName}"}
            }
        raise _NO_SUCH_ENTITY

    def _get_user(UserName: str) -> dict[str, Any]:
        if UserName in existing:
            return {"User": {"UserName": UserName}}
        raise _NO_SUCH_ENTITY

    client = make_iam(
        pages={"list_roles": [{"Roles": [{"RoleName": "the-role", "Arn": ROLE_ARN}]}]},
        get_role=MagicMock(side_effect=_get_role),
        get_user=MagicMock(side_effect=_get_user),
        list_role_tags={"Tags": []},
    )
    return OrphanedTrustDetector(ACCOUNT, REGION, {"enabled": True}, iam_client=client)


def test_orphan_present_is_flagged(make_iam: Callable[..., MagicMock]) -> None:
    trust = _trust(
        f"arn:aws:iam::{ACCOUNT}:role/valid",
        f"arn:aws:iam::{ACCOUNT}:role/orphan",
        "arn:aws:iam::999999999999:role/crossacct",  # other account — unverifiable, skipped
        f"arn:aws:iam::{ACCOUNT}:root",  # root — skipped
    )
    findings = list(_detector(make_iam, trust, existing={"valid"}).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].details["orphan_principals"] == [f"arn:aws:iam::{ACCOUNT}:role/orphan"]


def test_no_orphans_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    trust = _trust(f"arn:aws:iam::{ACCOUNT}:role/valid")
    assert list(_detector(make_iam, trust, existing={"valid"}).scan()) == []


def test_service_principal_only_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    trust = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    assert list(_detector(make_iam, trust, existing=set()).scan()) == []
