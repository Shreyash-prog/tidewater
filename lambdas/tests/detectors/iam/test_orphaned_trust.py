"""Tests for the iam.orphaned_trust detector.

The detector recognizes two orphan forms in a role's trust policy: same-account
ARN-format principals that no longer resolve (verified via GetRole/GetUser), and
bare AWS unique IDs (AIDA*/AROA*/AIPA*) that AWS substitutes for a deleted
entity's ARN. The fakes here mock GetRole/GetUser directly — moto's behavior for
bare unique IDs is undefined, and explicit mocks make the existence checks clear.
"""

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


def _principals(finding: Any) -> list[dict[str, str]]:
    return finding.details["orphan_principals"]


def test_arn_format_orphan_is_flagged_medium(make_iam: Callable[..., MagicMock]) -> None:
    # (a) Existing case: ARN-format orphan, no bare ids → MEDIUM.
    trust = _trust(
        f"arn:aws:iam::{ACCOUNT}:role/valid",
        f"arn:aws:iam::{ACCOUNT}:role/orphan",
        "arn:aws:iam::999999999999:role/crossacct",  # other account — unverifiable, skipped
        f"arn:aws:iam::{ACCOUNT}:root",  # root — skipped
    )
    findings = list(_detector(make_iam, trust, existing={"valid"}).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert _principals(findings[0]) == [
        {"type": "arn", "principal": f"arn:aws:iam::{ACCOUNT}:role/orphan"}
    ]


def test_bare_unique_id_orphan_is_flagged_high(make_iam: Callable[..., MagicMock]) -> None:
    # (b) NEW case that was previously missed entirely: a deleted user is left as a
    # bare AIDA* unique id. There is one valid principal so the role is still
    # assumable, but the bare id must be flagged HIGH.
    trust = _trust(f"arn:aws:iam::{ACCOUNT}:role/valid", "AIDASITUILUEC7BNIGN7A")
    findings = list(_detector(make_iam, trust, existing={"valid"}).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert _principals(findings[0]) == [{"type": "unique_id", "principal": "AIDASITUILUEC7BNIGN7A"}]


def test_mixed_arn_and_bare_id_orphans(make_iam: Callable[..., MagicMock]) -> None:
    # (c) Both forms present → flagged HIGH (because a bare id is present), and the
    # finding lists each with the correct type.
    trust = _trust(
        f"arn:aws:iam::{ACCOUNT}:role/valid",
        f"arn:aws:iam::{ACCOUNT}:user/deleted-user",  # arn-format orphan
        "AROAEXAMPLEROLEUNIQID",  # bare role unique id
    )
    findings = list(_detector(make_iam, trust, existing={"valid"}).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    # Sorted by principal string; uppercase bare ids sort ahead of lowercase ARNs.
    assert _principals(findings[0]) == [
        {"type": "unique_id", "principal": "AROAEXAMPLEROLEUNIQID"},
        {"type": "arn", "principal": f"arn:aws:iam::{ACCOUNT}:user/deleted-user"},
    ]


def test_root_plus_bare_id_flags_only_bare_id(make_iam: Callable[..., MagicMock]) -> None:
    # (d) Account root is always valid and must never be flagged; only the bare id.
    trust = _trust(f"arn:aws:iam::{ACCOUNT}:root", "AIPAEXAMPLEGROUPUNIQI")
    findings = list(_detector(make_iam, trust, existing=set()).scan())
    assert len(findings) == 1
    assert _principals(findings[0]) == [{"type": "unique_id", "principal": "AIPAEXAMPLEGROUPUNIQI"}]


def test_bare_id_matched_on_prefix_not_length(make_iam: Callable[..., MagicMock]) -> None:
    # (e) Real AIDA* ids are 21 chars today, but the check is prefix-based: a short
    # AIDA* token is still recognized so the detector keeps working if AWS ever
    # changes the id length.
    trust = _trust(f"arn:aws:iam::{ACCOUNT}:role/valid", "AIDASHORT")
    findings = list(_detector(make_iam, trust, existing={"valid"}).scan())
    assert len(findings) == 1
    assert _principals(findings[0]) == [{"type": "unique_id", "principal": "AIDASHORT"}]


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
