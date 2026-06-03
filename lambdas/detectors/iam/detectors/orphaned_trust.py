"""iam.orphaned_trust detector.

Flags roles whose AssumeRolePolicyDocument trusts same-account IAM principals
that no longer exist. Two orphan forms are recognized:

* **ARN-format** (e.g. ``arn:aws:iam::<acct>:user/some-user``) — verified by a
  same-account ``GetRole`` / ``GetUser`` lookup. AWS occasionally retains these
  for a few minutes after the entity is deleted, so they're MEDIUM.
* **Bare AWS unique IDs** (``AIDA*`` user, ``AROA*`` role, ``AIPA*`` group) — AWS
  replaces a deleted principal's ARN with its bare unique ID in the trust
  document. These are **unmistakable** orphans: AWS rejects bare unique IDs when
  *creating* a trust policy, so any present can only have come from a deletion.
  A finding with at least one of these is HIGH.

Cross-account principals and the account root can't be verified and are skipped.
Read-only.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from shared.detector_base import Detector
from shared.models import Finding, Severity
from shared.role_guard import is_protected_role

# Unique-ID prefixes AWS assigns to IAM entities. Matched by prefix, NOT length:
# the bare IDs are 21 chars today, but AWS doesn't guarantee that forever, and a
# bare ID with one of these prefixes is an orphan regardless of length.
BARE_UNIQUE_ID_PREFIXES = ("AIDA", "AROA", "AIPA")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class OrphanedTrustDetector(Detector):
    rule_id = "iam.orphaned_trust"
    service = "iam"
    severity = Severity.MEDIUM

    def __init__(
        self, account: str, region: str, threshold: dict[str, Any], iam_client: Any | None = None
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")

    def scan(self) -> Iterator[Finding]:
        now = datetime.now(UTC)
        for page in self.iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                if is_protected_role(role["Arn"]):
                    continue
                detail = self.iam.get_role(RoleName=role["RoleName"])["Role"]
                orphans = self._orphan_principals(detail.get("AssumeRolePolicyDocument", {}))
                if orphans:
                    # A bare unique ID is a confirmed deletion (AWS won't accept it
                    # on create), so it outranks the occasionally-transient ARN form.
                    has_unique_id = any(o["type"] == "unique_id" for o in orphans)
                    severity = Severity.HIGH if has_unique_id else Severity.MEDIUM
                    yield Finding(
                        account=self.account,
                        region=self.region,
                        service="iam",
                        resource_arn=detail["Arn"],
                        rule_id=self.rule_id,
                        severity=severity,
                        detected_at=now,
                        last_seen_at=now,
                        details={
                            "role_name": detail["RoleName"],
                            "role_arn": detail["Arn"],
                            "orphan_principals": orphans,
                            "tags": self._role_tags(detail["RoleName"]),
                        },
                    )

    def _role_tags(self, role_name: str) -> dict[str, str]:
        resp = self.iam.list_role_tags(RoleName=role_name)
        return {tag["Key"]: tag["Value"] for tag in resp.get("Tags", [])}

    def _orphan_principals(self, document: dict[str, Any]) -> list[dict[str, str]]:
        """Return orphan principals as ``{"type": "arn"|"unique_id", "principal": ...}``.

        The ``type`` makes it clear in the dashboard which category each orphan is,
        and the remediator drops both forms from the trust policy.
        """
        orphans: dict[str, dict[str, str]] = {}
        for statement in _as_list(document.get("Statement")):
            if not isinstance(statement, dict):
                continue
            aws_principals = _as_list((statement.get("Principal") or {}).get("AWS"))
            for principal in aws_principals:
                classified = self._classify(str(principal))
                if classified is not None:
                    orphans[classified["principal"]] = classified
        return sorted(orphans.values(), key=lambda o: o["principal"])

    def _classify(self, principal: str) -> dict[str, str] | None:
        if self._is_bare_unique_id(principal):
            return {"type": "unique_id", "principal": principal}
        if self._is_arn_orphan(principal):
            return {"type": "arn", "principal": principal}
        return None

    @staticmethod
    def _is_bare_unique_id(principal: str) -> bool:
        # Bare IDs are not ARNs and carry an IAM-entity unique-ID prefix.
        return not principal.startswith("arn:") and principal.startswith(BARE_UNIQUE_ID_PREFIXES)

    def _is_arn_orphan(self, principal_arn: str) -> bool:
        # Only verifiable: same-account role/user ARNs. Skip root and cross-account.
        parts = principal_arn.split(":")
        if len(parts) < 6 or parts[4] != self.account:
            return False
        resource = parts[5]
        if resource.startswith("role/"):
            return not self._exists(self.iam.get_role, RoleName=resource.split("/", 1)[1])
        if resource.startswith("user/"):
            return not self._exists(self.iam.get_user, UserName=resource.split("/", 1)[1])
        return False

    @staticmethod
    def _exists(api: Any, **kwargs: Any) -> bool:
        try:
            api(**kwargs)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return False
            raise
