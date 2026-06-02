"""iam.orphaned_trust detector.

Flags roles whose AssumeRolePolicyDocument trusts same-account IAM principals
(roles/users) that no longer exist. Cross-account principals and the account root
can't be verified and are skipped. Read-only.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from shared.detector_base import Detector
from shared.models import Finding, Severity
from shared.role_guard import is_protected_role


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
                    yield Finding(
                        account=self.account,
                        region=self.region,
                        service="iam",
                        resource_arn=detail["Arn"],
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
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

    def _orphan_principals(self, document: dict[str, Any]) -> list[str]:
        orphans: list[str] = []
        for statement in _as_list(document.get("Statement")):
            if not isinstance(statement, dict):
                continue
            aws_principals = _as_list((statement.get("Principal") or {}).get("AWS"))
            for principal in aws_principals:
                if self._is_orphan(str(principal)):
                    orphans.append(str(principal))
        return sorted(set(orphans))

    def _is_orphan(self, principal_arn: str) -> bool:
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
