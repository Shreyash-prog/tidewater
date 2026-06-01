"""iam.unused_role detector.

Flags IAM roles that are idle past a threshold: either never used and created
more than `idle_days` ago (severity HIGH), or last used more than `idle_days` ago
(severity MEDIUM). Read-only — it never mutates IAM. AWS-managed/service-linked
roles are always skipped. The trust policy is deliberately NOT included in the
finding details (noise; surfaced separately in v1).
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3

from shared.detector_base import Detector
from shared.models import Finding, Severity

# Roles we never flag or delete. Matched against the role name and, for
# service-linked roles, the role path.
_SKIP_NAME_PREFIXES = (
    "AWSReservedSSO_",
    "cdk-hnb659fds-",
    "StackSet-",
    "OrganizationAccountAccessRole",
    "aws-controltower-",
    "aws-service-role/",
)
_SKIP_PATH_PREFIXES = ("/aws-service-role/",)

DEFAULT_IDLE_DAYS = 7


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class UnusedRoleDetector(Detector):
    rule_id = "iam.unused_role"
    service = "iam"
    severity = Severity.HIGH

    def __init__(
        self,
        account: str,
        region: str,
        threshold: dict[str, Any],
        iam_client: Any | None = None,
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")

    @staticmethod
    def _is_aws_managed(role: dict[str, Any]) -> bool:
        name = role.get("RoleName", "")
        path = role.get("Path", "/")
        if any(path.startswith(p) for p in _SKIP_PATH_PREFIXES):
            return True
        return any(name.startswith(p) for p in _SKIP_NAME_PREFIXES)

    def scan(self) -> Iterator[Finding]:
        idle_days = int(self.threshold.get("idle_days", DEFAULT_IDLE_DAYS))
        now = datetime.now(UTC)
        for page in self.iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                if self._is_aws_managed(role):
                    continue
                detail = self.iam.get_role(RoleName=role["RoleName"])["Role"]
                tags = self._role_tags(role["RoleName"])
                finding = self._evaluate(detail, idle_days=idle_days, now=now, tags=tags)
                if finding is not None:
                    yield finding

    def _role_tags(self, role_name: str) -> dict[str, str]:
        # Tags drive tag-based policy decisions (policy engine, Phase 4).
        resp = self.iam.list_role_tags(RoleName=role_name)
        return {tag["Key"]: tag["Value"] for tag in resp.get("Tags", [])}

    def _evaluate(
        self, role: dict[str, Any], *, idle_days: int, now: datetime, tags: dict[str, str]
    ) -> Finding | None:
        create_date = _aware(role["CreateDate"])
        last_used_raw = (role.get("RoleLastUsed") or {}).get("LastUsedDate")

        if last_used_raw is None:
            days_idle = (now - create_date).days
            severity = Severity.HIGH
            last_used_iso: str | None = None
        else:
            last_used = _aware(last_used_raw)
            days_idle = (now - last_used).days
            severity = Severity.MEDIUM
            last_used_iso = last_used.isoformat()

        # "More than idle_days" — exactly at threshold does not flag.
        if days_idle <= idle_days:
            return None

        details: dict[str, Any] = {
            "role_name": role["RoleName"],
            "role_arn": role["Arn"],
            "create_date": create_date.isoformat(),
            "last_used_date": last_used_iso,
            "days_idle": days_idle,
            "threshold_idle_days": idle_days,
            "tags": tags,
        }
        return Finding(
            account=self.account,
            region=self.region,
            service="iam",
            resource_arn=role["Arn"],
            rule_id=self.rule_id,
            severity=severity,
            detected_at=now,
            last_seen_at=now,
            details=details,
        )
