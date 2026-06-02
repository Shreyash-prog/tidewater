"""iam.policy_quota detector.

Flags roles approaching the IAM hard limit of 10 attached managed policies:
HIGH at the limit (>= 10), MEDIUM when at/above the configured
`attached_count_threshold` (default 8). Read-only.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
from aws_lambda_powertools import Logger

from shared.detector_base import Detector
from shared.models import Finding, Severity
from shared.role_guard import is_protected_role

logger = Logger(child=True)

IAM_ATTACHED_POLICY_LIMIT = 10


class PolicyQuotaDetector(Detector):
    rule_id = "iam.policy_quota"
    service = "iam"
    severity = Severity.HIGH

    def __init__(
        self, account: str, region: str, threshold: dict[str, Any], iam_client: Any | None = None
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")

    def scan(self) -> Iterator[Finding]:
        raw = self.threshold.get("attached_count_threshold")
        if raw is None:
            logger.warning(
                "iam.policy_quota: attached_count_threshold not configured; skipping run",
                extra={"rule_id": self.rule_id},
            )
            return
        threshold = int(raw)
        logger.info(
            "iam.policy_quota: evaluating roles",
            extra={"rule_id": self.rule_id, "attached_count_threshold": threshold},
        )
        now = datetime.now(UTC)
        for page in self.iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                if is_protected_role(role["Arn"]):
                    continue
                names = self._attached_policy_names(role["RoleName"])
                if len(names) < threshold:
                    continue
                severity = (
                    Severity.HIGH if len(names) >= IAM_ATTACHED_POLICY_LIMIT else Severity.MEDIUM
                )
                yield Finding(
                    account=self.account,
                    region=self.region,
                    service="iam",
                    resource_arn=role["Arn"],
                    rule_id=self.rule_id,
                    severity=severity,
                    detected_at=now,
                    last_seen_at=now,
                    details={
                        "role_name": role["RoleName"],
                        "role_arn": role["Arn"],
                        "attached_count": len(names),
                        "threshold": threshold,
                        "attached_policy_names": names,
                        "tags": self._role_tags(role["RoleName"]),
                    },
                )

    def _role_tags(self, role_name: str) -> dict[str, str]:
        resp = self.iam.list_role_tags(RoleName=role_name)
        return {tag["Key"]: tag["Value"] for tag in resp.get("Tags", [])}

    def _attached_policy_names(self, role_name: str) -> list[str]:
        names: list[str] = []
        for page in self.iam.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name
        ):
            names.extend(p["PolicyName"] for p in page.get("AttachedPolicies", []))
        return sorted(names)
