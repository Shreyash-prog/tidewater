"""iam.unused_policy detector.

Flags customer-managed (Scope=Local) policies with zero attachments — no roles,
users, or groups. Read-only.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3

from shared.detector_base import Detector
from shared.models import Finding, Severity


class UnusedPolicyDetector(Detector):
    rule_id = "iam.unused_policy"
    service = "iam"
    severity = Severity.LOW

    def __init__(
        self, account: str, region: str, threshold: dict[str, Any], iam_client: Any | None = None
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")

    def scan(self) -> Iterator[Finding]:
        now = datetime.now(UTC)
        for page in self.iam.get_paginator("list_policies").paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                if self._has_attachments(policy["Arn"]):
                    continue
                yield Finding(
                    account=self.account,
                    region=self.region,
                    service="iam",
                    resource_arn=policy["Arn"],
                    rule_id=self.rule_id,
                    severity=Severity.LOW,
                    detected_at=now,
                    last_seen_at=now,
                    details={
                        "policy_arn": policy["Arn"],
                        "policy_name": policy["PolicyName"],
                        "create_date": policy["CreateDate"].isoformat()
                        if hasattr(policy.get("CreateDate"), "isoformat")
                        else str(policy.get("CreateDate")),
                        "default_version_id": policy.get("DefaultVersionId"),
                        "tags": self._policy_tags(policy["Arn"]),
                    },
                )

    def _policy_tags(self, policy_arn: str) -> dict[str, str]:
        resp = self.iam.list_policy_tags(PolicyArn=policy_arn)
        return {tag["Key"]: tag["Value"] for tag in resp.get("Tags", [])}

    def _has_attachments(self, policy_arn: str) -> bool:
        roles: list[Any] = []
        users: list[Any] = []
        groups: list[Any] = []
        for page in self.iam.get_paginator("list_entities_for_policy").paginate(
            PolicyArn=policy_arn
        ):
            roles.extend(page.get("PolicyRoles", []))
            users.extend(page.get("PolicyUsers", []))
            groups.extend(page.get("PolicyGroups", []))
        return bool(roles or users or groups)
