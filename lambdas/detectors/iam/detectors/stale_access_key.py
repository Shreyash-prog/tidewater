"""iam.stale_access_key detector.

Flags Active access keys that are stale: never used and created more than
`idle_days` ago (HIGH), or last used more than `idle_days` ago (MEDIUM, and only
when also created more than `idle_days` ago). Read-only.

Remediation only *deactivates* the key (reversible); deletion is operator-driven.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
from aws_lambda_powertools import Logger

from shared.detector_base import Detector
from shared.models import Finding, Severity

logger = Logger(child=True)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class StaleAccessKeyDetector(Detector):
    rule_id = "iam.stale_access_key"
    service = "iam"
    severity = Severity.HIGH

    def __init__(
        self, account: str, region: str, threshold: dict[str, Any], iam_client: Any | None = None
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")

    def scan(self) -> Iterator[Finding]:
        raw = self.threshold.get("idle_days")
        if raw is None:
            logger.warning(
                "iam.stale_access_key: idle_days not configured; skipping run",
                extra={"rule_id": self.rule_id},
            )
            return
        idle_days = int(raw)
        logger.info(
            "iam.stale_access_key: evaluating access keys",
            extra={"rule_id": self.rule_id, "idle_days": idle_days},
        )
        now = datetime.now(UTC)
        for page in self.iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                yield from self._scan_user(user["UserName"], idle_days=idle_days, now=now)

    def _scan_user(self, user_name: str, *, idle_days: int, now: datetime) -> Iterator[Finding]:
        keys = self.iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        if not keys:
            return
        tags = self._user_tags(user_name)
        for key in keys:
            finding = self._evaluate(user_name, key, idle_days=idle_days, now=now, tags=tags)
            if finding is not None:
                yield finding

    def _user_tags(self, user_name: str) -> dict[str, str]:
        resp = self.iam.list_user_tags(UserName=user_name)
        return {tag["Key"]: tag["Value"] for tag in resp.get("Tags", [])}

    def _evaluate(
        self,
        user_name: str,
        key: dict[str, Any],
        *,
        idle_days: int,
        now: datetime,
        tags: dict[str, str],
    ) -> Finding | None:
        if key.get("Status") != "Active":
            return None
        key_id = key["AccessKeyId"]
        create_idle = (now - _aware(key["CreateDate"])).days
        if create_idle <= idle_days:
            return None  # too new

        last_used_raw = (
            self.iam.get_access_key_last_used(AccessKeyId=key_id)
            .get("AccessKeyLastUsed", {})
            .get("LastUsedDate")
        )

        if last_used_raw is None:
            severity = Severity.HIGH
            days_idle = create_idle
            last_used_iso: str | None = None
        else:
            last_used = _aware(last_used_raw)
            days_idle = (now - last_used).days
            if days_idle <= idle_days:
                return None  # recently used
            severity = Severity.MEDIUM
            last_used_iso = last_used.isoformat()

        return Finding(
            account=self.account,
            region=self.region,
            service="iam",
            resource_arn=f"arn:aws:iam::{self.account}:user/{user_name}#accesskey/{key_id}",
            rule_id=self.rule_id,
            severity=severity,
            detected_at=now,
            last_seen_at=now,
            details={
                "user_name": user_name,
                "access_key_id": key_id,
                "status": key["Status"],
                "create_date": _aware(key["CreateDate"]).isoformat(),
                "last_used_date": last_used_iso,
                "days_since_last_use": days_idle,
                "tags": tags,
            },
        )
