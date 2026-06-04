"""iam.policy_quota detector (+ forecasting).

Flags roles approaching the IAM hard limit of 10 attached managed policies:
HIGH at the limit (>= 10), MEDIUM when at/above the configured
`attached_count_threshold` (default 8). Read-only.

This detector is also Tidewater's first **forecast-eligible** rule. On every scan
it appends each role's attached-policy count to the metric_history table, and —
when the rule's forecast is enabled — it reads that history back and projects
when the role will breach the quota. A clean rising trend that breaches within
`alert_at_days_remaining` days emits a SEPARATE finding, rule_id
`iam.policy_quota.forecast_alert`, with its own lifecycle and policy decision.
Metric writes are best-effort: a failed write is logged and never blocks
detection. See CLAUDE.md "Forecasting".
"""

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
from aws_lambda_powertools import Logger
from boto3.dynamodb.conditions import Key

from shared.detector_base import Detector
from shared.forecasting import compute_forecast
from shared.metrics import metric_history_pk, write_metric_history
from shared.models import Finding, Severity
from shared.role_guard import is_protected_role

logger = Logger(child=True)

IAM_ATTACHED_POLICY_LIMIT = 10
FORECAST_RULE_ID = "iam.policy_quota.forecast_alert"


class PolicyQuotaDetector(Detector):
    rule_id = "iam.policy_quota"
    service = "iam"
    severity = Severity.HIGH

    def __init__(
        self,
        account: str,
        region: str,
        threshold: dict[str, Any],
        iam_client: Any | None = None,
        metric_history_table: Any | None = None,
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")
        self._metric_table = metric_history_table
        self._metric_table_resolved = metric_history_table is not None

    def _metrics_table(self) -> Any | None:
        """The metric_history Table resource, or None if not configured.

        Built lazily from METRIC_HISTORY_TABLE so unit tests that don't exercise
        forecasting (and don't set the env) simply skip metric writes/reads.
        """
        if not self._metric_table_resolved:
            name = os.environ.get("METRIC_HISTORY_TABLE")
            self._metric_table = boto3.resource("dynamodb").Table(name) if name else None
            self._metric_table_resolved = True
        return self._metric_table

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
                yield from self._evaluate_role(role, threshold=threshold, now=now)

    def _evaluate_role(
        self, role: dict[str, Any], *, threshold: int, now: datetime
    ) -> Iterator[Finding]:
        role_arn = role["Arn"]
        role_name = role["RoleName"]
        names = self._attached_policy_names(role_name)
        count = len(names)
        tags = self._role_tags(role_name)

        # Accumulate history on EVERY scan — forecasting needs complete data, not
        # just history of breaches. Best-effort: never let it break detection.
        self._record_metric(role_arn, count)

        # Current-state finding — fires only on an actual breach (unchanged).
        if count >= threshold:
            severity = Severity.HIGH if count >= IAM_ATTACHED_POLICY_LIMIT else Severity.MEDIUM
            yield Finding(
                account=self.account,
                region=self.region,
                service="iam",
                resource_arn=role_arn,
                rule_id=self.rule_id,
                severity=severity,
                detected_at=now,
                last_seen_at=now,
                details={
                    "role_name": role_name,
                    "role_arn": role_arn,
                    "attached_count": count,
                    "threshold": threshold,
                    "attached_policy_names": names,
                    "tags": tags,
                },
            )

        # Forecast finding — a SEPARATE, independent check. Best-effort: a metric
        # read/compute failure is logged and never blocks current-state detection.
        try:
            forecast_finding = self._forecast_finding(
                role_arn, role_name, count, tags=tags, now=now
            )
        except Exception:
            logger.warning(
                "iam.policy_quota: forecast computation failed; continuing",
                extra={"resource_arn": role_arn},
            )
            forecast_finding = None
        if forecast_finding is not None:
            yield forecast_finding

    def _record_metric(self, role_arn: str, count: int) -> None:
        table = self._metrics_table()
        if table is None:
            return
        try:
            write_metric_history(
                table,
                account=self.account,
                region=self.region,
                service="iam",
                resource_arn=role_arn,
                rule_id=self.rule_id,
                value=float(count),
                metadata={"attached_count": count},
            )
        except Exception:
            logger.warning(
                "iam.policy_quota: metric_history write failed; continuing",
                extra={"resource_arn": role_arn},
            )

    def _forecast_finding(
        self, role_arn: str, role_name: str, count: int, *, tags: dict[str, str], now: datetime
    ) -> Finding | None:
        if not self.threshold.get("forecast_enabled"):
            return None
        alert_at_days = self.threshold.get("alert_at_days_remaining")
        if alert_at_days is None:
            return None
        history = self._history(role_arn)
        forecast = compute_forecast(
            history, current_value=count, quota=IAM_ATTACHED_POLICY_LIMIT, now=now
        )
        if forecast["status"] != "numeric":
            return None
        if forecast["days_to_breach"] > float(alert_at_days):
            return None
        logger.info(
            "iam.policy_quota: forecast breach imminent",
            extra={
                "rule_id": FORECAST_RULE_ID,
                "resource_arn": role_arn,
                "days_to_breach": forecast["days_to_breach"],
                "confidence": forecast["confidence"],
            },
        )
        return Finding(
            account=self.account,
            region=self.region,
            service="iam",
            resource_arn=role_arn,
            rule_id=FORECAST_RULE_ID,
            severity=Severity.MEDIUM,
            detected_at=now,
            last_seen_at=now,
            details={
                "role_name": role_name,
                "role_arn": role_arn,
                "current_count": count,
                "quota": IAM_ATTACHED_POLICY_LIMIT,
                "alert_at_days_remaining": alert_at_days,
                "forecast": forecast,
                "tags": tags,
            },
        )

    def _history(self, role_arn: str) -> list[dict[str, Any]]:
        table = self._metrics_table()
        if table is None:
            return []
        pk = metric_history_pk(self.account, self.region, "iam", role_arn)
        resp = table.query(KeyConditionExpression=Key("pk").eq(pk), ScanIndexForward=True)
        items: list[dict[str, Any]] = resp.get("Items", [])
        return items

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
