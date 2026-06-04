"""lambda.unused_function detector.

Flags Lambda functions that received zero ``AWS/Lambda Invocations`` over a
configurable window. The signal source is a CloudWatch metric (not the service
API as the IAM detectors use): a function is "unused" if ``Sum(Invocations)``
over the last ``idle_days`` is exactly 0. Read-only — deletion happens in the
``TidewaterDeleteUnusedFunction`` runbook, which adds downstream-impact gates.

`lambda:ListFunctions` does not return tags, so each function needs a separate
`lambda:ListTags` call (tags drive tag-based policy decisions downstream).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from aws_lambda_powertools import Logger

from shared.detector_base import Detector
from shared.models import Finding, Severity

logger = Logger(child=True)

_NAMESPACE = "AWS/Lambda"
_METRIC = "Invocations"
_PERIOD_SECONDS = 86400  # daily aggregation across the window


class UnusedFunctionDetector(Detector):
    rule_id = "lambda.unused_function"
    service = "lambda"
    severity = Severity.MEDIUM

    def __init__(
        self,
        account: str,
        region: str,
        threshold: dict[str, Any],
        lambda_client: Any | None = None,
        cloudwatch_client: Any | None = None,
    ) -> None:
        super().__init__(account, region, threshold)
        self.lambda_: Any = lambda_client or boto3.client("lambda")
        self.cw: Any = cloudwatch_client or boto3.client("cloudwatch")

    def _idle_days(self) -> int:
        """Return the configured idle-days window.

        Required — there is intentionally no default. A rule that omits it is a
        platform misconfiguration we surface loudly rather than silently picking a
        window (which could auto-remediate far more aggressively than intended).
        """
        raw = self.threshold.get("idle_days")
        if raw is None:
            raise ValueError(
                "rule lambda.unused_function requires threshold.idle_days to be configured."
            )
        return int(raw)

    def scan(self) -> Iterator[Finding]:
        idle_days = self._idle_days()
        now = datetime.now(UTC)
        window_start = now - timedelta(days=idle_days)
        logger.info(
            "lambda.unused_function: evaluating functions",
            extra={"rule_id": self.rule_id, "idle_days": idle_days},
        )
        for page in self.lambda_.get_paginator("list_functions").paginate():
            for function in page.get("Functions", []):
                if self._invocations(function["FunctionName"], window_start, now) == 0:
                    yield self._finding(
                        function, idle_days=idle_days, now=now, window_start=window_start
                    )

    def _invocations(self, function_name: str, start: datetime, end: datetime) -> float:
        resp = self.cw.get_metric_statistics(
            Namespace=_NAMESPACE,
            MetricName=_METRIC,
            Dimensions=[{"Name": "FunctionName", "Value": function_name}],
            StartTime=start,
            EndTime=end,
            Period=_PERIOD_SECONDS,
            Statistics=["Sum"],
        )
        # No datapoints at all (never invoked) sums to 0 — also "unused".
        return sum(point.get("Sum", 0.0) for point in resp.get("Datapoints", []))

    def _tags(self, function_arn: str) -> dict[str, str]:
        resp = self.lambda_.list_tags(Resource=function_arn)
        return dict(resp.get("Tags", {}))

    def _finding(
        self, function: dict[str, Any], *, idle_days: int, now: datetime, window_start: datetime
    ) -> Finding:
        details: dict[str, Any] = {
            "function_name": function["FunctionName"],
            "runtime": function.get("Runtime"),
            "last_modified": function.get("LastModified"),
            "code_size_bytes": function.get("CodeSize"),
            "memory_mb": function.get("MemorySize"),
            # Always zero for a flagged function; kept explicit (and an int, so the
            # DynamoDB write never sees a float).
            "invocations_in_window": 0,
            "window_start": window_start.isoformat(),
            "window_end": now.isoformat(),
            "threshold_idle_days": idle_days,
            "tags": self._tags(function["FunctionArn"]),
        }
        return Finding(
            account=self.account,
            region=self.region,
            service="lambda",
            resource_arn=function["FunctionArn"],
            rule_id=self.rule_id,
            severity=self.severity,
            detected_at=now,
            last_seen_at=now,
            details=details,
        )
