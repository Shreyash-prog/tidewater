"""Detector base class (docs/architecture.md §6).

A detector scans one AWS service for one rule and yields Findings. Subclasses set
the class attributes and implement `scan()`; `run()` wraps it with metrics and
structured logging. Detectors are read-only — they never mutate AWS resources.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.metrics import MetricUnit

from shared.models import Finding, Severity

logger = Logger(child=True)
tracer = Tracer()
metrics = Metrics()


class Detector(ABC):
    # Subclasses set these.
    rule_id: str
    service: str
    severity: Severity

    def __init__(self, account: str, region: str, threshold: dict[str, Any]) -> None:
        self.account = account
        self.region = region
        self.threshold = threshold

    @abstractmethod
    def scan(self) -> Iterator[Finding]:
        """Yield zero or more Findings. Implementations call boto3 (read-only)."""

    @tracer.capture_method
    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for finding in self.scan():
            findings.append(finding)
            metrics.add_metric(name="FindingEmitted", unit=MetricUnit.Count, value=1)
        logger.info(
            "detector run complete",
            extra={
                "rule_id": self.rule_id,
                "service": self.service,
                "account": self.account,
                "region": self.region,
                "findings": len(findings),
            },
        )
        return findings
