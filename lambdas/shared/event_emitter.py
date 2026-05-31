"""Emit Finding lifecycle events to the tidewater-events EventBridge bus.

The Phase 2 rule on the bus forwards everything with a `tidewater.*` source to the
SNS notifications topic, so emitting here is what surfaces findings downstream.
"""

import os
from typing import Any, Literal

import boto3
from aws_lambda_powertools import Logger

from shared.models import Finding

logger = Logger(child=True)

Action = Literal["created", "updated", "remediated", "skipped"]


def _events() -> Any:
    return boto3.client("events")


def _bus_name() -> str:
    bus = os.environ.get("EVENT_BUS_NAME")
    if not bus:
        raise RuntimeError("EVENT_BUS_NAME environment variable is not set")
    return bus


def emit_finding_event(finding: Finding, action: Action) -> None:
    """Publish a single Finding.{action} event for the finding."""
    entry = {
        "Source": f"tidewater.detector.{finding.service}",
        "DetailType": f"Finding.{action}",
        "Detail": finding.model_dump_json(),
        "EventBusName": _bus_name(),
    }
    resp = _events().put_events(Entries=[entry])
    failed = resp.get("FailedEntryCount", 0)
    if failed:
        logger.error(
            "failed to emit finding event",
            extra={"action": action, "rule_id": finding.rule_id, "failed": failed},
        )
