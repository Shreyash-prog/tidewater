"""Emit events to the tidewater-events EventBridge bus.

The Phase 2 rule on the bus forwards everything with a `tidewater.*` source to the
SNS notifications topic, so emitting here is what surfaces activity downstream.
"""

import json
import os
from typing import Any

import boto3
from aws_lambda_powertools import Logger

from shared.models import Finding

logger = Logger(child=True)


def _events() -> Any:
    return boto3.client("events")


def _bus_name() -> str:
    bus = os.environ.get("EVENT_BUS_NAME")
    if not bus:
        raise RuntimeError("EVENT_BUS_NAME environment variable is not set")
    return bus


def emit_event(detail_type: str, detail: dict[str, Any], *, source: str) -> None:
    """Publish one event. `source` must start with `tidewater.` to be routed to SNS."""
    resp = _events().put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps(detail, default=str),
                "EventBusName": _bus_name(),
            }
        ]
    )
    if resp.get("FailedEntryCount", 0):
        logger.error(
            "failed to emit event",
            extra={"source": source, "detail_type": detail_type},
        )


def emit_finding_event(finding: Finding, action: str) -> None:
    """Emit a Finding.{action} event (detector created/updated path)."""
    emit_event(
        f"Finding.{action}",
        finding.model_dump(mode="json"),
        source=f"tidewater.detector.{finding.service}",
    )
