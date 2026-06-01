"""Audit log writer — JSON Lines to S3 (docs/architecture.md §13, CLAUDE.md).

Every framework action (policy decision, remediation, approval) appends one
immutable JSONL record to s3://{AuditLogBucket}/audit/YYYY/MM/DD/HH/{ulid}.jsonl.
Records are never overwritten — one object per action.
"""

import json
import os
from datetime import UTC, datetime
from typing import Any, Literal

import boto3
from aws_lambda_powertools import Logger

from shared.identifiers import new_ulid

logger = Logger(child=True)

AuditEventType = Literal[
    "policy_decided",
    "remediation_started",
    "remediation_completed",
    "remediation_failed",
    "approval_requested",
    "approval_granted",
    "approval_rejected",
]


def _s3() -> Any:
    return boto3.client("s3")


def _audit_bucket() -> str:
    bucket = os.environ.get("AUDIT_BUCKET")
    if not bucket:
        raise RuntimeError("AUDIT_BUCKET environment variable is not set")
    return bucket


def write_audit_event(
    *,
    event_type: AuditEventType,
    finding_pk: str,
    finding_sk: str,
    rule_id: str,
    resource_arn: str,
    actor: str,
    details: dict[str, Any] | None = None,
    snapshot_s3_key: str | None = None,
) -> str:
    """Write one audit record. Returns its S3 key."""
    now = datetime.now(UTC)
    audit_id = new_ulid()
    record: dict[str, Any] = {
        "audit_id": audit_id,
        "timestamp": now.isoformat(),
        "event_type": event_type,
        "finding_pk": finding_pk,
        "finding_sk": finding_sk,
        "rule_id": rule_id,
        "resource_arn": resource_arn,
        "actor": actor,
        "details": details or {},
        "snapshot_s3_key": snapshot_s3_key,
    }
    key = f"audit/{now:%Y/%m/%d/%H}/{audit_id}.jsonl"
    _s3().put_object(
        Bucket=_audit_bucket(),
        Key=key,
        Body=(json.dumps(record, default=str) + "\n").encode(),
        ContentType="application/x-ndjson",
    )
    logger.info("audit event written", extra={"event_type": event_type, "s3_key": key})
    return key
