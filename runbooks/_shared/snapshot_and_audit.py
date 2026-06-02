"""Shared snapshot/audit/finding helpers for the IAM remediation runbooks.

This is the canonical, unit-tested implementation of the cross-cutting runbook
steps (snapshot-before-mutate, JSONL audit, finding resolution, event emit). The
SSM Automation documents currently inline equivalent logic per the Phase 4
``delete_iam_role.yml`` pattern (self-contained ``aws:executeScript`` steps);
wiring this module into the documents via SSM attachments is deferred — see the
Phase 5 PR notes. Keeping the logic here means it's validated by unit tests that
the inline YAML scripts otherwise couldn't get.

Functions take boto3 clients as arguments so they're trivially testable with moto.
"""

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

# Reuse the protected-role allowlist rather than duplicating it (CLAUDE.md).
from shared.role_guard import PROTECTED_NAME_PREFIXES as ROLE_PROTECTED_PATTERNS

__all__ = [
    "ROLE_PROTECTED_PATTERNS",
    "emit_remediation_event",
    "new_audit_id",
    "update_finding_resolved",
    "write_final_audit",
    "write_snapshot",
]


def new_audit_id() -> str:
    return format(int(time.time() * 1000), "x") + os.urandom(5).hex()


def write_snapshot(
    s3_client: Any,
    bucket: str,
    key: str,
    payload: dict[str, Any],
    *,
    finding_pk: str,
    finding_sk: str,
    taken_by: str,
) -> str:
    """Write the pre-mutation snapshot to S3 with standard metadata. Returns the key."""
    body = {
        **payload,
        "snapshot_metadata": {
            "snapshot_at": datetime.now(UTC).isoformat(),
            "taken_by": taken_by,
            "finding_pk": finding_pk,
            "finding_sk": finding_sk,
        },
    }
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(body, default=str).encode(),
        ContentType="application/json",
    )
    return key


def update_finding_resolved(
    dynamodb_client: Any,
    table_name: str,
    pk: str,
    sk: str,
    snapshot_key: str,
    *,
    note: str | None = None,
) -> None:
    names = {"#s": "status"}
    values: dict[str, Any] = {
        ":s": {"S": "resolved"},
        ":r": {"S": datetime.now(UTC).isoformat()},
        ":k": {"S": snapshot_key},
    }
    expression = "SET #s = :s, resolved_at = :r, snapshot_s3_key = :k"
    if note is not None:
        expression += ", resolution_note = :n"
        values[":n"] = {"S": note}
    dynamodb_client.update_item(
        TableName=table_name,
        Key={"pk": {"S": pk}, "sk": {"S": sk}},
        UpdateExpression=expression,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def emit_remediation_event(
    events_client: Any,
    bus_name: str,
    *,
    finding_pk: str,
    finding_sk: str,
    event_type: str,
    detail: dict[str, Any] | None = None,
) -> None:
    payload = {"finding_pk": finding_pk, "finding_sk": finding_sk, **(detail or {})}
    events_client.put_events(
        Entries=[
            {
                "Source": "tidewater.ssm_automation",
                "DetailType": event_type,
                "EventBusName": bus_name,
                "Detail": json.dumps(payload, default=str),
            }
        ]
    )


def write_final_audit(
    s3_client: Any,
    bucket: str,
    *,
    execution_id: str,
    finding_pk: str,
    finding_sk: str,
    rule_id: str,
    resource_arn: str,
    actor: str,
    success: bool,
    snapshot_s3_key: str | None = None,
) -> str:
    """Append the end-of-automation JSONL audit record. Returns its S3 key."""
    now = datetime.now(UTC)
    audit_id = new_audit_id()
    record = {
        "audit_id": audit_id,
        "timestamp": now.isoformat(),
        "event_type": "remediation_completed" if success else "remediation_failed",
        "execution_id": execution_id,
        "finding_pk": finding_pk,
        "finding_sk": finding_sk,
        "rule_id": rule_id,
        "resource_arn": resource_arn,
        "actor": actor,
        "snapshot_s3_key": snapshot_s3_key,
    }
    key = f"audit/{now:%Y/%m/%d/%H}/{audit_id}.jsonl"
    s3_client.put_object(Bucket=bucket, Key=key, Body=(json.dumps(record) + "\n").encode())
    return key
