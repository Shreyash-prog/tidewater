"""Approval mutation route — POST /approvals/{approval_id}.

Closes the human-in-the-loop side of the prompt → decide → remediate cycle. The
dashboard's approve/reject buttons hit this endpoint; on approve it invokes the
remediator Lambda the same way the policy engine does for auto decisions
(InvocationType=Event, fire-and-forget).

The approval_id is derived deterministically from the finding's (pk, sk) — the
same sha256 helper as policy_engine.handler.approval_id_for() — so the dashboard
can derive the URL client-side from the finding identity.

Handlers return a plain dict for 200 or a (body, status_code) tuple otherwise.
"""

import hashlib
import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import unquote

import boto3
from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError

from shared.audit import write_audit_event
from shared.event_emitter import emit_event

logger = Logger(child=True)

SOURCE = "tidewater.dashboard_api"
MAX_REASON_LEN = 200
MAX_APPROVER_LEN = 100

Response = dict[str, Any] | tuple[dict[str, Any], int]


def _approvals_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["APPROVALS_TABLE"])


def _findings_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])


def _lambda_client() -> Any:
    return boto3.client("lambda")


def approval_id_for(finding_pk: str, finding_sk: str) -> str:
    """Must match policy_engine.handler.approval_id_for exactly."""
    digest = hashlib.sha256(f"{finding_pk}|{finding_sk}".encode()).hexdigest()[:24]
    return f"appr_{digest}"


def _decimal_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, dict):
        return {k: _decimal_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decimal_safe(v) for v in value]
    return value


def decide(event: dict[str, Any]) -> Response:
    """POST /approvals/{approval_id} — body: {action, approver, reason?}."""
    approval_id = unquote((event.get("pathParameters") or {}).get("approval_id", ""))
    if not approval_id:
        return {"error": "missing approval_id"}, 400

    body = json.loads(event.get("body") or "{}")
    action = body.get("action")
    approver = (body.get("approver") or "").strip()
    reason = (body.get("reason") or "").strip()

    if action not in ("approve", "reject"):
        return {"error": "action must be 'approve' or 'reject'"}, 400
    if not approver or len(approver) > MAX_APPROVER_LEN:
        return {"error": f"approver name required, max {MAX_APPROVER_LEN} chars"}, 400
    if action == "reject" and len(reason) > MAX_REASON_LEN:
        return {"error": f"reason too long, max {MAX_REASON_LEN} chars"}, 400
    if action == "approve":
        reason = ""  # approve never carries a reason; drop silently

    approvals = _approvals_table()
    existing = approvals.get_item(Key={"approval_id": approval_id, "metadata": "metadata"}).get(
        "Item"
    )
    if existing is None:
        return {"error": "approval not found"}, 404

    finding_pk = str(existing["finding_pk"])
    finding_sk = str(existing["finding_sk"])
    if approval_id_for(finding_pk, finding_sk) != approval_id:
        logger.error(
            "approval_id mismatch — data integrity issue",
            extra={"approval_id": approval_id},
        )
        return {"error": "approval id mismatch"}, 500

    now = datetime.now(UTC).isoformat()
    new_status = "approved" if action == "approve" else "rejected"

    # Conditional update: only the first decider (status still pending) wins.
    update_expr = "SET #s = :new, decided_by = :who, decided_at = :now"
    values: dict[str, Any] = {
        ":new": new_status,
        ":who": approver,
        ":now": now,
        ":pending": "pending",
    }
    if action == "reject" and reason:
        update_expr += ", #r = :reason"
        values[":reason"] = reason
    names = {"#s": "status"}
    if action == "reject" and reason:
        names["#r"] = "reason"
    try:
        approvals.update_item(
            Key={"approval_id": approval_id, "metadata": "metadata"},
            UpdateExpression=update_expr,
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {
                "error": "approval already decided",
                "status": existing.get("status", "unknown"),
                "decided_by": existing.get("decided_by"),
                "decided_at": existing.get("decided_at"),
            }, 409
        raise

    # Update the finding (sync — must land before we invoke the remediator).
    findings = _findings_table()
    finding_status = "in_remediation" if action == "approve" else "skipped"
    decision_reason = (
        f"approved by {approver}"
        if action == "approve"
        else f"rejected by {approver}: {reason or 'no reason given'}"
    )
    findings.update_item(
        Key={"pk": finding_pk, "sk": finding_sk},
        UpdateExpression="SET #s = :new, decision_reason = :reason, last_seen_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":new": finding_status,
            ":reason": decision_reason,
            ":now": now,
        },
    )

    finding = findings.get_item(Key={"pk": finding_pk, "sk": finding_sk}).get("Item", {})
    rule_id = str(finding.get("rule_id", ""))
    resource_arn = str(finding.get("resource_arn", ""))

    if action == "approve":
        _lambda_client().invoke(
            FunctionName=os.environ["REMEDIATOR_FUNCTION_NAME"],
            InvocationType="Event",  # fire-and-forget, mirrors the policy engine
            Payload=json.dumps(_decimal_safe(finding)).encode(),
        )
        logger.info(
            "remediator invoked async after approval",
            extra={"approval_id": approval_id, "rule_id": rule_id},
        )

    emit_event(
        "Approval.granted" if action == "approve" else "Approval.denied",
        {
            "approval_id": approval_id,
            "finding_pk": finding_pk,
            "finding_sk": finding_sk,
            "decided_by": approver,
            "decided_at": now,
            "reason": reason if action == "reject" else None,
        },
        source=SOURCE,
    )
    audit_type: Literal["approval_granted", "approval_rejected"] = (
        "approval_granted" if action == "approve" else "approval_rejected"
    )
    write_audit_event(
        event_type=audit_type,
        finding_pk=finding_pk,
        finding_sk=finding_sk,
        rule_id=rule_id,
        resource_arn=resource_arn,
        actor=approver,
        details={"approval_id": approval_id, "reason": reason if action == "reject" else None},
    )

    return {
        "approval_id": approval_id,
        "status": new_status,
        "decided_by": approver,
        "decided_at": now,
        "reason": reason if action == "reject" else None,
    }
