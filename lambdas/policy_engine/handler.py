"""Policy engine Lambda (DynamoDB Streams consumer).

For each new/updated finding it loads the rule, decides an action
(auto / prompt / dry_run / skip) from the rule's policy + the resource's tags +
the grace period, writes the decision back, and dispatches: AUTO → invoke the
remediator; PROMPT → create an approval row + emit approval.requested;
SKIP → mark skipped + emit finding.skipped; DRY_RUN → record only.

Idempotent: it only writes + dispatches when the computed decision differs from
what's already stored, so the write-back's own stream event terminates the loop.
Uses Powertools BatchProcessor for partial-batch-failure semantics.
"""

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.utilities.batch import (
    BatchProcessor,
    EventType,
    process_partial_response,
)
from aws_lambda_powertools.utilities.batch.types import PartialItemFailureResponse
from aws_lambda_powertools.utilities.data_classes.dynamo_db_stream_event import (
    DynamoDBRecord,
    DynamoDBRecordEventName,
)
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.exceptions import ClientError

from shared.audit import write_audit_event
from shared.event_emitter import emit_event
from shared.models import Approval, ApprovalStatus, Finding, FindingStatus, PolicyAction, Rule
from shared.rule_loader import load_enabled_rules_for_service

logger = Logger()
tracer = Tracer()
metrics = Metrics()

processor = BatchProcessor(event_type=EventType.DynamoDBStreams)

SOURCE = "tidewater.policy_engine"
ACTOR = "policy_engine"
_PROCESSABLE = (DynamoDBRecordEventName.INSERT, DynamoDBRecordEventName.MODIFY)


def _findings_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])


def _approvals_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["APPROVALS_TABLE"])


def _rule_for(finding: Finding) -> Rule | None:
    rules = load_enabled_rules_for_service(finding.service)
    return next((r for r in rules if r.rule_id == finding.rule_id), None)


def evaluate(rule: Rule, finding: Finding, now: datetime) -> tuple[PolicyAction, str]:
    """Decide the policy action for a finding. First matching override wins."""
    tags: dict[str, str] = finding.details.get("tags") or {}
    action = rule.policy.default
    reason = "policy default"
    for override in rule.policy.overrides:
        if all(tags.get(key) == value for key, value in override.match.items()):
            action = override.action
            reason = f"override matched {override.match}"
            break

    if action is PolicyAction.AUTO and now - finding.detected_at < timedelta(
        days=rule.grace_period_days
    ):
        reason = f"auto downgraded to prompt: {rule.grace_period_days}d grace not elapsed"
        action = PolicyAction.PROMPT

    return action, reason


def _write_decision(pk: str, sk: str, decision: PolicyAction, reason: str) -> None:
    names = {"#pd": "policy_decision", "#dr": "decision_reason"}
    values: dict[str, Any] = {":pd": decision.value, ":reason": reason}
    set_parts = ["#pd = :pd", "#dr = :reason"]
    if decision is PolicyAction.SKIP:
        names["#status"] = "status"
        values[":skipped"] = FindingStatus.SKIPPED.value
        set_parts.append("#status = :skipped")
    _findings_table().update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET " + ", ".join(set_parts),
        ConditionExpression="attribute_exists(pk)",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def _invoke_remediator(pk: str, sk: str, rule_id: str) -> None:
    boto3.client("lambda").invoke(
        FunctionName=os.environ["REMEDIATOR_FUNCTION_NAME"],
        InvocationType="Event",
        Payload=json.dumps({"finding_pk": pk, "finding_sk": sk, "rule_id": rule_id}).encode(),
    )


def approval_id_for(finding_pk: str, finding_sk: str) -> str:
    """Deterministic approval id from a finding's identity.

    One approval per (finding_pk, finding_sk) ever — keying the row on this hash
    turns the idempotency check into a single GetItem and makes a duplicate
    create impossible. Prefixed `appr_` so it's visually distinct from a ULID.
    """
    digest = hashlib.sha256(f"{finding_pk}|{finding_sk}".encode()).hexdigest()[:24]
    return f"appr_{digest}"


def _ensure_approval(finding: Finding, pk: str, sk: str) -> None:
    """Create exactly one pending approval per finding (idempotent)."""
    approval_id = approval_id_for(pk, sk)
    table = _approvals_table()
    existing = table.get_item(Key={"approval_id": approval_id, "metadata": "metadata"}).get("Item")
    if existing is not None:
        if existing.get("status") == ApprovalStatus.PENDING.value:
            logger.info(
                "approval already exists, skipping creation",
                extra={"approval_id": approval_id},
            )
        else:
            logger.warning(
                "finding was previously approved/rejected; not re-creating approval — "
                "should this be re-opened?",
                extra={"approval_id": approval_id, "approval_status": existing.get("status")},
            )
        return

    approval = Approval(
        approval_id=approval_id, finding_pk=pk, finding_sk=sk, requested_at=datetime.now(UTC)
    )
    item = approval.model_dump(mode="json")
    item["metadata"] = "metadata"  # table sort key
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(approval_id)")
    except ClientError as exc:
        # Lost a race to another invocation — the approval already exists; that's fine.
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "approval created concurrently, skipping", extra={"approval_id": approval_id}
            )
            return
        raise
    emit_event(
        "approval.requested",
        {"approval_id": approval_id, **finding.model_dump(mode="json")},
        source=SOURCE,
    )
    write_audit_event(
        event_type="approval_requested",
        finding_pk=pk,
        finding_sk=sk,
        rule_id=finding.rule_id,
        resource_arn=finding.resource_arn,
        actor=ACTOR,
        details={"approval_id": approval_id},
    )


def _dispatch(decision: PolicyAction, finding: Finding, pk: str, sk: str) -> None:
    if decision is PolicyAction.AUTO:
        _invoke_remediator(pk, sk, finding.rule_id)
        logger.info("dispatched auto-remediation", extra={"finding_sk": sk})
    elif decision is PolicyAction.PROMPT:
        _ensure_approval(finding, pk, sk)
    elif decision is PolicyAction.SKIP:
        emit_event("finding.skipped", finding.model_dump(mode="json"), source=SOURCE)


def _process(record: DynamoDBRecord) -> None:
    if record.event_name not in _PROCESSABLE:
        return
    image = record.dynamodb.new_image if record.dynamodb else None
    if not image:
        return

    status = image.get("status")
    stored_decision = image.get("policy_decision")
    # Already decided and no longer open (resolved / in_remediation / skipped).
    if status != FindingStatus.OPEN.value and stored_decision is not None:
        return

    finding = Finding.model_validate(image)
    pk, sk = image["pk"], image["sk"]

    rule = _rule_for(finding)
    if rule is None:
        logger.error("no enabled rule for finding; skipping", extra={"rule_id": finding.rule_id})
        return

    decision, reason = evaluate(rule, finding, datetime.now(UTC))

    # Only persist the decision (and its audit record) when it actually changed —
    # those are the duplicate-noise operations.
    if stored_decision != decision.value:
        _write_decision(pk, sk, decision, reason)
        write_audit_event(
            event_type="policy_decided",
            finding_pk=pk,
            finding_sk=sk,
            rule_id=finding.rule_id,
            resource_arn=finding.resource_arn,
            actor=ACTOR,
            details={"decision": decision.value, "reason": reason},
        )
        logger.info("policy decided", extra={"finding_sk": sk, "decision": decision.value})

    # Always dispatch — downstream ops (_ensure_approval, _invoke_remediator,
    # emit_event) are idempotent. This lets the framework reconverge if approvals
    # were purged or remediation needs retrying, instead of leaving an open
    # `prompt` finding with no approval row.
    _dispatch(decision, finding, pk, sk)


@logger.inject_lambda_context
@tracer.capture_lambda_handler
@metrics.log_metrics
def handler(event: dict[str, Any], context: LambdaContext) -> PartialItemFailureResponse:
    return process_partial_response(
        event=event, record_handler=_process, processor=processor, context=context
    )
