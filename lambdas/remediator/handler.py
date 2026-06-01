"""Remediator Lambda.

Invoked by the policy engine (action=AUTO) or, from Phase 9, by the API when an
approval is granted. It maps a finding's rule_id to an SSM Automation document and
starts it — it never deletes anything directly (all destructive actions go through
SSM, per CLAUDE.md / architecture.md). The SSM runbook takes the snapshot before
deleting; this Lambda's job is dispatch + audit.

Defense in depth: it refuses to remediate AWS-managed/protected roles even if
invoked with one.
"""

import os
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

from shared.audit import write_audit_event
from shared.event_emitter import emit_event
from shared.models import FindingStatus
from shared.role_guard import is_protected_role, role_name_from_arn

logger = Logger()
tracer = Tracer()
metrics = Metrics()

SOURCE = "tidewater.remediator"
ACTOR = "remediator"

# rule_id -> SSM Automation document name. Grows in Phase 5.
REGISTRY: dict[str, str] = {
    "iam.unused_role": "TidewaterDeleteIamRole",
}


def _findings_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])


def _start_automation(document_name: str, parameters: dict[str, list[str]]) -> str:
    resp = boto3.client("ssm").start_automation_execution(
        DocumentName=document_name, Parameters=parameters
    )
    return str(resp["AutomationExecutionId"])


def _set_status(pk: str, sk: str, status: FindingStatus) -> None:
    _findings_table().update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET #status = :s",
        ConditionExpression="attribute_exists(pk)",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": status.value},
    )


@logger.inject_lambda_context
@tracer.capture_lambda_handler
@metrics.log_metrics
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    pk = event["finding_pk"]
    sk = event["finding_sk"]

    item = _findings_table().get_item(Key={"pk": pk, "sk": sk}).get("Item")
    if not item:
        logger.error("finding not found; nothing to remediate", extra={"finding_sk": sk})
        return {"status": "not_found"}

    rule_id = str(item["rule_id"])
    resource_arn = str(item["resource_arn"])

    document_name = REGISTRY.get(rule_id)
    if document_name is None:
        logger.error("no remediation runbook for rule_id; skipping", extra={"rule_id": rule_id})
        return {"status": "no_runbook", "rule_id": rule_id}

    # Defense in depth: never remediate a protected role, even if asked to.
    if is_protected_role(resource_arn):
        logger.error("refusing to remediate protected role", extra={"resource_arn": resource_arn})
        write_audit_event(
            event_type="remediation_failed",
            finding_pk=pk,
            finding_sk=sk,
            rule_id=rule_id,
            resource_arn=resource_arn,
            actor=ACTOR,
            details={"reason": "protected role — remediation refused"},
        )
        return {"status": "refused_protected", "resource_arn": resource_arn}

    role_name = role_name_from_arn(resource_arn)
    _set_status(pk, sk, FindingStatus.IN_REMEDIATION)

    execution_id = _start_automation(
        document_name,
        {
            "RoleName": [role_name],
            "SnapshotBucket": [os.environ["SNAPSHOT_BUCKET"]],
            "AuditBucket": [os.environ["AUDIT_BUCKET"]],
            "FindingsTableName": [os.environ["FINDINGS_TABLE"]],
            "FindingPk": [pk],
            "FindingSk": [sk],
            "EventBusName": [os.environ["EVENT_BUS_NAME"]],
            "AutomationAssumeRole": [os.environ["SSM_EXECUTION_ROLE_ARN"]],
        },
    )

    write_audit_event(
        event_type="remediation_started",
        finding_pk=pk,
        finding_sk=sk,
        rule_id=rule_id,
        resource_arn=resource_arn,
        actor=ACTOR,
        details={"document_name": document_name, "execution_id": execution_id},
    )
    emit_event(
        "finding.remediation_started",
        {
            "finding_pk": pk,
            "finding_sk": sk,
            "rule_id": rule_id,
            "resource_arn": resource_arn,
            "execution_id": execution_id,
        },
        source=SOURCE,
    )
    logger.info("remediation started", extra={"execution_id": execution_id, "role_name": role_name})
    return {"status": "started", "execution_id": execution_id}
