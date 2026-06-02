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
from collections.abc import Callable
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

# rule_id -> SSM Automation document name.
# NOTE: iam.wildcard_policy is intentionally absent — it is flag-only and must
# never be auto-remediated (CLAUDE.md). The policy engine never routes it here,
# and even if it did, REGISTRY.get() returns None → "no_runbook".
REGISTRY: dict[str, str] = {
    "iam.unused_role": "TidewaterDeleteIamRole",
    "iam.stale_access_key": "TidewaterDeleteIamAccessKey",
    "iam.orphaned_trust": "TidewaterRemoveTrustPrincipal",
    "iam.unused_policy": "TidewaterDeleteUnusedPolicy",
    "iam.policy_quota": "TidewaterDetachUnusedPolicy",
}


# Per-rule builders for the runbook-specific SSM parameters. Common parameters
# (snapshot/audit buckets, findings table, finding keys, bus, assume-role) are
# added centrally in the handler. Each builder reads the finding's `details`,
# which the detector populated.
def _params_unused_role(item: dict[str, Any]) -> dict[str, list[str]]:
    return {"RoleName": [role_name_from_arn(str(item["resource_arn"]))]}


def _params_stale_access_key(item: dict[str, Any]) -> dict[str, list[str]]:
    details = item.get("details", {})
    return {
        "AccessKeyId": [str(details["access_key_id"])],
        "UserName": [str(details["user_name"])],
    }


def _params_orphaned_trust(item: dict[str, Any]) -> dict[str, list[str]]:
    details = item.get("details", {})
    return {
        "RoleName": [str(details["role_name"])],
        "OrphanPrincipals": [str(p) for p in details["orphan_principals"]],
    }


def _params_unused_policy(item: dict[str, Any]) -> dict[str, list[str]]:
    return {"PolicyArn": [str(item.get("details", {})["policy_arn"])]}


def _params_detach_unused_policy(item: dict[str, Any]) -> dict[str, list[str]]:
    return {"RoleName": [str(item.get("details", {})["role_name"])]}


PARAM_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, list[str]]]] = {
    "iam.unused_role": _params_unused_role,
    "iam.stale_access_key": _params_stale_access_key,
    "iam.orphaned_trust": _params_orphaned_trust,
    "iam.unused_policy": _params_unused_policy,
    "iam.policy_quota": _params_detach_unused_policy,
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

    # Idempotent re-invocation guard: don't start a second SSM execution for a
    # finding that's already being remediated or is done.
    status = str(item.get("status", ""))
    if status in (FindingStatus.IN_REMEDIATION.value, FindingStatus.RESOLVED.value):
        logger.info(
            "finding already being remediated or resolved, skipping",
            extra={"finding_pk": pk, "finding_sk": sk, "status": status},
        )
        return {"status": "already_in_progress", "finding_status": status}

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

    build_params = PARAM_BUILDERS.get(rule_id)
    if build_params is None:
        logger.error("no parameter builder for rule_id; skipping", extra={"rule_id": rule_id})
        return {"status": "no_runbook", "rule_id": rule_id}

    _set_status(pk, sk, FindingStatus.IN_REMEDIATION)

    parameters: dict[str, list[str]] = {
        **build_params(item),
        "SnapshotBucket": [os.environ["SNAPSHOT_BUCKET"]],
        "AuditBucket": [os.environ["AUDIT_BUCKET"]],
        "FindingsTableName": [os.environ["FINDINGS_TABLE"]],
        "FindingPk": [pk],
        "FindingSk": [sk],
        "EventBusName": [os.environ["EVENT_BUS_NAME"]],
        "AutomationAssumeRole": [os.environ["SSM_EXECUTION_ROLE_ARN"]],
    }
    execution_id = _start_automation(document_name, parameters)

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
    logger.info(
        "remediation started",
        extra={"execution_id": execution_id, "rule_id": rule_id, "document_name": document_name},
    )
    return {"status": "started", "execution_id": execution_id}
