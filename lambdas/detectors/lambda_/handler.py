"""Lambda detector Lambda handler.

Loads enabled `lambda` rules from S3, runs the registered detectors, writes
findings idempotently, and emits an EventBridge event per new/updated finding.
Mirrors the IAM detector handler exactly; the only differences are the service
name and the registry.

Like the IAM detector it hard-sets each finding's policy_decision to dry_run on
write — the policy engine (DynamoDB Streams) re-decides for real, and resetting
to dry_run each run is what lets a returned-to-prompt finding re-dispatch. Fails
closed: if rules can't be loaded, it logs and emits zero findings.
"""

import os
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext

from detectors.lambda_.detectors.unused_function import UnusedFunctionDetector
from shared.detector_base import Detector
from shared.event_emitter import emit_finding_event
from shared.findings_writer import FindingsTableWriter
from shared.models import Finding, PolicyAction
from shared.rule_loader import load_enabled_rules_for_service

logger = Logger()
tracer = Tracer()
metrics = Metrics()

SERVICE = "lambda"

# rule_id -> detector class.
REGISTRY: dict[str, type[Detector]] = {
    "lambda.unused_function": UnusedFunctionDetector,
}


def _resolve_account(event: dict[str, Any]) -> str:
    account = event.get("account")
    if account:
        return str(account)
    return boto3.client("sts").get_caller_identity()["Account"]


@logger.inject_lambda_context
@tracer.capture_lambda_handler
@metrics.log_metrics
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, int]:
    account = _resolve_account(event)
    region = event.get("region") or os.environ.get("AWS_REGION", "us-east-1")
    # Optional scoped, read-only rule prefix (defaults to production "rules/").
    rules_prefix = event.get("rules_prefix_override") or "rules/"

    try:
        rules = load_enabled_rules_for_service(SERVICE, prefix=rules_prefix)
    except Exception:
        # Fail closed: never act on stale/unloadable config.
        logger.exception("failed to load rules; emitting zero findings")
        metrics.add_metric(name="RuleLoadFailure", unit=MetricUnit.Count, value=1)
        return {"findings_emitted": 0, "rules_run": 0}

    findings: list[Finding] = []
    rules_run = 0
    for rule in rules:
        detector_cls = REGISTRY.get(rule.rule_id)
        if detector_cls is None:
            logger.info("unknown rule_id, skipping", extra={"rule_id": rule.rule_id})
            continue
        rules_run += 1
        detector = detector_cls(account=account, region=region, threshold=rule.threshold)
        for finding in detector.run():
            finding.policy_decision = PolicyAction.DRY_RUN  # policy engine decides for real
            findings.append(finding)

    result = FindingsTableWriter().write_batch(findings)
    for finding in result.created:
        emit_finding_event(finding, "created")
    for finding in result.updated:
        emit_finding_event(finding, "updated")

    logger.info(
        "lambda detector complete",
        extra={"findings_emitted": result.count, "rules_run": rules_run},
    )
    return {"findings_emitted": result.count, "rules_run": rules_run}
