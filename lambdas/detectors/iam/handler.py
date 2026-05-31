"""IAM detector Lambda handler.

Loads enabled `iam` rules from S3, runs the detectors registered for them, writes
findings idempotently, and emits an EventBridge event per new/updated finding.

Phase 3: the only registered rule is iam.unused_role, and every finding's
policy_decision is hard-set to dry_run (the policy engine arrives in Phase 4).
Fails closed: if rules can't be loaded, it logs and emits zero findings.
"""

import os
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext

from detectors.iam.detectors.unused_role import UnusedRoleDetector
from shared.detector_base import Detector
from shared.event_emitter import emit_finding_event
from shared.findings_writer import FindingsTableWriter
from shared.models import Finding, PolicyAction
from shared.rule_loader import load_enabled_rules_for_service

logger = Logger()
tracer = Tracer()
metrics = Metrics()

SERVICE = "iam"

# rule_id -> detector class. Grows in Phase 5.
REGISTRY: dict[str, type[Detector]] = {
    "iam.unused_role": UnusedRoleDetector,
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

    try:
        rules = load_enabled_rules_for_service(SERVICE)
    except Exception:
        # Fail closed: never act on stale/unloadable config.
        logger.exception("failed to load rules; emitting zero findings")
        metrics.add_metric(name="RuleLoadFailure", unit=MetricUnit.Count, value=1)
        return {"findings_emitted": 0, "rules_run": 0}

    # Optional per-invocation threshold override (used by the smoke test to flag a
    # freshly created role; not used by scheduled runs). e.g. {"idle_days": -1}.
    threshold_override: dict[str, Any] = event.get("threshold_override") or {}

    findings: list[Finding] = []
    rules_run = 0
    for rule in rules:
        detector_cls = REGISTRY.get(rule.rule_id)
        if detector_cls is None:
            logger.info("unknown rule_id, skipping", extra={"rule_id": rule.rule_id})
            continue
        rules_run += 1
        threshold = {**rule.threshold, **threshold_override}
        detector = detector_cls(account=account, region=region, threshold=threshold)
        for finding in detector.run():
            finding.policy_decision = PolicyAction.DRY_RUN  # Phase 4 will decide for real
            findings.append(finding)

    result = FindingsTableWriter().write_batch(findings)
    for finding in result.created:
        emit_finding_event(finding, "created")
    for finding in result.updated:
        emit_finding_event(finding, "updated")

    logger.info(
        "iam detector complete",
        extra={"findings_emitted": result.count, "rules_run": rules_run},
    )
    return {"findings_emitted": result.count, "rules_run": rules_run}
