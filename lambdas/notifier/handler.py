"""Notifier Lambda — EventBridge → filtered/deduped → SNS email.

Subscribes (via an EventBridge rule on the tidewater-events bus) to the finding
and remediation-failure events, filters to the notification-worthy ones, dedupes
per finding (so the same unresolved finding doesn't email on every scan), formats
a plain-text message, and publishes it to the tidewater-notifications SNS topic.
Email subscribers are added manually post-deploy (see CLAUDE.md "Notifications").

Only three categories notify: HIGH-severity findings with policy_decision=prompt,
any *.forecast_alert finding, and remediation.failed events. Everything else
(MEDIUM/LOW, auto/skip paths, happy-path remediation, internal coordination) is
deliberately silent — those live on the dashboard / audit log, not the inbox.
"""

import os
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

from notifier.dedupe import claim_notification_slot
from notifier.format import format_event

logger = Logger()
tracer = Tracer()
metrics = Metrics()

# Detail-types the EventBridge rule forwards. The detector emits Finding.created/
# Finding.updated; the policy engine re-emits Finding.updated once it has decided;
# the remediator emits remediation.failed. We match these and filter further here.
NOTIFY_EVENT_TYPES = frozenset({"Finding.created", "Finding.updated", "remediation.failed"})


def _findings_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])


def _sns() -> Any:
    return boto3.client("sns")


def _staleness_days() -> int:
    return int(os.environ.get("STALENESS_DAYS", "7"))


def _is_notification_worthy(event_type: str, detail: dict[str, Any]) -> bool:
    if event_type not in NOTIFY_EVENT_TYPES:
        return False
    if event_type == "remediation.failed":
        return True  # every failure notifies
    rule_id = str(detail.get("rule_id", ""))
    if rule_id.endswith(".forecast_alert"):
        return True  # projections always need eyes, regardless of severity
    severity = str(detail.get("severity", "")).lower()
    decision = str(detail.get("policy_decision", ""))
    return severity == "high" and decision == "prompt"


def _finding_keys(detail: dict[str, Any]) -> tuple[str | None, str | None]:
    """Best-effort (pk, sk) from any event detail shape.

    Finding events carry the full finding model (no pk/sk) — derive them. The
    remediation.failed event carries finding_pk/finding_sk directly.
    """
    if detail.get("pk") and detail.get("sk"):
        return str(detail["pk"]), str(detail["sk"])
    if detail.get("finding_pk") and detail.get("finding_sk"):
        return str(detail["finding_pk"]), str(detail["finding_sk"])
    fields = ("account", "region", "service", "resource_arn", "rule_id")
    if all(detail.get(f) for f in fields):
        pk = f"{detail['account']}#{detail['region']}#{detail['service']}"
        sk = f"{detail['resource_arn']}#{detail['rule_id']}"
        return pk, sk
    return None, None


@logger.inject_lambda_context
@tracer.capture_lambda_handler
@metrics.log_metrics
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    detail = event.get("detail", {}) or {}
    event_type = event.get("detail-type", "")

    if not _is_notification_worthy(event_type, detail):
        logger.info("event not notification-worthy; skipping", extra={"event_type": event_type})
        return {"sent": False, "reason": "filter"}

    # Dedupe per finding. If we can't identify the finding we still send (better a
    # rare duplicate than a dropped alert), but finding events always resolve keys.
    pk, sk = _finding_keys(detail)
    if (
        pk
        and sk
        and not claim_notification_slot(_findings_table(), pk, sk, staleness_days=_staleness_days())
    ):
        logger.info(
            "notification already sent recently; skipping",
            extra={"finding_pk": pk, "finding_sk": sk},
        )
        return {"sent": False, "reason": "deduped"}

    subject, body = format_event(event_type, detail)
    _sns().publish(
        TopicArn=os.environ["NOTIFICATIONS_TOPIC_ARN"],
        Subject=subject,
        Message=body,
    )
    logger.info("notification sent", extra={"event_type": event_type, "subject": subject})
    return {"sent": True, "event_type": event_type}
