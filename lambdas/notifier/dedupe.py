"""Finding-level notification dedupe via the findings table's `notified_at`.

We avoid a separate dedupe table by claiming a "notification slot" with a single
conditional UpdateItem on the finding row: the write succeeds only if `notified_at`
is unset or older than the staleness window. The `ConditionalCheckFailedException`
IS the dedupe signal — a recent notification already went out for this finding.

`notified_at` is a sparse attribute owned ONLY by the notifier; detectors and
remediators never read or write it.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError


def claim_notification_slot(table: Any, pk: str, sk: str, staleness_days: int = 7) -> bool:
    """Atomically claim a notification slot for one finding.

    Returns True if claimed (caller should send), False if a notification was
    already sent within `staleness_days` (caller should skip). Non-dedupe errors
    propagate.
    """
    now = datetime.now(UTC)
    cutoff = (now - timedelta(days=staleness_days)).isoformat()
    try:
        table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET notified_at = :now",
            ConditionExpression="attribute_not_exists(notified_at) OR notified_at < :cutoff",
            ExpressionAttributeValues={":now": now.isoformat(), ":cutoff": cutoff},
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise
