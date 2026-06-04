"""Metric-history writes for trend forecasting (docs/architecture.md §4).

Quota-shaped detectors append one data point per scan to the metric_history
table; `shared.forecasting.compute_forecast` reads them back. Points expire via
DynamoDB TTL (default 30 days), which is ample for a 14-day forecast window.

Keys mirror the findings table's composite shape:
  pk = account#region#service#resource_arn
  sk = ISO 8601 timestamp (chronological order on range queries)
"""

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any


def metric_history_pk(account: str, region: str, service: str, resource_arn: str) -> str:
    return f"{account}#{region}#{service}#{resource_arn}"


def write_metric_history(
    table: Any,  # boto3 DynamoDB Table resource
    account: str,
    region: str,
    service: str,
    resource_arn: str,
    rule_id: str,
    value: float,
    metadata: dict[str, Any] | None = None,
    ttl_days: int = 30,
) -> None:
    """Write a single metric data point to the metric_history table.

    `value` is stored as a Decimal (DynamoDB rejects floats); `metadata` is
    JSON-encoded. Callers should treat this as best-effort — a failed metric
    write must never block finding emission.
    """
    now = datetime.now(UTC)
    item: dict[str, Any] = {
        "pk": metric_history_pk(account, region, service, resource_arn),
        "sk": now.isoformat(),
        "rule_id": rule_id,
        "value": Decimal(str(value)),
        "ttl": int((now + timedelta(days=ttl_days)).timestamp()),
    }
    if metadata is not None:
        item["metadata"] = json.dumps(metadata)
    table.put_item(Item=item)
