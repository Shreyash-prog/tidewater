"""Seed the metric_history table with synthetic data points for demo purposes.

Usage:
  python tools/seed_metric_history.py \\
    --table <metric_history_table_name> \\
    --resource-arn arn:aws:iam::155936382216:role/<role-name> \\
    --rule-id iam.policy_quota \\
    --account 155936382216 \\
    --region us-east-1 \\
    --service iam \\
    --values "5,5,6,6,7,7,7,8,8,8,9,9,10" \\
    --days-ago 13

Writes one data point per day for the given values, starting --days-ago days ago
(value[0] at that timestamp, then +1 day per value). The last value should be the
resource's current count. This lets us demo the forecast working today instead of
waiting ~14 days for real data to accumulate.

This is a CLI helper, NOT framework code — it lives in tools/ and is never
deployed.
"""

import argparse
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any


def parse_values(raw: str) -> list[float]:
    """Parse a comma-separated list of numbers (whitespace tolerated)."""
    return [float(part.strip()) for part in raw.split(",") if part.strip()]


def build_items(
    *,
    account: str,
    region: str,
    service: str,
    resource_arn: str,
    rule_id: str,
    values: list[float],
    days_ago: int,
    ttl_days: int = 30,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Build metric_history items (one per day) for the given values.

    Mirrors the schema written by ``shared.metrics.write_metric_history``:
    pk=account#region#service#resource_arn, sk=ISO timestamp, Decimal value, TTL.
    """
    now = now or datetime.now(UTC)
    start = now - timedelta(days=days_ago)
    pk = f"{account}#{region}#{service}#{resource_arn}"
    items: list[dict[str, Any]] = []
    for offset, value in enumerate(values):
        ts = start + timedelta(days=offset)
        items.append(
            {
                "pk": pk,
                "sk": ts.isoformat(),
                "rule_id": rule_id,
                "value": Decimal(str(value)),
                "ttl": int((ts + timedelta(days=ttl_days)).timestamp()),
            }
        )
    return items


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed metric_history for demos.")
    parser.add_argument("--table", required=True, help="metric_history DynamoDB table name")
    parser.add_argument("--resource-arn", required=True)
    parser.add_argument("--rule-id", default="iam.policy_quota")
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--service", default="iam")
    parser.add_argument("--values", required=True, help="comma-separated metric values")
    parser.add_argument("--days-ago", type=int, default=13)
    parser.add_argument("--ttl-days", type=int, default=30)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    import boto3  # local import: not needed when this module is imported for tests

    args = _parse_args(argv)
    items = build_items(
        account=args.account,
        region=args.region,
        service=args.service,
        resource_arn=args.resource_arn,
        rule_id=args.rule_id,
        values=parse_values(args.values),
        days_ago=args.days_ago,
        ttl_days=args.ttl_days,
    )
    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table)
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)
    print(f"Wrote {len(items)} data points to {args.table} for {args.resource_arn}")


if __name__ == "__main__":
    main()
