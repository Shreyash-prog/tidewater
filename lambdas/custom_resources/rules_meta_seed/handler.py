"""CloudFormation custom resource: seed a rules_meta row at deploy time.

Inserts/refreshes the metadata row for a rule (PK=rule_id, SK=metadata) with a
deploy-time `last_loaded_at`. Self-contained (boto3 from the runtime, no shared
code), invoked via the CDK Provider framework. On Delete it removes the row.
"""

from datetime import UTC, datetime
from typing import Any

import boto3


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request_type = event["RequestType"]
    props = event["ResourceProperties"]
    table_name: str = props["TableName"]
    rule_id: str = props["RuleId"]
    physical_id = f"rules-meta-seed-{rule_id}"

    table = boto3.resource("dynamodb").Table(table_name)

    if request_type in ("Create", "Update"):
        table.put_item(
            Item={
                "rule_id": rule_id,
                "metadata": "metadata",
                "enabled": props.get("Enabled", "true") == "true",
                "version": int(props.get("Version", "1")),
                "s3_key": props["S3Key"],
                "schedule": props.get("Schedule", "on-demand"),
                "last_loaded_at": datetime.now(UTC).isoformat(),
            }
        )
        return {"PhysicalResourceId": physical_id}

    if request_type == "Delete":
        table.delete_item(Key={"rule_id": rule_id, "metadata": "metadata"})
        return {"PhysicalResourceId": event.get("PhysicalResourceId", physical_id)}

    raise ValueError(f"Unexpected RequestType: {request_type}")
