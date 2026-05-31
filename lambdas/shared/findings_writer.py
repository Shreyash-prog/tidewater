"""Idempotent writer for the findings DynamoDB table (docs/architecture.md §4).

Each finding maps to a deterministic key — PK=`account#region#service`,
SK=`resource_arn#rule_id` — so re-running a detector upserts the same row instead
of duplicating it. We use UpdateItem (not BatchWriteItem) because only UpdateItem
supports the conditional upsert + `detected_at` preservation that idempotency
requires.
"""

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import boto3
from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError

from shared.aws_retry import with_backoff
from shared.models import Finding

logger = Logger(child=True)

_DDB_RETRYABLE = frozenset(
    {
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
        "RequestLimitExceeded",
        "InternalServerError",
        "TransactionConflictException",
    }
)

# Attributes set on every write besides the key and the special detected_at/last_seen_at.
_LOOPED_ATTRS = (
    "account",
    "region",
    "service",
    "resource_arn",
    "rule_id",
    "status",
    "severity",
    "details",
    "policy_decision",
)


@dataclass
class WriteResult:
    created: list[Finding] = field(default_factory=list)
    updated: list[Finding] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.created) + len(self.updated)


def finding_pk(finding: Finding) -> str:
    return f"{finding.account}#{finding.region}#{finding.service}"


def finding_sk(finding: Finding) -> str:
    return f"{finding.resource_arn}#{finding.rule_id}"


class FindingsTableWriter:
    def __init__(self, table_name: str | None = None) -> None:
        name = table_name or os.environ.get("FINDINGS_TABLE")
        if not name:
            raise RuntimeError("FINDINGS_TABLE environment variable is not set")
        self._table = boto3.resource("dynamodb").Table(name)

    def write_batch(self, findings: list[Finding]) -> WriteResult:
        result = WriteResult()
        for finding in findings:
            if self._upsert(finding):
                result.created.append(finding)
            else:
                result.updated.append(finding)
        logger.info(
            "findings written",
            extra={"created_count": len(result.created), "updated_count": len(result.updated)},
        )
        return result

    def _upsert(self, finding: Finding) -> bool:
        """Conditionally upsert one finding. Returns True if newly created."""
        now_iso = datetime.now(UTC).isoformat()
        payload = finding.model_dump(mode="json")

        names: dict[str, str] = {
            "#sk": "sk",
            "#detected_at": "detected_at",
            "#last_seen_at": "last_seen_at",
        }
        values: dict[str, Any] = {":now": now_iso}
        set_parts = [
            "#detected_at = if_not_exists(#detected_at, :now)",
            "#last_seen_at = :now",
        ]
        for i, attr in enumerate(_LOOPED_ATTRS):
            names[f"#a{i}"] = attr
            values[f":a{i}"] = payload[attr]
            set_parts.append(f"#a{i} = :a{i}")

        params: dict[str, Any] = {
            "Key": {"pk": finding_pk(finding), "sk": finding_sk(finding)},
            "UpdateExpression": "SET " + ", ".join(set_parts),
            # Idempotency guard: write only for a new item or a changed timestamp.
            "ConditionExpression": "attribute_not_exists(#sk) OR #last_seen_at <> :now",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values,
            "ReturnValues": "ALL_OLD",
        }
        try:
            resp = with_backoff(lambda: self._table.update_item(**params), retryable=_DDB_RETRYABLE)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False  # already current within this timestamp
            raise
        # ALL_OLD returns the prior attributes; empty/absent means it was created.
        return not resp.get("Attributes")
