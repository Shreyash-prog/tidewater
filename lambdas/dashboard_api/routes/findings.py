"""Read-only findings routes. All endpoints return JSON suitable for the SPA.

POC scale: list uses a DynamoDB Scan with filter expressions (a few hundred
findings at most). At larger scale these would move to GSI queries.
"""

import base64
import json
import os
from decimal import Decimal
from typing import Any
from urllib.parse import unquote

import boto3
from aws_lambda_powertools import Logger

logger = Logger(child=True)

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50
_SNAPSHOT_TTL_SECONDS = 300
_AUDIT_MAX_KEYS = 1000


def _table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])


def _s3() -> Any:
    return boto3.client("s3")


def _convert(value: Any) -> Any:
    """Make a DynamoDB item JSON-serializable (Decimal -> int/float)."""
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, dict):
        return {k: _convert(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_convert(v) for v in value]
    return value


def _path(event: dict[str, Any]) -> dict[str, str]:
    return event.get("pathParameters") or {}


def list_findings(event: dict[str, Any]) -> dict[str, Any]:
    """GET /findings?service=&severity=&status=&rule_id=&limit=&next_token="""
    params = event.get("queryStringParameters") or {}
    limit = min(int(params.get("limit") or _DEFAULT_LIMIT), _MAX_LIMIT)

    filter_parts: list[str] = []
    expr_values: dict[str, Any] = {}
    expr_names: dict[str, str] = {}
    # (attribute, query-param, needs-#alias-because-reserved-word)
    for attr, key, reserved in (
        ("status", "status", True),
        ("severity", "severity", False),
        ("service", "service", False),
        ("rule_id", "rule_id", False),
    ):
        value = params.get(key)
        if not value:
            continue
        name = f"#{attr}" if reserved else attr
        if reserved:
            expr_names[name] = attr
        filter_parts.append(f"{name} = :{attr}")
        expr_values[f":{attr}"] = value

    scan_kwargs: dict[str, Any] = {"Limit": limit}
    if filter_parts:
        scan_kwargs["FilterExpression"] = " AND ".join(filter_parts)
        scan_kwargs["ExpressionAttributeValues"] = expr_values
        if expr_names:
            scan_kwargs["ExpressionAttributeNames"] = expr_names
    if next_token := params.get("next_token"):
        scan_kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(next_token))

    resp = _table().scan(**scan_kwargs)
    result: dict[str, Any] = {
        "items": [_convert(item) for item in resp.get("Items", [])],
        "count": resp.get("Count", 0),
    }
    if "LastEvaluatedKey" in resp:
        result["next_token"] = base64.b64encode(
            json.dumps(resp["LastEvaluatedKey"], default=str).encode()
        ).decode()
    return result


def get_finding(event: dict[str, Any]) -> dict[str, Any]:
    """GET /findings/{pk}/{sk}"""
    path = _path(event)
    pk = unquote(path["pk"])
    sk = unquote(path["sk"])
    resp = _table().get_item(Key={"pk": pk, "sk": sk})
    if "Item" not in resp:
        return {"error": "finding not found"}
    return _convert(resp["Item"])


def get_finding_audit(event: dict[str, Any]) -> dict[str, Any]:
    """GET /findings/{pk}/{sk}/audit — audit-log entries for this finding (from S3).

    Audit records are JSON Lines objects under audit/. We list and filter by
    finding identity in the body (POC simplicity over per-finding indexing).
    """
    path = _path(event)
    pk = unquote(path["pk"])
    sk = unquote(path["sk"])
    bucket = os.environ["AUDIT_LOG_BUCKET"]
    s3 = _s3()
    relevant: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": "audit/", "MaxKeys": _AUDIT_MAX_KEYS}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("finding_pk") == pk and entry.get("finding_sk") == sk:
                    relevant.append(entry)
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
    relevant.sort(key=lambda e: str(e.get("timestamp", "")))
    return {"items": relevant, "count": len(relevant)}


def get_finding_snapshot(event: dict[str, Any]) -> dict[str, Any]:
    """GET /findings/{pk}/{sk}/snapshot — a short-lived presigned S3 URL."""
    path = _path(event)
    pk = unquote(path["pk"])
    sk = unquote(path["sk"])
    item = _table().get_item(Key={"pk": pk, "sk": sk}).get("Item", {})
    snapshot_key = item.get("snapshot_s3_key")
    if not snapshot_key:
        return {"error": "no snapshot for this finding"}
    url = _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": os.environ["SNAPSHOTS_BUCKET"], "Key": snapshot_key},
        ExpiresIn=_SNAPSHOT_TTL_SECONDS,
    )
    return {"url": url, "expires_in": _SNAPSHOT_TTL_SECONDS}
