"""Read-only rules routes — list and detail (rule YAML from the rules-yaml bucket)."""

import os
from typing import Any

import boto3
import yaml
from aws_lambda_powertools import Logger

logger = Logger(child=True)

_PREFIX = "rules/"


def _s3() -> Any:
    return boto3.client("s3")


def _bucket() -> str:
    return os.environ["RULES_BUCKET"]


def list_rules(event: dict[str, Any]) -> dict[str, Any]:
    """GET /rules — rule_ids with high-level metadata."""
    s3 = _s3()
    bucket = _bucket()
    items: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": _PREFIX}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".yaml"):
                continue
            try:
                body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
                rule = yaml.safe_load(body) or {}
            except Exception:
                logger.warning("failed to parse rule", extra={"s3_key": key})
                continue
            policy = rule.get("policy", {}) or {}
            items.append(
                {
                    "rule_id": rule.get("rule"),
                    "enabled": rule.get("enabled", True),
                    "schedule": rule.get("schedule"),
                    "policy_default": policy.get("default"),
                    "has_overrides": len(policy.get("overrides", []) or []) > 0,
                    "forecast_enabled": (rule.get("forecast", {}) or {}).get("enabled", False),
                }
            )
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
    items.sort(key=lambda r: str(r.get("rule_id")))
    return {"items": items, "count": len(items)}


def get_rule(event: dict[str, Any]) -> dict[str, Any]:
    """GET /rules/{rule_id} — the full rule YAML as a parsed dict."""
    rule_id = (event.get("pathParameters") or {})["rule_id"]
    key = f"{_PREFIX}{rule_id}.yaml"
    s3 = _s3()
    try:
        body = s3.get_object(Bucket=_bucket(), Key=key)["Body"].read().decode()
    except s3.exceptions.NoSuchKey:
        return {"error": "rule not found"}
    return yaml.safe_load(body) or {}
