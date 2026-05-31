"""Load rule YAMLs from the rules-yaml S3 bucket into validated Rule models.

Layout: `rules/{rule_id}.yaml` (e.g. `rules/iam.unused_role.yaml`). Results are
cached per service for 5 minutes for performance only — on an S3 error the loader
raises (after bounded retries) rather than serving stale rules, so the detector
fails closed (emits zero findings) instead of acting on outdated config.
"""

import os
import time
from dataclasses import dataclass
from functools import partial
from typing import Any

import boto3
import yaml
from aws_lambda_powertools import Logger
from pydantic import ValidationError

from shared.aws_retry import with_backoff
from shared.models import Rule

logger = Logger(child=True)

CACHE_TTL_SECONDS = 300
_RULES_PREFIX = "rules/"

# S3 transient errors worth retrying.
_S3_RETRYABLE = frozenset(
    {"InternalError", "ServiceUnavailable", "SlowDown", "RequestTimeout", "Throttling"}
)


@dataclass
class _CacheEntry:
    expires_at: float
    rules: list[Rule]


_cache: dict[str, _CacheEntry] = {}


def clear_cache() -> None:
    """Drop the in-process cache (used by tests)."""
    _cache.clear()


def _s3() -> Any:
    return boto3.client("s3")


def _rules_bucket() -> str:
    bucket = os.environ.get("RULES_BUCKET")
    if not bucket:
        raise RuntimeError("RULES_BUCKET environment variable is not set")
    return bucket


def _to_rule(raw: dict[str, Any]) -> Rule:
    """Map the on-disk YAML shape onto the aliased Rule model fields."""
    data = dict(raw)
    policy = data.pop("policy", None)
    if isinstance(policy, dict) and "default" in policy:
        data["policy.default"] = policy["default"]
    notifications = data.pop("notifications", None)
    if isinstance(notifications, dict) and "channels" in notifications:
        data["notifications_channels"] = notifications["channels"]
    return Rule.model_validate(data)


def _list_rule_keys(bucket: str, service: str) -> list[str]:
    client = _s3()
    keys: list[str] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": _RULES_PREFIX}
        if token:
            kwargs["ContinuationToken"] = token
        resp = with_backoff(partial(client.list_objects_v2, **kwargs), retryable=_S3_RETRYABLE)
        for obj in resp.get("Contents", []):
            key = obj["Key"]
            stem = key[len(_RULES_PREFIX) :].removesuffix(".yaml")
            if key.endswith(".yaml") and stem.startswith(f"{service}."):
                keys.append(key)
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")
    return keys


def _load_rule(bucket: str, key: str) -> Rule | None:
    """Fetch and parse one rule. Returns None on parse/validation error (logged)."""
    client = _s3()
    obj = with_backoff(partial(client.get_object, Bucket=bucket, Key=key), retryable=_S3_RETRYABLE)
    body = obj["Body"].read()
    try:
        raw = yaml.safe_load(body)
    except yaml.YAMLError:
        logger.exception("failed to parse rule YAML; skipping", extra={"s3_key": key})
        return None
    if not isinstance(raw, dict):
        logger.error("rule YAML is not a mapping; skipping", extra={"s3_key": key})
        return None
    try:
        return _to_rule(raw)
    except ValidationError:
        logger.exception("rule failed validation; skipping", extra={"s3_key": key})
        return None


def load_enabled_rules_for_service(service: str) -> list[Rule]:
    """Return enabled, validated rules for a service.

    Cached for CACHE_TTL_SECONDS. Raises on persistent S3 errors (fail closed).
    Individual malformed rules are skipped, not fatal.
    """
    cached = _cache.get(service)
    if cached and cached.expires_at > time.time():
        return cached.rules

    bucket = _rules_bucket()
    rules: list[Rule] = []
    for key in _list_rule_keys(bucket, service):
        rule = _load_rule(bucket, key)
        if rule is None:
            continue
        if not rule.enabled:
            logger.info("rule disabled; skipping", extra={"rule_id": rule.rule_id})
            continue
        rules.append(rule)

    _cache[service] = _CacheEntry(expires_at=time.time() + CACHE_TTL_SECONDS, rules=rules)
    return rules
