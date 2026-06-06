"""HTTP API Lambda authorizer — pre-shared bearer-token validation.

Validates the ``Authorization: Bearer <token>`` header against the token stored
in SSM Parameter Store (a SecureString generated once at deploy time). The lookup
is cached for the life of the warm container (`lru_cache`) so we don't hit SSM on
every request. HTTP API simple authorizers return an ``isAuthorized`` boolean.
"""

import os
from functools import lru_cache
from typing import Any

import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()

_BEARER_PREFIX = "Bearer "


@lru_cache(maxsize=1)
def _expected_token() -> str:
    resp = boto3.client("ssm").get_parameter(
        Name=os.environ["BEARER_TOKEN_PARAMETER"], WithDecryption=True
    )
    return str(resp["Parameter"]["Value"])


def _bearer(event: dict[str, Any]) -> str | None:
    # HTTP API lowercases header names; tolerate either casing defensively.
    headers = event.get("headers") or {}
    raw = headers.get("authorization") or headers.get("Authorization") or ""
    if not raw.startswith(_BEARER_PREFIX):
        return None
    return raw[len(_BEARER_PREFIX) :]


@logger.inject_lambda_context
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, bool]:
    token = _bearer(event)
    if not token:
        return {"isAuthorized": False}
    try:
        authorized = token == _expected_token()
    except Exception:
        logger.exception("authorizer: failed to read bearer token parameter")
        return {"isAuthorized": False}
    return {"isAuthorized": authorized}
