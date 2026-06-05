"""Bearer-token authorizer tests (moto-backed SSM)."""

from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from moto import mock_aws

from authorizer import handler as auth

REGION = "us-east-1"
PARAM = "/platform-hygiene/poc/bearer-token"
TOKEN = "s3cr3t-token-value"


def _context() -> Any:
    return SimpleNamespace(
        function_name="authorizer",
        memory_limit_in_mb=128,
        invoked_function_arn="arn:aws:lambda:us-east-1:111:function:authorizer",
        aws_request_id="req-1",
    )


@pytest.fixture(autouse=True)
def ssm(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("BEARER_TOKEN_PARAMETER", PARAM)
    auth._expected_token.cache_clear()
    with mock_aws():
        boto3.client("ssm", region_name=REGION).put_parameter(
            Name=PARAM, Value=TOKEN, Type="SecureString"
        )
        yield
    auth._expected_token.cache_clear()


def _event(authorization: str | None) -> dict[str, Any]:
    headers = {"authorization": authorization} if authorization is not None else {}
    return {"headers": headers}


def test_valid_bearer_authorized() -> None:
    assert auth.handler(_event(f"Bearer {TOKEN}"), _context()) == {"isAuthorized": True}


def test_invalid_bearer_rejected() -> None:
    assert auth.handler(_event("Bearer wrong"), _context()) == {"isAuthorized": False}


def test_missing_header_rejected() -> None:
    assert auth.handler(_event(None), _context()) == {"isAuthorized": False}


def test_malformed_header_rejected() -> None:
    assert auth.handler(_event(TOKEN), _context()) == {"isAuthorized": False}  # no "Bearer "


def test_uppercase_header_name_tolerated() -> None:
    assert auth.handler({"headers": {"Authorization": f"Bearer {TOKEN}"}}, _context()) == {
        "isAuthorized": True
    }
