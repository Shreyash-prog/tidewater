"""Tests for the bearer-token custom resource handler (moto-backed SSM)."""

import importlib.util
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

_HANDLER_PATH = (
    Path(__file__).resolve().parents[1] / "custom_resources" / "bearer_token" / "handler.py"
)
_PARAM = "/platform-hygiene/poc/bearer-token"
_REGION = "us-east-1"


def _load_handler() -> Any:
    spec = importlib.util.spec_from_file_location("bearer_token_handler", _HANDLER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _aws_region(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", _REGION)


def _create_event() -> dict[str, Any]:
    return {
        "RequestType": "Create",
        "ResourceProperties": {"ParameterName": _PARAM, "ParameterType": "SecureString"},
    }


@mock_aws
def test_creates_securestring_token() -> None:
    handler = _load_handler()
    result = handler.handler(_create_event(), None)
    assert result["PhysicalResourceId"] == _PARAM

    ssm = boto3.client("ssm", region_name=_REGION)
    param = ssm.get_parameter(Name=_PARAM, WithDecryption=True)["Parameter"]
    assert param["Type"] == "SecureString"
    # secrets.token_urlsafe(32) yields ~43 URL-safe characters.
    assert len(param["Value"]) >= 40


@mock_aws
def test_is_idempotent_and_does_not_overwrite() -> None:
    handler = _load_handler()
    handler.handler(_create_event(), None)

    ssm = boto3.client("ssm", region_name=_REGION)
    original = ssm.get_parameter(Name=_PARAM, WithDecryption=True)["Parameter"]["Value"]

    # A subsequent Update must not rotate the existing token.
    handler.handler(
        {"RequestType": "Update", "ResourceProperties": {"ParameterName": _PARAM}}, None
    )
    after = ssm.get_parameter(Name=_PARAM, WithDecryption=True)["Parameter"]["Value"]
    assert after == original
