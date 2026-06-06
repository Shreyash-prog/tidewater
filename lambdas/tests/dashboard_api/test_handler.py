"""Router/dispatch tests for the dashboard API handler."""

import json
from types import SimpleNamespace
from typing import Any

import pytest

from dashboard_api import handler as h


def _context() -> Any:
    return SimpleNamespace(
        function_name="dashboard-api",
        memory_limit_in_mb=512,
        invoked_function_arn="arn:aws:lambda:us-east-1:111:function:dashboard-api",
        aws_request_id="req-1",
    )


def _event(route_key: str, *, method: str = "GET", **extra: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "routeKey": route_key,
        "requestContext": {"http": {"method": method}},
    }
    event.update(extra)
    return event


def test_dispatches_to_route(aws: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    aws.put_finding(aws.findings)
    resp = h.handler(_event("GET /findings"), _context())
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["count"] == 1


def test_cors_headers_present(aws: Any) -> None:
    resp = h.handler(_event("GET /rules"), _context())
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
    assert "Authorization" in resp["headers"]["Access-Control-Allow-Headers"]
    assert resp["headers"]["Content-Type"] == "application/json"


def test_options_preflight_returns_204() -> None:
    resp = h.handler(_event("OPTIONS /findings", method="OPTIONS"), _context())
    assert resp["statusCode"] == 204


def test_unknown_route_returns_404() -> None:
    resp = h.handler(_event("GET /nope"), _context())
    assert resp["statusCode"] == 404
    assert json.loads(resp["body"])["error"] == "route not found"


def test_missing_path_param_returns_400(aws: Any) -> None:
    # GET /findings/{pk}/{sk} with no pathParameters → KeyError → 400.
    resp = h.handler(_event("GET /findings/{pk}/{sk}"), _context())
    assert resp["statusCode"] == 400
    assert "missing parameter" in json.loads(resp["body"])["error"]


def test_handler_error_returns_500(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_event: dict[str, Any]) -> Any:
        raise RuntimeError("kaboom")

    monkeypatch.setitem(h.ROUTES, "GET /rules", _boom)
    resp = h.handler(_event("GET /rules"), _context())
    assert resp["statusCode"] == 500
    assert json.loads(resp["body"])["error"] == "internal server error"
