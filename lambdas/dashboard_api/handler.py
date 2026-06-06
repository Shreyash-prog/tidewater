"""Dashboard API Lambda — internal router for the read-only dashboard endpoints.

Receives API Gateway v2 (HTTP API) events, dispatches to a route handler by
``routeKey``, and returns a JSON response. Bearer auth is enforced upstream by the
HTTP API's Lambda authorizer (lambdas/authorizer), so handlers here assume the
caller is already authenticated. Read-only: no route mutates state — approvals
(POST /approvals) arrive in Phase 9b.
"""

import json
from collections.abc import Callable
from typing import Any

from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

from dashboard_api.routes import findings as findings_routes
from dashboard_api.routes import rules as rules_routes

logger = Logger()

ROUTES: dict[str, Callable[[dict[str, Any]], Any]] = {
    "GET /findings": findings_routes.list_findings,
    "GET /findings/{pk}/{sk}": findings_routes.get_finding,
    "GET /findings/{pk}/{sk}/audit": findings_routes.get_finding_audit,
    "GET /findings/{pk}/{sk}/snapshot": findings_routes.get_finding_snapshot,
    "GET /rules": rules_routes.list_rules,
    "GET /rules/{rule_id}": rules_routes.get_rule,
}

CORS_HEADERS = {
    # CloudFront serves the SPA from a different origin than the API; the bearer
    # token (not cookies) is the auth, so a permissive CORS origin is safe here.
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
}


def _response(status: int, body: Any) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


@logger.inject_lambda_context
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    route_key = event.get("routeKey", "")
    method = (event.get("requestContext", {}).get("http", {}).get("method") or "").upper()
    if method == "OPTIONS":
        return _response(204, "")

    handler_fn = ROUTES.get(route_key)
    if handler_fn is None:
        return _response(404, {"error": "route not found", "route": route_key})
    try:
        return _response(200, handler_fn(event))
    except KeyError as exc:
        return _response(400, {"error": f"missing parameter: {exc}"})
    except Exception:
        logger.exception("dashboard_api: unexpected error", extra={"route": route_key})
        return _response(500, {"error": "internal server error"})
