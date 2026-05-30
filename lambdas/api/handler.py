"""Dashboard API Lambda.

Phase 2: only `GET /health`. Real routes (findings, approvals, rules, forecasts,
audit) arrive in Phase 8. Uses the Powertools HTTP resolver, structured logging,
tracing, and metrics per docs/architecture.md §13.
"""

import os
from typing import Any

from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.event_handler import APIGatewayHttpResolver
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()
tracer = Tracer()
metrics = Metrics()
app = APIGatewayHttpResolver()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": os.environ.get("DEPLOY_VERSION", "unknown")}


@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_HTTP)
@tracer.capture_lambda_handler
@metrics.log_metrics
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    return app.resolve(event, context)
