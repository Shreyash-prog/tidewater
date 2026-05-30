"""API Gateway Lambda authorizer (stub).

Phase 2: allows everything. Real pre-shared bearer-token validation against SSM
Parameter Store arrives in Phase 8 (docs/architecture.md §7). HTTP API simple
authorizers return an `isAuthorized` boolean.
"""

from typing import Any

from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()


@logger.inject_lambda_context
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    # TODO(Phase 8): validate the bearer token against /platform-hygiene/poc/bearer-token.
    return {"isAuthorized": True}
