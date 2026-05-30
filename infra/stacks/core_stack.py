"""CoreStack — the framework's own infrastructure.

Empty in Phase 1 (repo skeleton). Phase 2 fills this in with DynamoDB tables,
S3 buckets, the EventBridge bus + Scheduler, SNS topic, API Gateway, CloudFront,
the Lambda authorizer, the bearer-token SSM parameter, and AWS Budgets — all per
docs/architecture.md §3 and §9.
"""

from typing import Any

from aws_cdk import Stack
from constructs import Construct


class CoreStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: Any) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # Resources added in Phase 2.
