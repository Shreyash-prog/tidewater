"""FixturesStack — demo-only resources.

Phase 6 adds a single stable demo target for the lambda.unused_function detector:
a minimal, never-invoked Python function tagged Environment=nonprod (so the
rule's nonprod->auto override applies). Phase 7 fills this in further (~100 stub
Lambdas, ~30 IAM roles, synthetic metric history). Has no direct dependency on
CoreStack — it reads shared values via SSM lookup so it can be destroyed alone
(docs/architecture.md §9).
"""

from typing import Any

from aws_cdk import RemovalPolicy, Stack, Tags
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

# Stable name so demos/docs can reference the target directly.
UNUSED_FIXTURE_FUNCTION_NAME = "tidewater-fixture-unused-lambda"

_FIXTURE_CODE = """\
def handler(event, context):
    return {"statusCode": 200}
"""


class FixturesStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: Any) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 1-day log retention per the Free Tier guardrail (CLAUDE.md). Explicit
        # log group so we own its retention + removal policy.
        log_group = logs.LogGroup(
            self,
            "UnusedFixtureFunctionLogGroup",
            log_group_name=f"/aws/lambda/{UNUSED_FIXTURE_FUNCTION_NAME}",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        unused_fn = lambda_.Function(
            self,
            "UnusedFixtureFunction",
            function_name=UNUSED_FIXTURE_FUNCTION_NAME,
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_inline(_FIXTURE_CODE),
            log_group=log_group,
            description="Demo target for lambda.unused_function (deliberately never invoked).",
        )
        # The nonprod tag drives the rule's nonprod->auto remediation override.
        Tags.of(unused_fn).add("Environment", "nonprod")
