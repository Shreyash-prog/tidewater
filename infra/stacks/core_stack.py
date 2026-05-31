"""CoreStack — everything the framework needs to run (docs/architecture.md §3, §4, §9).

Phase 2 stands up the resources with empty/stub behaviour: tables, buckets,
CloudFront + a placeholder page, the EventBridge bus + Scheduler group, SNS
topics, an HTTP API with a single /health route, the bearer-token SSM parameter
(via a custom resource), AWS Budgets with a $20 stop-action, and a CloudWatch
dashboard. Detector/policy/remediator logic comes in later phases.
"""

from typing import Any, cast

from aws_cdk import (
    CfnOutput,
    CfnParameter,
    CfnResource,
    CustomResource,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_budgets as budgets
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_scheduler as scheduler
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from aws_cdk import aws_ssm as ssm
from aws_cdk import custom_resources as cr
from aws_cdk.aws_apigatewayv2 import (
    CorsHttpMethod,
    CorsPreflightOptions,
    HttpApi,
    HttpMethod,
    HttpNoneAuthorizer,
)
from aws_cdk.aws_apigatewayv2_authorizers import HttpLambdaAuthorizer, HttpLambdaResponseType
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration
from constructs import Construct

from infra.constructs.lambda_function import PythonLambda

# Buckets whose removal policy is RETAIN (the audit trail must survive teardown).
RETAIN_BUCKETS = {"audit-log", "snapshots"}

BEARER_TOKEN_PARAM = "/platform-hygiene/poc/bearer-token"
DEPLOY_VERSION_PARAM = "/platform-hygiene/poc/deploy-version"

BUDGET_NAME = "tidewater-poc-budget"
BUDGET_LIMIT_USD = 20

PLACEHOLDER_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Tidewater</title>
    <style>
      body { font-family: system-ui, sans-serif; display: flex; min-height: 100vh;
             align-items: center; justify-content: center; margin: 0; color: #0f172a; }
    </style>
  </head>
  <body>
    <main>Tidewater &mdash; Phase 2 placeholder. Dashboard ships in Phase 9.</main>
  </body>
</html>
"""


class CoreStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        notification_email: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # Where budget alerts and SNS notifications are sent (configurable via the
        # `notification_email` CDK context value — see infra/app.py).
        self._notification_email = notification_email

        deploy_version = CfnParameter(
            self,
            "DeployVersionParameter",
            type="String",
            default="poc-local-dev",
            description="Date-based deploy tag (docs/architecture.md §11).",
        )

        tables = self._dynamodb_tables()
        buckets = self._s3_buckets()
        distribution = self._cloudfront(buckets["dashboard"])
        notifications_topic, budget_topic = self._sns_topics()
        bus = self._eventbridge(notifications_topic)
        api_url = self._api(distribution, deploy_version)
        self._ssm_parameters(deploy_version)
        self._budgets(budget_topic)
        self._cloudwatch_dashboard()

        self._outputs(
            tables=tables,
            buckets=buckets,
            distribution=distribution,
            api_url=api_url,
            bus=bus,
            notifications_topic=notifications_topic,
            deploy_version=deploy_version,
        )

    # ------------------------------------------------------------------ DynamoDB
    def _dynamodb_tables(self) -> dict[str, dynamodb.Table]:
        def table(
            construct_id: str,
            pk: str,
            sk: str,
            *,
            ttl_attribute: str | None = None,
            stream: dynamodb.StreamViewType | None = None,
        ) -> dynamodb.Table:
            return dynamodb.Table(
                self,
                construct_id,
                partition_key=dynamodb.Attribute(name=pk, type=dynamodb.AttributeType.STRING),
                sort_key=dynamodb.Attribute(name=sk, type=dynamodb.AttributeType.STRING),
                billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                    point_in_time_recovery_enabled=True
                ),
                removal_policy=RemovalPolicy.DESTROY,
                time_to_live_attribute=ttl_attribute,
                stream=stream,
            )

        findings = table(
            "FindingsTable",
            "pk",  # account#region#service
            "sk",  # resource_arn#rule_id
            ttl_attribute="ttl",
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )
        findings.add_global_secondary_index(
            index_name="status-detected_at",
            partition_key=dynamodb.Attribute(name="status", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="detected_at", type=dynamodb.AttributeType.STRING),
        )

        approvals = table("ApprovalsTable", "approval_id", "metadata")
        approvals.add_global_secondary_index(
            index_name="status-requested_at",
            partition_key=dynamodb.Attribute(name="status", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="requested_at", type=dynamodb.AttributeType.STRING),
        )

        metric_history = table("MetricHistoryTable", "metric_name", "timestamp")
        forecasts = table("ForecastsTable", "metric_name", "model_run")
        rules_meta = table("RulesMetaTable", "rule_id", "metadata")

        return {
            "findings": findings,
            "approvals": approvals,
            "metric_history": metric_history,
            "forecasts": forecasts,
            "rules_meta": rules_meta,
        }

    # ------------------------------------------------------------------ S3
    def _s3_buckets(self) -> dict[str, s3.Bucket]:
        def bucket(
            construct_id: str,
            *,
            retain: bool,
            versioned: bool = True,
            lifecycle_rules: list[s3.LifecycleRule] | None = None,
        ) -> s3.Bucket:
            return s3.Bucket(
                self,
                construct_id,
                # Never pass bucket_name — let CDK add a stack hash suffix to dodge
                # global-name collisions (build-plan Phase 2).
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                encryption=s3.BucketEncryption.S3_MANAGED,
                enforce_ssl=True,
                versioned=versioned,
                removal_policy=RemovalPolicy.RETAIN if retain else RemovalPolicy.DESTROY,
                auto_delete_objects=not retain,
                lifecycle_rules=lifecycle_rules,
            )

        audit_log = bucket(
            "AuditLogBucket",
            retain=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(30),
                        )
                    ]
                )
            ],
        )
        # Guard the audit trail against accidental bucket deletion.
        audit_log.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyBucketDeletion",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:DeleteBucket"],
                resources=[audit_log.bucket_arn],
            )
        )

        snapshots = bucket(
            "SnapshotsBucket",
            retain=True,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(30))],
        )
        rules_yaml = bucket("RulesYamlBucket", retain=False, versioned=True)
        dashboard = bucket("DashboardSpaBucket", retain=False, versioned=False)

        return {
            "audit-log": audit_log,
            "snapshots": snapshots,
            "rules-yaml": rules_yaml,
            "dashboard": dashboard,
        }

    # ------------------------------------------------------------------ CloudFront
    def _cloudfront(self, dashboard_bucket: s3.Bucket) -> cloudfront.Distribution:
        security_headers = cloudfront.ResponseHeadersPolicy(
            self,
            "SecurityHeadersPolicy",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.days(365),
                    include_subdomains=True,
                    override=True,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=True),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=True
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
                    override=True,
                ),
                xss_protection=cloudfront.ResponseHeadersXSSProtection(
                    protection=True, mode_block=True, override=True
                ),
            ),
        )

        distribution = cloudfront.Distribution(
            self,
            "DashboardDistribution",
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            http_version=cloudfront.HttpVersion.HTTP2_AND_3,
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(dashboard_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=security_headers,
            ),
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403, response_http_status=200, response_page_path="/index.html"
                ),
                cloudfront.ErrorResponse(
                    http_status=404, response_http_status=200, response_page_path="/index.html"
                ),
            ],
        )

        s3deploy.BucketDeployment(
            self,
            "DashboardPlaceholder",
            sources=[s3deploy.Source.data("index.html", PLACEHOLDER_HTML)],
            destination_bucket=dashboard_bucket,
            distribution=distribution,
            distribution_paths=["/*"],
        )

        return distribution

    # ------------------------------------------------------------------ SNS
    def _sns_topics(self) -> tuple[sns.Topic, sns.Topic]:
        notifications = sns.Topic(self, "NotificationsTopic", topic_name="tidewater-notifications")
        budget_alerts = sns.Topic(self, "BudgetAlertsTopic", topic_name="tidewater-budget-alerts")
        budget_alerts.add_subscription(subscriptions.EmailSubscription(self._notification_email))
        # Allow AWS Budgets to publish budget alerts to the topic.
        budget_alerts.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowBudgetsPublish",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("budgets.amazonaws.com")],
                actions=["sns:Publish"],
                resources=[budget_alerts.topic_arn],
            )
        )
        return notifications, budget_alerts

    # ------------------------------------------------------------------ EventBridge
    def _eventbridge(self, notifications_topic: sns.Topic) -> events.EventBus:
        bus = events.EventBus(self, "EventBus", event_bus_name="tidewater-events")

        scheduler.CfnScheduleGroup(self, "DetectorScheduleGroup", name="tidewater-detectors")

        rule = events.Rule(
            self,
            "TidewaterEventsToSns",
            event_bus=bus,
            description="Fan out all tidewater.* events to the notifications topic.",
            # Placeholder pattern; overridden below with a source-prefix match
            # (CDK's L2 EventPattern doesn't expose prefix matching on scalar fields).
            event_pattern=events.EventPattern(source=["tidewater.placeholder"]),
        )
        rule.add_target(targets.SnsTopic(notifications_topic))
        cfn_rule = cast(CfnResource, rule.node.default_child)
        cfn_rule.add_property_override("EventPattern", {"source": [{"prefix": "tidewater."}]})

        return bus

    # ------------------------------------------------------------------ API + Lambdas
    def _api(self, distribution: cloudfront.Distribution, deploy_version: CfnParameter) -> str:
        authorizer_fn = PythonLambda(
            self,
            "Authorizer",
            entry="lambdas/authorizer",
            description="Stub bearer-token authorizer (real validation in Phase 8).",
        )
        api_fn = PythonLambda(
            self,
            "Api",
            entry="lambdas/api",
            environment={"DEPLOY_VERSION": deploy_version.value_as_string},
            description="Dashboard API (only /health in Phase 2).",
        )

        authorizer = HttpLambdaAuthorizer(
            "DefaultAuthorizer",
            authorizer_fn.function,
            response_types=[HttpLambdaResponseType.SIMPLE],
        )

        http_api = HttpApi(
            self,
            "HttpApi",
            api_name="tidewater-api",
            default_authorizer=authorizer,
            cors_preflight=CorsPreflightOptions(
                allow_origins=[f"https://{distribution.distribution_domain_name}"],
                allow_methods=[CorsHttpMethod.GET, CorsHttpMethod.OPTIONS],
                allow_headers=["authorization", "content-type"],
            ),
        )

        # /health is public — it bypasses the default authorizer.
        http_api.add_routes(
            path="/health",
            methods=[HttpMethod.GET],
            integration=HttpLambdaIntegration("HealthIntegration", api_fn.function),
            authorizer=HttpNoneAuthorizer(),
        )

        return http_api.api_endpoint

    # ------------------------------------------------------------------ SSM
    def _ssm_parameters(self, deploy_version: CfnParameter) -> None:
        ssm.StringParameter(
            self,
            "DeployVersionParam",
            parameter_name=DEPLOY_VERSION_PARAM,
            string_value=deploy_version.value_as_string,
        )

        bearer_provider_fn = PythonLambda(
            self,
            "BearerTokenProvider",
            entry="lambdas/custom_resources/bearer_token",
            description="Generates the dashboard bearer token at deploy time.",
        )
        bearer_param_arn = self.format_arn(
            service="ssm",
            resource="parameter",
            resource_name=BEARER_TOKEN_PARAM.lstrip("/"),
        )
        bearer_provider_fn.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"],
                resources=[bearer_param_arn],
            )
        )
        # SecureString put/get needs the default SSM KMS key.
        bearer_provider_fn.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
                resources=["*"],
                conditions={"StringEquals": {"kms:ViaService": f"ssm.{self.region}.amazonaws.com"}},
            )
        )

        provider = cr.Provider(
            self, "BearerTokenCrProvider", on_event_handler=bearer_provider_fn.function
        )
        CustomResource(
            self,
            "BearerToken",
            service_token=provider.service_token,
            resource_type="Custom::BearerToken",
            properties={
                "ParameterName": BEARER_TOKEN_PARAM,
                "ParameterType": "SecureString",
            },
        )

    # ------------------------------------------------------------------ Budgets
    def _budgets(self, budget_topic: sns.Topic) -> None:
        deny_all = iam.ManagedPolicy(
            self,
            "BudgetDenyAllPolicy",
            managed_policy_name="tidewater-budget-deny-all",
            description="Attached by the budget stop-action to halt scheduled detectors.",
            statements=[
                iam.PolicyStatement(effect=iam.Effect.DENY, actions=["*"], resources=["*"])
            ],
        )

        # Stub target role the EventBridge Scheduler will use (Phase 3 wires schedules).
        scheduler_role = iam.Role(
            self,
            "DetectorSchedulerRole",
            role_name="tidewater-detector-scheduler",
            assumed_by=iam.ServicePrincipal("scheduler.amazonaws.com"),
            description="EventBridge Scheduler execution role for detectors (Phase 3).",
        )

        # Role AWS Budgets assumes to perform the IAM action.
        budget_action_role = iam.Role(
            self,
            "BudgetActionRole",
            assumed_by=iam.ServicePrincipal("budgets.amazonaws.com"),
            description="Lets AWS Budgets attach the deny-all policy at 100% spend.",
            inline_policies={
                "AttachDenyAll": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
                            resources=[scheduler_role.role_arn],
                        ),
                        iam.PolicyStatement(
                            actions=["iam:GetPolicy", "iam:ListPolicyVersions"],
                            resources=[deny_all.managed_policy_arn],
                        ),
                    ]
                )
            },
        )

        def subscribers() -> list[budgets.CfnBudget.SubscriberProperty]:
            return [
                budgets.CfnBudget.SubscriberProperty(
                    subscription_type="EMAIL", address=self._notification_email
                ),
                budgets.CfnBudget.SubscriberProperty(
                    subscription_type="SNS", address=budget_topic.topic_arn
                ),
            ]

        def notification(threshold: int) -> budgets.CfnBudget.NotificationWithSubscribersProperty:
            return budgets.CfnBudget.NotificationWithSubscribersProperty(
                notification=budgets.CfnBudget.NotificationProperty(
                    notification_type="ACTUAL",
                    comparison_operator="GREATER_THAN",
                    threshold=threshold,
                    threshold_type="PERCENTAGE",
                ),
                subscribers=subscribers(),
            )

        budget = budgets.CfnBudget(
            self,
            "PocBudget",
            budget=budgets.CfnBudget.BudgetDataProperty(
                budget_name=BUDGET_NAME,
                budget_type="COST",
                time_unit="MONTHLY",
                budget_limit=budgets.CfnBudget.SpendProperty(amount=BUDGET_LIMIT_USD, unit="USD"),
            ),
            notifications_with_subscribers=[notification(50), notification(90)],
        )

        action = budgets.CfnBudgetsAction(
            self,
            "BudgetStopAction",
            budget_name=BUDGET_NAME,
            action_type="APPLY_IAM_POLICY",
            action_threshold=budgets.CfnBudgetsAction.ActionThresholdProperty(
                value=100, type="PERCENTAGE"
            ),
            notification_type="ACTUAL",
            execution_role_arn=budget_action_role.role_arn,
            approval_model="AUTOMATIC",
            definition=budgets.CfnBudgetsAction.DefinitionProperty(
                iam_action_definition=budgets.CfnBudgetsAction.IamActionDefinitionProperty(
                    policy_arn=deny_all.managed_policy_arn,
                    roles=[scheduler_role.role_name],
                )
            ),
            subscribers=[
                budgets.CfnBudgetsAction.SubscriberProperty(
                    type="EMAIL", address=self._notification_email
                )
            ],
        )
        action.add_dependency(budget)

    # ------------------------------------------------------------------ CloudWatch
    def _cloudwatch_dashboard(self) -> None:
        dashboard = cloudwatch.Dashboard(
            self, "PocCloudWatchDashboard", dashboard_name="Tidewater-POC"
        )
        dashboard.add_widgets(
            cloudwatch.TextWidget(
                markdown="# Tidewater POC\nMetric widgets are added in Phase 11.",
                width=24,
                height=2,
            )
        )

    # ------------------------------------------------------------------ Outputs
    def _outputs(
        self,
        *,
        tables: dict[str, dynamodb.Table],
        buckets: dict[str, s3.Bucket],
        distribution: cloudfront.Distribution,
        api_url: str,
        bus: events.EventBus,
        notifications_topic: sns.Topic,
        deploy_version: CfnParameter,
    ) -> None:
        outputs: dict[str, str] = {
            "DashboardUrl": f"https://{distribution.distribution_domain_name}",
            "ApiUrl": api_url,
            "FindingsTableName": tables["findings"].table_name,
            "ApprovalsTableName": tables["approvals"].table_name,
            "MetricHistoryTableName": tables["metric_history"].table_name,
            "ForecastsTableName": tables["forecasts"].table_name,
            "RulesMetaTableName": tables["rules_meta"].table_name,
            "AuditLogBucketName": buckets["audit-log"].bucket_name,
            "SnapshotsBucketName": buckets["snapshots"].bucket_name,
            "RulesYamlBucketName": buckets["rules-yaml"].bucket_name,
            "EventBusName": bus.event_bus_name,
            "NotificationsTopicArn": notifications_topic.topic_arn,
            "BearerTokenParameterName": BEARER_TOKEN_PARAM,
            "DeployVersion": deploy_version.value_as_string,
        }
        for key, value in outputs.items():
            CfnOutput(self, key, value=value)
