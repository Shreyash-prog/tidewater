"""CoreStack — everything the framework needs to run (docs/architecture.md §3, §4, §9).

Phase 2 stands up the resources with empty/stub behaviour: tables, buckets,
CloudFront + a placeholder page, the EventBridge bus + Scheduler group, SNS
topics, an HTTP API with a single /health route, the bearer-token SSM parameter
(via a custom resource), AWS Budgets with a $20 stop-action, and a CloudWatch
dashboard. Detector/policy/remediator logic comes in later phases.
"""

from pathlib import Path
from typing import Any, cast

import yaml
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
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_event_sources as lambda_event_sources
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_scheduler as scheduler
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from aws_cdk import aws_sqs as sqs
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

# Directory of rule YAMLs uploaded to the rules-yaml bucket on every deploy.
INITIAL_RULES_DIR = Path(__file__).resolve().parents[1] / "initial_rules"

# SSM Automation runbooks (repo root / runbooks).
RUNBOOKS_DIR = Path(__file__).resolve().parents[2] / "runbooks"
DELETE_IAM_ROLE_DOC_NAME = "TidewaterDeleteIamRole"
# Phase 5 runbooks: SSM document name -> runbook YAML file.
# NOTE: CloudFormation cannot update a custom-named AWS::SSM::Document whose body
# changes (it would require replacement of a named resource, which CFN refuses).
# Bumping the version suffix (e.g. V2 -> V3) when a runbook's logic changes makes
# CFN treat it as a new document. See CLAUDE.md "SSM Document maintenance".
PHASE5_DOCUMENTS = {
    "TidewaterDeleteIamAccessKey": "delete_iam_access_key.yml",
    "TidewaterRemoveTrustPrincipalV2": "remove_trust_principal.yml",
    "TidewaterDeleteUnusedPolicy": "delete_unused_policy.yml",
    "TidewaterDetachUnusedPolicy": "detach_unused_policy.yml",
}
ALL_DOCUMENT_NAMES = [DELETE_IAM_ROLE_DOC_NAME, *PHASE5_DOCUMENTS]

# rule_id -> (rules-yaml S3 key) for the rules_meta seed rows.
PHASE5_RULES = [
    "iam.wildcard_policy",
    "iam.stale_access_key",
    "iam.orphaned_trust",
    "iam.unused_policy",
    "iam.policy_quota",
]

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
        iam_detector_name = self._iam_detector(
            rules_bucket=buckets["rules-yaml"],
            findings_table=tables["findings"],
            rules_meta_table=tables["rules_meta"],
            bus=bus,
        )
        policy_engine_name, remediator_name = self._policy_and_remediation(
            findings_table=tables["findings"],
            approvals_table=tables["approvals"],
            rules_bucket=buckets["rules-yaml"],
            snapshots_bucket=buckets["snapshots"],
            audit_bucket=buckets["audit-log"],
            bus=bus,
        )

        self._outputs(
            tables=tables,
            buckets=buckets,
            distribution=distribution,
            api_url=api_url,
            bus=bus,
            notifications_topic=notifications_topic,
            deploy_version=deploy_version,
            iam_detector_name=iam_detector_name,
            policy_engine_name=policy_engine_name,
            remediator_name=remediator_name,
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
        # Per-resource in-flight lookup: the policy engine checks whether any other
        # finding for the same resource_arn is already in_remediation before it
        # dispatches an auto remediation, so two rules flagging one resource don't
        # remediate it concurrently. O(1) index query instead of a table scan.
        findings.add_global_secondary_index(
            index_name="ResourceArnStatusIndex",
            partition_key=dynamodb.Attribute(
                name="resource_arn", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="status", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
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

    # ------------------------------------------------------------------ IAM detector
    def _iam_detector(
        self,
        *,
        rules_bucket: s3.Bucket,
        findings_table: dynamodb.Table,
        rules_meta_table: dynamodb.Table,
        bus: events.EventBus,
    ) -> str:
        # Failed (async) invocations land here for inspection (Phase 3 is on-demand).
        dlq = sqs.Queue(
            self,
            "IamDetectorDlq",
            queue_name="iam-detector-dlq",
            retention_period=Duration.days(14),
        )

        detector = PythonLambda(
            self,
            "IamDetector",
            entry="lambdas/detectors/iam",
            handler="detectors.iam.handler.handler",
            include_shared=True,
            memory_size=512,
            timeout=Duration.minutes(5),
            dead_letter_queue=dlq,
            environment={
                "RULES_BUCKET": rules_bucket.bucket_name,
                "FINDINGS_TABLE": findings_table.table_name,
                "EVENT_BUS_NAME": bus.event_bus_name,
            },
            description="Detects idle IAM roles (iam.unused_role). On-demand in Phase 3.",
        )
        fn = detector.function

        # Read-only IAM access — never anything destructive (that's the remediator).
        fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:ListRoles",
                    "iam:GetRole",
                    "iam:GetUser",
                    "iam:ListUsers",
                    "iam:ListRoleTags",
                    "iam:ListUserTags",
                    "iam:ListPolicyTags",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListRolePolicies",
                    "iam:GetRolePolicy",
                    "iam:ListAccessKeys",
                    "iam:GetAccessKeyLastUsed",
                    "iam:ListPolicies",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListEntitiesForPolicy",
                    "iam:GenerateServiceLastAccessedDetails",
                    "iam:GetServiceLastAccessedDetails",
                ],
                resources=["*"],
            )
        )
        rules_bucket.grant_read(fn)
        findings_table.grant(
            fn, "dynamodb:BatchWriteItem", "dynamodb:UpdateItem", "dynamodb:GetItem"
        )
        bus.grant_put_events_to(fn)

        # Upload the rule YAML(s) to the bucket on every deploy.
        s3deploy.BucketDeployment(
            self,
            "RulesDeployment",
            sources=[s3deploy.Source.asset(str(INITIAL_RULES_DIR))],
            destination_bucket=rules_bucket,
            destination_key_prefix="rules",
        )

        # Seed the rules_meta row for iam.unused_role at deploy time.
        seed_fn = PythonLambda(
            self,
            "RulesMetaSeed",
            entry="lambdas/custom_resources/rules_meta_seed",
            description="Seeds rules_meta rows at deploy time.",
        )
        rules_meta_table.grant(seed_fn.function, "dynamodb:PutItem", "dynamodb:DeleteItem")
        seed_provider = cr.Provider(
            self, "RulesMetaSeedProvider", on_event_handler=seed_fn.function
        )
        CustomResource(
            self,
            "IamUnusedRoleRulesMeta",
            service_token=seed_provider.service_token,
            resource_type="Custom::RulesMetaSeed",
            properties={
                "TableName": rules_meta_table.table_name,
                "RuleId": "iam.unused_role",
                "Enabled": "true",
                "Version": "1",
                "S3Key": "rules/iam.unused_role.yaml",
                "Schedule": "on-demand",
            },
        )
        # Phase 5: seed one rules_meta row per new rule (same Custom Resource).
        # These are created in series via explicit CloudFormation DependsOn edges:
        # CFN otherwise invokes the single backing provider Lambda once per rule
        # concurrently, tripping AWS Lambda's control-plane Invoke rate limit
        # (TooManyRequestsException: Rate Exceeded). Serializing keeps at most one
        # provider invocation in flight at a time. This is orchestration-level
        # throttling, not a Lambda-side retry concern.
        rules_meta_resources: list[CustomResource] = []
        for rule_id in PHASE5_RULES:
            construct_id = "RulesMeta" + "".join(part.title() for part in rule_id.split("."))
            resource = CustomResource(
                self,
                construct_id,
                service_token=seed_provider.service_token,
                resource_type="Custom::RulesMetaSeed",
                properties={
                    "TableName": rules_meta_table.table_name,
                    "RuleId": rule_id,
                    "Enabled": "true",
                    "Version": "1",
                    "S3Key": f"rules/{rule_id}.yaml",
                    "Schedule": "on-demand",
                },
            )
            if rules_meta_resources:
                # Each depends on the previous so CFN processes them one at a time.
                resource.node.add_dependency(rules_meta_resources[-1])
            rules_meta_resources.append(resource)

        return fn.function_name

    # ----------------------------------------------------- Policy engine + remediator
    def _policy_and_remediation(
        self,
        *,
        findings_table: dynamodb.Table,
        approvals_table: dynamodb.Table,
        rules_bucket: s3.Bucket,
        snapshots_bucket: s3.Bucket,
        audit_bucket: s3.Bucket,
        bus: events.EventBus,
    ) -> tuple[str, str]:
        # --- SSM Automation document + the role it assumes when it runs. ---
        ssm_role = iam.Role(
            self,
            "SsmExecutionRole",
            role_name="TidewaterSsmExecutionRole",
            assumed_by=iam.ServicePrincipal("ssm.amazonaws.com"),
            description="Assumed by the IAM remediation SSM runbooks (only their needed perms).",
        )
        ssm_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:GetRole",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListRolePolicies",
                    "iam:GetRolePolicy",
                    "iam:ListInstanceProfilesForRole",
                    "iam:DetachRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:RemoveRoleFromInstanceProfile",
                    "iam:DeleteRole",
                    # Phase 5 runbooks (role-scoped mutations + reads).
                    "iam:UpdateAssumeRolePolicy",
                ],
                resources=[
                    f"arn:aws:iam::{self.account}:role/*",
                    f"arn:aws:iam::{self.account}:instance-profile/*",
                ],
            )
        )
        # Phase 5: user-scoped reads + access-key deactivation (never DeleteAccessKey).
        ssm_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:GetUser",
                    "iam:GetAccessKeyLastUsed",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListUserPolicies",
                    "iam:UpdateAccessKey",
                ],
                resources=[f"arn:aws:iam::{self.account}:user/*"],
            )
        )
        # Phase 5: customer-managed policy reads + deletion (delete_unused_policy).
        ssm_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:ListPolicyVersions",
                    "iam:GetPolicyVersion",
                    "iam:ListEntitiesForPolicy",
                    "iam:DeletePolicyVersion",
                    "iam:DeletePolicy",
                ],
                resources=[f"arn:aws:iam::{self.account}:policy/*"],
            )
        )
        # Phase 5: service-last-accessed analysis for least-recently-used detach.
        # GetServiceLastAccessedDetails keys off a JobId, so it is not resource-scopable.
        ssm_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:GenerateServiceLastAccessedDetails",
                    "iam:GetServiceLastAccessedDetails",
                ],
                resources=["*"],
            )
        )
        snapshots_bucket.grant_put(ssm_role)
        audit_bucket.grant_put(ssm_role)
        findings_table.grant(ssm_role, "dynamodb:UpdateItem")
        bus.grant_put_events_to(ssm_role)
        ssm_role.add_to_policy(
            iam.PolicyStatement(actions=["ssm:GetAutomationExecution"], resources=["*"])
        )

        runbook_content = yaml.safe_load((RUNBOOKS_DIR / "delete_iam_role.yml").read_text())
        ssm.CfnDocument(
            self,
            "DeleteIamRoleDocument",
            name=DELETE_IAM_ROLE_DOC_NAME,
            document_type="Automation",
            content=runbook_content,
        )
        # Phase 5 remediation documents (one CfnDocument per runbook).
        for doc_name, filename in PHASE5_DOCUMENTS.items():
            ssm.CfnDocument(
                self,
                doc_name + "Document",
                name=doc_name,
                document_type="Automation",
                content=yaml.safe_load((RUNBOOKS_DIR / filename).read_text()),
            )

        # ssm:StartAutomationExecution is authorized against the document/ ARN today;
        # the automation-definition/ format is being deprecated (kept for backward
        # compat per AWS migration guidance), and automation-execution/ is needed
        # once a run starts. This mirrors AWS's own
        # AWS-SSM-DiagnosisAutomation-AdministrationRolePolicy.
        start_automation_resources = [
            f"arn:aws:ssm:{self.region}:{self.account}:automation-execution/*",
        ]
        for doc_name in ALL_DOCUMENT_NAMES:
            start_automation_resources += [
                f"arn:aws:ssm:{self.region}:{self.account}:document/{doc_name}",
                f"arn:aws:ssm:{self.region}:{self.account}:automation-definition/{doc_name}:*",
            ]

        # --- Remediator Lambda (starts SSM Automation; never deletes directly). ---
        remediator_dlq = sqs.Queue(
            self, "RemediatorDlq", queue_name="remediator-dlq", retention_period=Duration.days(14)
        )
        remediator = PythonLambda(
            self,
            "Remediator",
            entry="lambdas/remediator",
            handler="remediator.handler.handler",
            include_shared=True,
            memory_size=256,
            timeout=Duration.minutes(1),
            dead_letter_queue=remediator_dlq,
            environment={
                "FINDINGS_TABLE": findings_table.table_name,
                "SNAPSHOT_BUCKET": snapshots_bucket.bucket_name,
                "AUDIT_BUCKET": audit_bucket.bucket_name,
                "EVENT_BUS_NAME": bus.event_bus_name,
                "SSM_DOCUMENT_NAME": DELETE_IAM_ROLE_DOC_NAME,
                "SSM_EXECUTION_ROLE_ARN": ssm_role.role_arn,
            },
            description="Dispatches SSM Automation remediations (auto or approved).",
        )
        rfn = remediator.function
        findings_table.grant(rfn, "dynamodb:GetItem", "dynamodb:UpdateItem")
        audit_bucket.grant_put(rfn)
        bus.grant_put_events_to(rfn)
        rfn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:StartAutomationExecution"],
                resources=start_automation_resources,
            )
        )
        # Poll execution status (execution IDs aren't known until runtime).
        rfn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:GetAutomationExecution"],
                resources=[f"arn:aws:ssm:{self.region}:{self.account}:automation-execution/*"],
            )
        )
        rfn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["iam:PassRole"],
                resources=[ssm_role.role_arn],
                conditions={"StringEquals": {"iam:PassedToService": "ssm.amazonaws.com"}},
            )
        )

        # --- Policy engine Lambda (DynamoDB Streams consumer). ---
        policy_dlq = sqs.Queue(
            self,
            "PolicyEngineDlq",
            queue_name="policy-engine-dlq",
            retention_period=Duration.days(14),
        )
        policy_engine = PythonLambda(
            self,
            "PolicyEngine",
            entry="lambdas/policy_engine",
            handler="policy_engine.handler.handler",
            include_shared=True,
            memory_size=512,
            timeout=Duration.minutes(2),
            dead_letter_queue=policy_dlq,
            environment={
                "FINDINGS_TABLE": findings_table.table_name,
                "APPROVALS_TABLE": approvals_table.table_name,
                "RULES_BUCKET": rules_bucket.bucket_name,
                "REMEDIATOR_FUNCTION_NAME": rfn.function_name,
                "EVENT_BUS_NAME": bus.event_bus_name,
                "AUDIT_BUCKET": audit_bucket.bucket_name,
            },
            description="Decides auto/prompt/dry_run/skip per finding (DynamoDB Streams).",
        )
        pfn = policy_engine.function
        # Query is needed for the per-resource in-flight conflict check against the
        # ResourceArnStatusIndex GSI; Table.grant also covers the table's /index/*
        # ARNs, so the GSI is included.
        findings_table.grant(pfn, "dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query")
        # GetItem is needed for the idempotency check in _ensure_approval.
        approvals_table.grant(pfn, "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem")
        rules_bucket.grant_read(pfn)
        audit_bucket.grant_put(pfn)
        bus.grant_put_events_to(pfn)
        rfn.grant_invoke(pfn)  # explicit function ARN, no wildcard

        # Grant the four stream-read permissions explicitly (ListStreams +
        # DescribeStream + GetRecords + GetShardIterator). DynamoEventSource also
        # grants these, but binding them to the role independently of the event
        # source means a refactor of the mapping can't silently drop them — the
        # poller fails closed-and-loud rather than never delivering records.
        findings_table.grant_stream_read(pfn)

        pfn.add_event_source(
            lambda_event_sources.DynamoEventSource(
                findings_table,
                starting_position=lambda_.StartingPosition.LATEST,
                batch_size=10,
                max_batching_window=Duration.seconds(5),
                retry_attempts=2,
                report_batch_item_failures=True,
                on_failure=lambda_event_sources.SqsDlq(policy_dlq),
            )
        )

        return pfn.function_name, rfn.function_name

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
        iam_detector_name: str,
        policy_engine_name: str,
        remediator_name: str,
    ) -> None:
        outputs: dict[str, str] = {
            "IamDetectorLambdaName": iam_detector_name,
            "PolicyEngineLambdaName": policy_engine_name,
            "RemediatorLambdaName": remediator_name,
            "SsmDocumentName": DELETE_IAM_ROLE_DOC_NAME,
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
