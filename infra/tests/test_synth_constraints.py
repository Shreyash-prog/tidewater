"""Guardrail tests over the synthesized CoreStack template.

These encode the Phase 2 safety rules so a future change can't silently regress
them: log retention, on-demand DynamoDB, bucket removal policies, no NAT
gateways, and a SecureString bearer-token parameter.
"""

from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

from infra.constructs.lambda_function import PythonLambda
from infra.stacks.core_stack import RETAIN_BUCKETS, CoreStack

ENV = cdk.Environment(account="123456789012", region="us-east-1")
REPO_ROOT = Path(__file__).resolve().parents[2]

# Logical-id substrings that identify each bucket's intended removal policy.
_RETAIN_BUCKET_IDS = ("AuditLogBucket", "SnapshotsBucket")
_DESTROY_BUCKET_IDS = ("RulesYamlBucket", "DashboardSpaBucket")


@pytest.fixture(scope="module")
def resources() -> dict[str, dict]:
    # Skip host bundling — these assertions are about template structure only.
    app = cdk.App(context={"bundle_lambdas": False})
    stack = CoreStack(app, "TestCore", env=ENV, notification_email="test@example.com")
    return assertions.Template.from_stack(stack).to_json()["Resources"]


def _of_type(resources: dict[str, dict], type_name: str) -> dict[str, dict]:
    return {k: v for k, v in resources.items() if v["Type"] == type_name}


def test_every_log_group_has_one_day_retention(resources: dict[str, dict]) -> None:
    log_groups = _of_type(resources, "AWS::Logs::LogGroup")
    assert log_groups, "expected at least one explicit log group"
    for name, lg in log_groups.items():
        assert lg["Properties"].get("RetentionInDays") == 1, name


def test_every_dynamodb_table_is_on_demand(resources: dict[str, dict]) -> None:
    tables = _of_type(resources, "AWS::DynamoDB::Table")
    assert len(tables) == 5
    for name, table in tables.items():
        assert table["Properties"].get("BillingMode") == "PAY_PER_REQUEST", name


def test_audit_and_snapshot_buckets_are_retained(resources: dict[str, dict]) -> None:
    assert sorted(RETAIN_BUCKETS) == ["audit-log", "snapshots"]
    for name, bucket in _of_type(resources, "AWS::S3::Bucket").items():
        if name.startswith(_RETAIN_BUCKET_IDS):
            assert bucket.get("DeletionPolicy") == "Retain", name
        elif name.startswith(_DESTROY_BUCKET_IDS):
            assert bucket.get("DeletionPolicy") == "Delete", name
        else:
            raise AssertionError(f"unexpected bucket logical id: {name}")


def test_no_nat_gateways(resources: dict[str, dict]) -> None:
    assert _of_type(resources, "AWS::EC2::NatGateway") == {}


def test_bearer_token_parameter_is_securestring(resources: dict[str, dict]) -> None:
    bearer = _of_type(resources, "Custom::BearerToken")
    assert len(bearer) == 1
    (cr,) = bearer.values()
    assert cr["Properties"]["ParameterType"] == "SecureString"


def test_findings_table_has_a_stream(resources: dict[str, dict]) -> None:
    streamed = [
        name
        for name, t in _of_type(resources, "AWS::DynamoDB::Table").items()
        if "StreamSpecification" in t["Properties"]
    ]
    assert len(streamed) == 1 and streamed[0].startswith("FindingsTable")


def test_findings_table_has_resource_arn_status_index(resources: dict[str, dict]) -> None:
    # The policy engine's per-resource in-flight check queries this GSI; it must
    # exist with resource_arn (HASH) + status (RANGE).
    findings = {
        name: t
        for name, t in _of_type(resources, "AWS::DynamoDB::Table").items()
        if name.startswith("FindingsTable")
    }
    assert len(findings) == 1
    (table,) = findings.values()
    gsis = {g["IndexName"]: g for g in table["Properties"].get("GlobalSecondaryIndexes", [])}
    assert "ResourceArnStatusIndex" in gsis, f"missing GSI; have {sorted(gsis)}"
    key_schema = {
        k["KeyType"]: k["AttributeName"] for k in gsis["ResourceArnStatusIndex"]["KeySchema"]
    }
    assert key_schema == {"HASH": "resource_arn", "RANGE": "status"}


def test_lambda_detector_function_exists(resources: dict[str, dict]) -> None:
    fns = {
        name: v
        for name, v in _of_type(resources, "AWS::Lambda::Function").items()
        if name.startswith("LambdaDetectorFunction")
    }
    assert len(fns) == 1, fns
    (props,) = (v["Properties"] for v in fns.values())
    assert props["Runtime"] == "python3.12"
    assert props["MemorySize"] == 512
    assert props["Timeout"] == 300


def test_delete_unused_function_document_synthesized(resources: dict[str, dict]) -> None:
    names = {v["Properties"]["Name"] for v in _of_type(resources, "AWS::SSM::Document").values()}
    assert "TidewaterDeleteUnusedFunction" in names, names


def test_ssm_execution_role_can_delete_functions(resources: dict[str, dict]) -> None:
    # The delete_unused_function runbook runs under TidewaterSsmExecutionRole.
    roles = {
        name: v
        for name, v in _of_type(resources, "AWS::IAM::Role").items()
        if v["Properties"].get("RoleName") == "TidewaterSsmExecutionRole"
    }
    assert len(roles) == 1, roles
    (role_id,) = roles
    actions = _actions_granted_to_role(resources, role_id)
    assert "lambda:DeleteFunction" in actions, f"SSM role lacks DeleteFunction: {sorted(actions)}"
    assert "lambda:GetFunction" in actions


def test_policy_engine_can_query_findings_index(resources: dict[str, dict]) -> None:
    # The in-flight check is a Query against the GSI; without dynamodb:Query the
    # check fails closed at runtime (the exact drift the boto3<->IAM audit guards).
    functions = [
        name
        for name in _of_type(resources, "AWS::Lambda::Function")
        if name.startswith("PolicyEngineFunction")
    ]
    assert len(functions) == 1, functions
    role_id = _role_id_for_function(resources, functions[0])
    actions = _actions_granted_to_role(resources, role_id)
    assert "dynamodb:Query" in actions, f"policy engine lacks Query: {sorted(actions)}"


def _statements_with_action(resources: dict[str, dict], action: str) -> list[dict]:
    statements: list[dict] = []
    for policy in _of_type(resources, "AWS::IAM::Policy").values():
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            actions = statement.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            if action in actions:
                statements.append(statement)
    return statements


def test_start_automation_grants_document_and_execution_arns(resources: dict[str, dict]) -> None:
    # ssm:StartAutomationExecution is authorized against the document/ ARN today;
    # granting only automation-definition/ caused an AccessDenied at runtime.
    statements = _statements_with_action(resources, "ssm:StartAutomationExecution")
    assert statements, "expected a ssm:StartAutomationExecution grant"

    arns: list[str] = []
    for statement in statements:
        resource = statement.get("Resource", [])
        resource = [resource] if isinstance(resource, str) else resource
        arns.extend(arn for arn in resource if isinstance(arn, str))

    assert any(":document/" in arn for arn in arns), f"missing document/ ARN in {arns}"
    assert any(":automation-execution/" in arn for arn in arns), (
        f"missing automation-execution/ ARN in {arns}"
    )


# The four permissions an EventSourceMapping's poller needs to actually fetch
# records. Missing the read trio (with only ListStreams) is a silent failure: the
# mapping reports healthy but the Lambda is never invoked.
_STREAM_READ_ACTIONS = frozenset(
    {
        "dynamodb:ListStreams",
        "dynamodb:DescribeStream",
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
    }
)


def _role_id_for_function(resources: dict[str, dict], function_id: str) -> str:
    role = resources[function_id]["Properties"]["Role"]
    return str(role["Fn::GetAtt"][0])


def _actions_granted_to_role(resources: dict[str, dict], role_id: str) -> set[str]:
    actions: set[str] = set()
    for policy in _of_type(resources, "AWS::IAM::Policy").values():
        roles = policy["Properties"].get("Roles", [])
        if not any(isinstance(r, dict) and r.get("Ref") == role_id for r in roles):
            continue
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            action = statement.get("Action", [])
            actions.update([action] if isinstance(action, str) else action)
    return actions


def test_dynamodb_stream_consumers_have_full_stream_read(resources: dict[str, dict]) -> None:
    consumers: list[str] = []
    for esm in _of_type(resources, "AWS::Lambda::EventSourceMapping").values():
        source = esm["Properties"].get("EventSourceArn")
        # DynamoDB stream sources are referenced as Fn::GetAtt [Table, StreamArn].
        if isinstance(source, dict) and source.get("Fn::GetAtt", [None, None])[1] == "StreamArn":
            consumers.append(esm["Properties"]["FunctionName"]["Ref"])

    assert consumers, "expected at least one DynamoDB Streams consumer"
    for function_id in consumers:
        role_id = _role_id_for_function(resources, function_id)
        actions = _actions_granted_to_role(resources, role_id)
        missing = _STREAM_READ_ACTIONS - actions
        assert not missing, f"{function_id} is missing stream-read permissions: {sorted(missing)}"


def _actions_on_table(resources: dict[str, dict], role_id: str, table_id_prefix: str) -> set[str]:
    """Actions a role is granted on statements whose Resource references a table."""
    actions: set[str] = set()
    for policy in _of_type(resources, "AWS::IAM::Policy").values():
        roles = policy["Properties"].get("Roles", [])
        if not any(isinstance(r, dict) and r.get("Ref") == role_id for r in roles):
            continue
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]:
            resource = statement.get("Resource", [])
            resource = resource if isinstance(resource, list) else [resource]
            refs_table = any(
                isinstance(r, dict)
                and isinstance(r.get("Fn::GetAtt"), list)
                and str(r["Fn::GetAtt"][0]).startswith(table_id_prefix)
                for r in resource
            )
            if refs_table:
                action = statement.get("Action", [])
                actions.update([action] if isinstance(action, str) else action)
    return actions


def test_policy_engine_can_getitem_on_approvals_table(resources: dict[str, dict]) -> None:
    # The idempotency check in _ensure_approval needs GetItem on the approvals
    # table (a grant that previously only allowed Put/Update — the bug).
    functions = [
        name
        for name, v in _of_type(resources, "AWS::Lambda::Function").items()
        if name.startswith("PolicyEngineFunction")
    ]
    assert len(functions) == 1, functions
    role_id = _role_id_for_function(resources, functions[0])
    actions = _actions_on_table(resources, role_id, "ApprovalsTable")
    assert "dynamodb:GetItem" in actions, f"policy engine lacks GetItem on approvals: {actions}"


def test_metric_history_table_has_ttl(resources: dict[str, dict]) -> None:
    # Forecasting data points expire via DynamoDB TTL (30 days).
    tables = {
        name: t
        for name, t in _of_type(resources, "AWS::DynamoDB::Table").items()
        if name.startswith("MetricHistoryTable")
    }
    assert len(tables) == 1, tables
    (props,) = (t["Properties"] for t in tables.values())
    ttl = props.get("TimeToLiveSpecification", {})
    assert ttl.get("Enabled") is True and ttl.get("AttributeName") == "ttl", ttl


def test_iam_detector_can_write_and_read_metric_history(resources: dict[str, dict]) -> None:
    # Forecasting: the IAM detector appends points (PutItem) and reads history (Query).
    functions = [
        name
        for name in _of_type(resources, "AWS::Lambda::Function")
        if name.startswith("IamDetectorFunction")
    ]
    assert len(functions) == 1, functions
    role_id = _role_id_for_function(resources, functions[0])
    actions = _actions_on_table(resources, role_id, "MetricHistoryTable")
    assert {"dynamodb:PutItem", "dynamodb:Query"} <= actions, (
        f"IAM detector lacks metric_history PutItem/Query: {sorted(actions)}"
    )


def _notifier_function(resources: dict[str, dict]) -> tuple[str, dict]:
    fns = {
        name: v
        for name, v in _of_type(resources, "AWS::Lambda::Function").items()
        if name.startswith("NotifierFunction")
    }
    assert len(fns) == 1, fns
    ((name, v),) = fns.items()
    return name, v


def test_notifier_function_exists(resources: dict[str, dict]) -> None:
    _name, fn = _notifier_function(resources)
    props = fn["Properties"]
    assert props["Runtime"] == "python3.12"
    assert props["MemorySize"] == 256
    assert props["Timeout"] == 30


def test_notifier_eventbridge_rule_pattern(resources: dict[str, dict]) -> None:
    rules = {
        name: v
        for name, v in _of_type(resources, "AWS::Events::Rule").items()
        if v["Properties"].get("Name") == "tidewater-notifier-rule"
    }
    assert len(rules) == 1, rules
    (props,) = (v["Properties"] for v in rules.values())
    assert set(props["EventPattern"]["detail-type"]) == {
        "Finding.created",
        "Finding.updated",
        "remediation.failed",
    }


def test_notifier_can_publish_to_sns(resources: dict[str, dict]) -> None:
    name, _ = _notifier_function(resources)
    role_id = _role_id_for_function(resources, name)
    actions = _actions_granted_to_role(resources, role_id)
    assert "sns:Publish" in actions, f"notifier lacks sns:Publish: {sorted(actions)}"


def test_notifier_can_claim_notification_slot(resources: dict[str, dict]) -> None:
    name, _ = _notifier_function(resources)
    role_id = _role_id_for_function(resources, name)
    actions = _actions_on_table(resources, role_id, "FindingsTable")
    assert "dynamodb:UpdateItem" in actions, (
        f"notifier lacks findings UpdateItem: {sorted(actions)}"
    )


# ------------------------------------------------------------------ Phase 9a dashboard
def _single_function(resources: dict[str, dict], prefix: str) -> tuple[str, dict]:
    fns = {
        name: v
        for name, v in _of_type(resources, "AWS::Lambda::Function").items()
        if name.startswith(prefix)
    }
    assert len(fns) == 1, f"expected one {prefix}; got {sorted(fns)}"
    ((name, v),) = fns.items()
    return name, v


def test_dashboard_api_function_exists(resources: dict[str, dict]) -> None:
    _name, fn = _single_function(resources, "DashboardApiFunction")
    props = fn["Properties"]
    assert props["Runtime"] == "python3.12"
    assert props["MemorySize"] == 512
    assert props["Timeout"] == 30


def test_authorizer_function_exists(resources: dict[str, dict]) -> None:
    # The HTTP API bearer authorizer (reused/upgraded from the Phase 2 stub).
    _single_function(resources, "AuthorizerFunction")


def test_six_dashboard_routes_target_the_api_lambda(resources: dict[str, dict]) -> None:
    expected = {
        "GET /findings",
        "GET /findings/{pk}/{sk}",
        "GET /findings/{pk}/{sk}/audit",
        "GET /findings/{pk}/{sk}/snapshot",
        "GET /rules",
        "GET /rules/{rule_id}",
    }
    routes = {
        v["Properties"]["RouteKey"]
        for v in _of_type(resources, "AWS::ApiGatewayV2::Route").values()
    }
    assert expected <= routes, f"missing routes: {sorted(expected - routes)}"
    # All six use the custom (bearer) authorizer; /health stays public.
    for v in _of_type(resources, "AWS::ApiGatewayV2::Route").values():
        rk = v["Properties"]["RouteKey"]
        if rk in expected:
            assert v["Properties"].get("AuthorizationType") == "CUSTOM", rk
        if rk == "GET /health":
            assert v["Properties"].get("AuthorizationType") == "NONE"


def test_bearer_token_parameter_custom_resource(resources: dict[str, dict]) -> None:
    bearer = _of_type(resources, "Custom::BearerToken")
    assert len(bearer) == 1
    (cr,) = bearer.values()
    assert cr["Properties"]["ParameterName"] == "/platform-hygiene/poc/bearer-token"
    assert cr["Properties"]["ParameterType"] == "SecureString"


def test_dashboard_api_can_read_findings(resources: dict[str, dict]) -> None:
    name, _ = _single_function(resources, "DashboardApiFunction")
    role_id = _role_id_for_function(resources, name)
    actions = _actions_on_table(resources, role_id, "FindingsTable")
    assert {"dynamodb:Scan", "dynamodb:GetItem"} <= actions, (
        f"dashboard API lacks findings Scan/GetItem: {sorted(actions)}"
    )


def test_dashboard_api_can_read_buckets(resources: dict[str, dict]) -> None:
    name, _ = _single_function(resources, "DashboardApiFunction")
    role_id = _role_id_for_function(resources, name)
    actions = _actions_granted_to_role(resources, role_id)
    # grant_read yields s3:GetObject* / s3:List* (wildcard form).
    assert any(a.startswith("s3:GetObject") for a in actions), (
        f"dashboard API lacks s3:GetObject: {sorted(actions)}"
    )
    assert any(a.startswith("s3:List") for a in actions), (
        f"dashboard API lacks s3:List: {sorted(actions)}"
    )


def test_authorizer_can_read_bearer_token(resources: dict[str, dict]) -> None:
    name, _ = _single_function(resources, "AuthorizerFunction")
    role_id = _role_id_for_function(resources, name)
    actions = _actions_granted_to_role(resources, role_id)
    assert "ssm:GetParameter" in actions, f"authorizer lacks ssm:GetParameter: {sorted(actions)}"


# ----------------------------------------------- PythonLambda handler/bundle guard
def _expected_handler_source(lam: PythonLambda) -> Path:
    """The source file the Lambda's handler must resolve to, given its bundle layout.

    The PythonLambda bundler produces two layouts (see infra/constructs):
      * include_shared=True  -> mirrors lambdas/ (entry at its lambdas-relative path
        + a top-level shared/), so a dotted handler like `dashboard_api.handler.handler`
        resolves to lambdas/dashboard_api/handler.py.
      * include_shared=False -> flattens the entry's CONTENTS to the zip root, so the
        handler must be `handler.handler` -> <entry>/handler.py.

    Returns the path that must exist; a mismatch (the Phase 9a defect:
    include_shared=False with a full-dotted handler) points at a nonexistent file.
    """
    module_path = "/".join(lam.handler_path.split(".")[:-1]) + ".py"
    if lam.include_shared:
        return REPO_ROOT / "lambdas" / module_path
    return lam.entry_path / module_path


def test_every_python_lambda_handler_resolves_in_bundle() -> None:
    """Every PythonLambda's handler must map to a real module in its bundle layout.

    Catches asset-vs-handler mismatches (Phase 9a's include_shared=False with a
    `dashboard_api.handler.handler` handler) at synth time instead of via an opaque
    Runtime.ImportModuleError 500 at cold start. Runs in-process (no cdk.out / node
    needed) so it executes in the Python-only pytest CI job.
    """
    app = cdk.App(context={"bundle_lambdas": False})
    stack = CoreStack(app, "HandlerCheck", env=ENV, notification_email="test@example.com")
    lambdas = [c for c in stack.node.find_all() if isinstance(c, PythonLambda)]
    assert lambdas, "no PythonLambda constructs found in the stack"

    failures = []
    for lam in lambdas:
        expected = _expected_handler_source(lam)
        if not expected.is_file():
            failures.append(
                f"{lam.node.id}: handler={lam.handler_path!r} "
                f"(include_shared={lam.include_shared}) expects {expected} but it is missing"
            )
    assert not failures, "handler/bundle mismatches:\n" + "\n".join(failures)
