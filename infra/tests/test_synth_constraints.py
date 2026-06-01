"""Guardrail tests over the synthesized CoreStack template.

These encode the Phase 2 safety rules so a future change can't silently regress
them: log retention, on-demand DynamoDB, bucket removal policies, no NAT
gateways, and a SecureString bearer-token parameter.
"""

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

from infra.stacks.core_stack import RETAIN_BUCKETS, CoreStack

ENV = cdk.Environment(account="123456789012", region="us-east-1")

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
