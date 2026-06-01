"""End-to-end smoke test for the iam.unused_role detector.

Uploads a temporary, scoped rule YAML to the rules-yaml bucket, creates a real
(unused) IAM role, invokes the deployed detector pointed at that scoped prefix via
`rules_prefix_override`, and waits for a finding. This exercises the real
production code path (load rules from S3 → run → write) with no test-only branches
in the Lambda. Requires real AWS credentials and a deployed CoreStack — excluded
from the default test run (see `make smoke`).

Cleanup (in finally) deletes the temporary rule object, the finding row, and the
IAM role unconditionally. The role and rule prefix are uniquely suffixed so any
accidental orphan is clearly attributable.

Threshold note: the detector flags roles idle *more than* `idle_days`. A
freshly-created role is 0 days idle, so the temporary rule uses `idle_days: -1`
to flag it. Asserting the finding's threshold proves the custom rule (not the
production default of 7) drove the run.
"""

import contextlib
import json
import time
import uuid
from typing import Any

import boto3
import pytest
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

pytestmark = pytest.mark.smoke

STACK = "PlatformHygiene-Core"
REGION = "us-east-1"
RULE_ID = "iam.unused_role"
SMOKE_IDLE_DAYS = -1

RULE_YAML = f"""\
rule: {RULE_ID}
enabled: true
schedule: on-demand
threshold:
  idle_days: {SMOKE_IDLE_DAYS}
forecast:
  enabled: false
policy:
  default: dry_run
notifications:
  channels: [eventbridge, sns]
"""


def _stack_outputs() -> dict[str, str]:
    cfn = boto3.client("cloudformation", region_name=REGION)
    stacks = cfn.describe_stacks(StackName=STACK)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


@pytest.fixture(scope="module")
def aws_env() -> dict[str, str]:
    try:
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        outputs = _stack_outputs()
    except (NoCredentialsError, BotoCoreError, ClientError) as exc:
        pytest.skip(f"AWS not available or stack not deployed: {exc}")
    required = {"IamDetectorLambdaName", "FindingsTableName", "RulesYamlBucketName"}
    if not required.issubset(outputs):
        pytest.skip(f"required stack outputs missing: {required - set(outputs)}")
    return {
        "account": account,
        "function": outputs["IamDetectorLambdaName"],
        "table": outputs["FindingsTableName"],
        "bucket": outputs["RulesYamlBucketName"],
    }


def test_detector_flags_unused_role(aws_env: dict[str, str]) -> None:
    iam = boto3.client("iam", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    lambda_client = boto3.client("lambda", region_name=REGION)
    table = boto3.resource("dynamodb", region_name=REGION).Table(aws_env["table"])

    suffix = uuid.uuid4().hex
    role_name = f"tidewater-smoke-iam-unused-role-{suffix}"
    role_arn = f"arn:aws:iam::{aws_env['account']}:role/{role_name}"
    rules_prefix = f"rules-smoketest/{suffix}/"
    rule_key = f"{rules_prefix}{RULE_ID}.yaml"
    pk = f"{aws_env['account']}#{REGION}#iam"
    sk = f"{role_arn}#{RULE_ID}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{aws_env['account']}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        s3.put_object(Bucket=aws_env["bucket"], Key=rule_key, Body=RULE_YAML.encode())
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Tidewater smoke test - safe to delete.",
        )

        payload = {
            "account": aws_env["account"],
            "region": REGION,
            "rules_prefix_override": rules_prefix,
        }
        resp = lambda_client.invoke(
            FunctionName=aws_env["function"], Payload=json.dumps(payload).encode()
        )
        assert resp["StatusCode"] == 200, resp

        item = _poll_for_item(table, pk, sk, timeout_s=60)

        assert item is not None, f"no finding appeared for {role_arn}"
        assert item["severity"] == "high"  # never used
        assert item["rule_id"] == RULE_ID
        assert item["details"]["role_name"] == role_name
        assert item["policy_decision"] == "dry_run"
        # Proves the scoped custom rule drove the run (production default is 7).
        assert int(item["details"]["threshold_idle_days"]) == SMOKE_IDLE_DAYS
    finally:
        with contextlib.suppress(ClientError):
            s3.delete_object(Bucket=aws_env["bucket"], Key=rule_key)
        with contextlib.suppress(ClientError):
            table.delete_item(Key={"pk": pk, "sk": sk})
        with contextlib.suppress(ClientError):
            iam.delete_role(RoleName=role_name)


def _poll_for_item(table: Any, pk: str, sk: str, *, timeout_s: int) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        item = table.get_item(Key={"pk": pk, "sk": sk}).get("Item")
        if item:
            return item
        time.sleep(3)
    return None
