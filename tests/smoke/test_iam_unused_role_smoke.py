"""End-to-end smoke test for the iam.unused_role detector.

Creates a real (unused) IAM role, invokes the deployed detector Lambda, and waits
for a finding to appear in the findings table. Requires real AWS credentials and
a deployed CoreStack — excluded from the default test run (see `make smoke`).

Cleanup deletes the role unconditionally. The role name is uniquely prefixed
(`tidewater-smoke-iam-unused-role-<uuid>`) so any accidental orphan is obvious.
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
    if "IamDetectorLambdaName" not in outputs or "FindingsTableName" not in outputs:
        pytest.skip("required stack outputs missing")
    return {
        "account": account,
        "function": outputs["IamDetectorLambdaName"],
        "table": outputs["FindingsTableName"],
    }


def test_detector_flags_unused_role(aws_env: dict[str, str]) -> None:
    iam = boto3.client("iam", region_name=REGION)
    lambda_client = boto3.client("lambda", region_name=REGION)
    table = boto3.resource("dynamodb", region_name=REGION).Table(aws_env["table"])

    role_name = f"tidewater-smoke-iam-unused-role-{uuid.uuid4().hex}"
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
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Tidewater smoke test — safe to delete.",
        )["Role"]["Arn"]

        # idle_days=-1 forces a freshly created (0-day-idle) role to be flagged,
        # given the detector's strict "more than threshold" comparison.
        payload = {
            "account": aws_env["account"],
            "region": REGION,
            "threshold_override": {"idle_days": -1},
        }
        resp = lambda_client.invoke(
            FunctionName=aws_env["function"], Payload=json.dumps(payload).encode()
        )
        assert resp["StatusCode"] == 200, resp

        pk = f"{aws_env['account']}#{REGION}#iam"
        sk = f"{role_arn}#{RULE_ID}"
        item = _poll_for_item(table, pk, sk, timeout_s=60)

        assert item is not None, f"no finding appeared for {role_arn}"
        assert item["severity"] == "high"  # never used
        assert item["rule_id"] == RULE_ID
        assert item["details"]["role_name"] == role_name
        assert item["policy_decision"] == "dry_run"
    finally:
        _delete_item(table, aws_env, role_arn=_safe_arn(aws_env, role_name))
        _delete_role(iam, role_name)


def _poll_for_item(table: Any, pk: str, sk: str, *, timeout_s: int) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        item = table.get_item(Key={"pk": pk, "sk": sk}).get("Item")
        if item:
            return item
        time.sleep(3)
    return None


def _safe_arn(aws_env: dict[str, str], role_name: str) -> str:
    return f"arn:aws:iam::{aws_env['account']}:role/{role_name}"


def _delete_item(table: Any, aws_env: dict[str, str], *, role_arn: str) -> None:
    pk = f"{aws_env['account']}#{REGION}#iam"
    sk = f"{role_arn}#{RULE_ID}"
    with contextlib.suppress(ClientError):
        table.delete_item(Key={"pk": pk, "sk": sk})


def _delete_role(iam: Any, role_name: str) -> None:
    with contextlib.suppress(ClientError):
        iam.delete_role(RoleName=role_name)
