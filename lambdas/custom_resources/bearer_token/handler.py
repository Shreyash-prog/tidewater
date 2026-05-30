"""CloudFormation custom resource: generate the dashboard bearer token.

Runs at deploy time (docs/architecture.md §7). On Create/Update it writes a
32-byte URL-safe random token to the SSM SecureString parameter ONLY if the
parameter does not already exist — so redeploys never rotate the token out from
under an operator who has already copied it. On Delete it removes the parameter.

CloudFormation can't create SecureString parameters natively, which is why this
is a custom resource rather than an AWS::SSM::Parameter.

Invoked via the CDK Provider framework: return a dict; the framework sends the
CloudFormation response. No third-party deps (secrets is stdlib, boto3 is in the
Lambda runtime).
"""

import contextlib
import secrets
from typing import Any, Literal, cast

import boto3

TOKEN_NBYTES = 32


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request_type = event["RequestType"]
    props = event["ResourceProperties"]
    parameter_name: str = props["ParameterName"]
    parameter_type = cast(
        Literal["SecureString", "String", "StringList"],
        props.get("ParameterType", "SecureString"),
    )

    ssm = boto3.client("ssm")
    physical_id = parameter_name

    if request_type in ("Create", "Update"):
        if not _parameter_exists(ssm, parameter_name):
            ssm.put_parameter(
                Name=parameter_name,
                Value=secrets.token_urlsafe(TOKEN_NBYTES),
                Type=parameter_type,
                Overwrite=False,
            )
        return {"PhysicalResourceId": physical_id, "Data": {"ParameterName": parameter_name}}

    if request_type == "Delete":
        with contextlib.suppress(ssm.exceptions.ParameterNotFound):
            ssm.delete_parameter(Name=parameter_name)
        return {"PhysicalResourceId": event.get("PhysicalResourceId", physical_id)}

    raise ValueError(f"Unexpected RequestType: {request_type}")


def _parameter_exists(ssm: Any, name: str) -> bool:
    try:
        ssm.get_parameter(Name=name)
        return True
    except ssm.exceptions.ParameterNotFound:
        return False
