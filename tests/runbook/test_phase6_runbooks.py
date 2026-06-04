"""Structural + safety-gate tests for the Phase 6 Lambda remediation runbook.

Structural: the 12 steps appear in the expected order, with the three
downstream-impact gates and both snapshot uploads ahead of deleteFunction.

Behavioural: the gate steps' executeScript bodies each expose a pure helper
(`_assert_no_mappings`, `_assert_no_url`, `_assert_internal_only`) that we exec
in-process and drive with synthetic state — no boto3, no AWS.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

_RUNBOOKS = Path(__file__).resolve().parents[2] / "runbooks"
_DOC = "delete_unused_function.yml"

_EXPECTED_STEPS = [
    "assertFunctionNotProtected",
    "getFunctionDetails",
    "listEventSourceMappings",
    "getFunctionUrlConfig",
    "getResourcePolicy",
    "buildSnapshot",
    "downloadAndStoreCode",
    "writeSnapshotMetadata",
    "deleteFunction",
    "updateFindingResolved",
    "emitRemediationCompletedEvent",
    "writeFinalAuditLog",
]


def _doc() -> dict[str, Any]:
    return yaml.safe_load((_RUNBOOKS / _DOC).read_text())


def _step_names() -> list[str]:
    return [s["name"] for s in _doc()["mainSteps"]]


def _script_namespace(step_name: str) -> dict[str, Any]:
    step = next(s for s in _doc()["mainSteps"] if s["name"] == step_name)
    namespace: dict[str, Any] = {}
    exec(step["inputs"]["Script"], namespace)  # noqa: S102 — trusted runbook source
    return namespace


def _helper(step_name: str, func_name: str) -> Callable[..., Any]:
    return _script_namespace(step_name)[func_name]


# ----------------------------------------------------------------------- structural
def test_all_twelve_steps_in_order() -> None:
    assert _step_names() == _EXPECTED_STEPS


def test_required_parameters_declared() -> None:
    params = set(_doc()["parameters"])
    assert {
        "FunctionName",
        "AccountId",
        "SnapshotBucket",
        "AuditBucket",
        "FindingsTableName",
        "FindingPk",
        "FindingSk",
        "EventBusName",
        "AutomationAssumeRole",
    } <= params


def test_safety_gates_run_before_delete() -> None:
    names = _step_names()
    delete_idx = names.index("deleteFunction")
    for gate in ("listEventSourceMappings", "getFunctionUrlConfig", "getResourcePolicy"):
        assert names.index(gate) < delete_idx, f"{gate} must run before deleteFunction"


def test_snapshot_uploads_before_delete() -> None:
    names = _step_names()
    delete_idx = names.index("deleteFunction")
    assert names.index("downloadAndStoreCode") < delete_idx
    assert names.index("writeSnapshotMetadata") < delete_idx


def test_delete_uses_lambda_delete_function_api() -> None:
    step = next(s for s in _doc()["mainSteps"] if s["name"] == "deleteFunction")
    assert step["inputs"]["Service"] == "lambda"
    assert step["inputs"]["Api"] == "DeleteFunction"


# -------------------------------------------------------------- gate 1: event sources
def test_event_source_gate_aborts_when_mappings_present() -> None:
    assert_no_mappings = _helper("listEventSourceMappings", "_assert_no_mappings")
    assert_no_mappings([])  # clean: no raise
    with pytest.raises(Exception, match="active event source mappings"):
        assert_no_mappings([{"UUID": "abc-123", "EventSourceArn": "arn:aws:sqs:::q"}])


# -------------------------------------------------------------------- gate 2: function URL
def test_function_url_gate_aborts_when_url_present() -> None:
    assert_no_url = _helper("getFunctionUrlConfig", "_assert_no_url")
    assert_no_url(None)  # clean: no raise
    with pytest.raises(Exception, match="public function URL with AuthType=NONE"):
        assert_no_url({"AuthType": "NONE", "FunctionUrl": "https://x.lambda-url"})


# --------------------------------------------------------------- gate 3: resource policy
def test_resource_policy_gate_aborts_on_external_service_principal() -> None:
    assert_internal_only = _helper("getResourcePolicy", "_assert_internal_only")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "apigw",
                "Effect": "Allow",
                "Principal": {"Service": "apigateway.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
            }
        ],
    }
    with pytest.raises(Exception, match="external sources"):
        assert_internal_only(policy, "111111111111")


def test_resource_policy_gate_aborts_on_cross_account_principal() -> None:
    external = _helper("getResourcePolicy", "_external_statements")
    policy = {
        "Statement": [
            {
                "Sid": "crossacct",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "lambda:InvokeFunction",
            }
        ]
    }
    assert external(policy, "111111111111") == ["crossacct"]


def test_resource_policy_gate_allows_internal_only() -> None:
    assert_internal_only = _helper("getResourcePolicy", "_assert_internal_only")
    external = _helper("getResourcePolicy", "_external_statements")
    policy = {
        "Statement": [
            {
                "Sid": "same-account-svc",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Condition": {"StringEquals": {"AWS:SourceAccount": "111111111111"}},
            },
            {
                "Sid": "same-account-aws",
                "Principal": {"AWS": "arn:aws:iam::111111111111:role/app"},
                "Action": "lambda:InvokeFunction",
            },
        ]
    }
    assert external(policy, "111111111111") == []
    assert_internal_only(policy, "111111111111")  # no raise
    assert_internal_only({"Statement": []}, "111111111111")  # empty policy ok
