"""Structural guarantees for the Phase 5 remediation runbooks.

Asserts, per runbook: required parameters are declared, the guardrail step exists
(where applicable), and the snapshot is written before any mutating step.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

_RUNBOOKS = Path(__file__).resolve().parents[2] / "runbooks"

# Mutating actions (executeAwsApi `Api`) and inline-script markers that must never
# run before writeSnapshotToS3.
_MUTATING_APIS = {
    "UpdateAccessKey",
    "UpdateAssumeRolePolicy",
    "DeletePolicy",
    "DeletePolicyVersion",
    "DetachRolePolicy",
    "DeleteRole",
}
_MUTATING_SCRIPT_MARKERS = (
    "update_access_key(",
    "update_assume_role_policy(",
    "delete_policy(",
    "delete_policy_version(",
    "detach_role_policy(",
)

_COMMON_PARAMS = {
    "SnapshotBucket",
    "AuditBucket",
    "FindingsTableName",
    "FindingPk",
    "FindingSk",
    "EventBusName",
    "AutomationAssumeRole",
}

CASES = [
    pytest.param(
        "delete_iam_access_key.yml",
        {"AccessKeyId", "UserName"},
        None,
        ["deactivateAccessKey"],
        id="delete_iam_access_key",
    ),
    pytest.param(
        "remove_trust_principal.yml",
        {"RoleName", "OrphanPrincipals"},
        "assertRoleNotProtected",
        ["updateAssumeRolePolicy"],
        id="remove_trust_principal",
    ),
    pytest.param(
        "delete_unused_policy.yml",
        {"PolicyArn"},
        "assertPolicyNotProtected",
        ["deleteNonDefaultVersions", "deletePolicy"],
        id="delete_unused_policy",
    ),
    pytest.param(
        "detach_unused_policy.yml",
        {"RoleName"},
        "assertRoleNotProtected",
        ["detachPolicy"],
        id="detach_unused_policy",
    ),
]


def _doc(filename: str) -> dict[str, Any]:
    return yaml.safe_load((_RUNBOOKS / filename).read_text())


@pytest.mark.parametrize(("filename", "extra_params", "guardrail", "mutating_steps"), CASES)
def test_required_parameters_declared(
    filename: str, extra_params: set[str], guardrail: str | None, mutating_steps: list[str]
) -> None:
    params = set(_doc(filename)["parameters"])
    assert params >= _COMMON_PARAMS
    assert extra_params <= params


@pytest.mark.parametrize(("filename", "extra_params", "guardrail", "mutating_steps"), CASES)
def test_guardrail_runs_before_snapshot(
    filename: str, extra_params: set[str], guardrail: str | None, mutating_steps: list[str]
) -> None:
    if guardrail is None:
        pytest.skip("no role/policy guardrail for this runbook")
    names = [s["name"] for s in _doc(filename)["mainSteps"]]
    assert guardrail in names
    assert names.index(guardrail) < names.index("writeSnapshotToS3")


@pytest.mark.parametrize(("filename", "extra_params", "guardrail", "mutating_steps"), CASES)
def test_snapshot_written_before_every_mutation(
    filename: str, extra_params: set[str], guardrail: str | None, mutating_steps: list[str]
) -> None:
    doc = _doc(filename)
    names = [s["name"] for s in doc["mainSteps"]]
    snapshot_idx = names.index("writeSnapshotToS3")
    for step in mutating_steps:
        assert snapshot_idx < names.index(step), f"{step} runs before snapshot in {filename}"

    # No mutating API/script call appears in any step before the snapshot.
    for step in doc["mainSteps"][:snapshot_idx]:
        inputs = step.get("inputs", {})
        assert inputs.get("Api") not in _MUTATING_APIS, f"{step['name']} mutates pre-snapshot"
        script = inputs.get("Script", "")
        for marker in _MUTATING_SCRIPT_MARKERS:
            assert marker not in script, f"{step['name']} mutates ({marker}) pre-snapshot"


def test_delete_unused_policy_asserts_no_attachments_before_delete() -> None:
    names = [s["name"] for s in _doc("delete_unused_policy.yml")["mainSteps"]]
    assert names.index("assertNoAttachments") < names.index("deletePolicy")
    assert names.index("assertNoAttachments") < names.index("deleteNonDefaultVersions")


def test_access_key_runbook_deactivates_not_deletes() -> None:
    doc = _doc("delete_iam_access_key.yml")
    apis = [s.get("inputs", {}).get("Api") for s in doc["mainSteps"]]
    assert "UpdateAccessKey" in apis  # deactivation
    assert "DeleteAccessKey" not in apis  # never auto-delete
