"""Structural guarantees for the IAM-role-deletion SSM runbook.

These assert the safety contract at the document level: a guardrail step exists,
all required parameters are declared, and — critically — the snapshot is written
to S3 before any destructive step runs.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

_RUNBOOK = Path(__file__).resolve().parents[2] / "runbooks" / "delete_iam_role.yml"

REQUIRED_PARAMETERS = {
    "RoleName",
    "SnapshotBucket",
    "AuditBucket",
    "FindingsTableName",
    "FindingPk",
    "FindingSk",
    "EventBusName",
}
EXPECTED_STEP_ORDER = [
    "assertRoleNotProtected",
    "getRoleDetails",
    "listAttachedManagedPolicies",
    "listInlinePolicies",
    "getEachInlinePolicy",
    "listInstanceProfilesForRole",
    "buildSnapshot",
    "writeSnapshotToS3",
    "detachManagedPolicies",
    "deleteInlinePolicies",
    "removeFromInstanceProfiles",
    "deleteRole",
    "updateFindingResolved",
    "emitRemediationCompletedEvent",
    "writeFinalAuditLog",
]
DESTRUCTIVE_APIS = {
    "DeleteRole",
    "DetachRolePolicy",
    "DeleteRolePolicy",
    "RemoveRoleFromInstanceProfile",
}
DESTRUCTIVE_SCRIPT_CALLS = (
    "delete_role(",
    "detach_role_policy(",
    "delete_role_policy(",
    "remove_role_from_instance_profile(",
)


@pytest.fixture(scope="module")
def doc() -> dict[str, Any]:
    return yaml.safe_load(_RUNBOOK.read_text())


@pytest.fixture(scope="module")
def names(doc: dict[str, Any]) -> list[str]:
    return [step["name"] for step in doc["mainSteps"]]


def test_schema_version_is_automation(doc: dict[str, Any]) -> None:
    assert doc["schemaVersion"] == "0.3"


def test_assume_role_is_parameterized(doc: dict[str, Any]) -> None:
    assert doc["assumeRole"] == "{{ AutomationAssumeRole }}"


def test_required_parameters_declared(doc: dict[str, Any]) -> None:
    assert REQUIRED_PARAMETERS.issubset(set(doc["parameters"]))


def test_guardrail_step_exists(names: list[str]) -> None:
    assert "assertRoleNotProtected" in names
    # ...and runs before any role read/delete.
    assert names.index("assertRoleNotProtected") < names.index("getRoleDetails")


def test_required_steps_present_and_in_order(names: list[str]) -> None:
    indices = [names.index(step) for step in EXPECTED_STEP_ORDER]
    assert indices == sorted(indices)


def test_snapshot_is_written_before_any_deletion(names: list[str]) -> None:
    snapshot_idx = names.index("writeSnapshotToS3")
    for destructive_step in ("detachManagedPolicies", "deleteInlinePolicies", "deleteRole"):
        assert snapshot_idx < names.index(destructive_step)


def test_no_destructive_action_before_snapshot(doc: dict[str, Any], names: list[str]) -> None:
    snapshot_idx = names.index("writeSnapshotToS3")
    for i, step in enumerate(doc["mainSteps"]):
        if i >= snapshot_idx:
            break
        inputs = step.get("inputs", {})
        assert inputs.get("Api") not in DESTRUCTIVE_APIS, step["name"]
        script = inputs.get("Script", "")
        for marker in DESTRUCTIVE_SCRIPT_CALLS:
            assert marker not in script, f"{step['name']} is destructive before snapshot"


def test_delete_role_uses_iam_delete_role_api(doc: dict[str, Any]) -> None:
    delete_step = next(s for s in doc["mainSteps"] if s["name"] == "deleteRole")
    assert delete_step["inputs"]["Api"] == "DeleteRole"
    assert delete_step["inputs"]["Service"] == "iam"
