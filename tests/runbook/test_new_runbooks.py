"""Structural guarantees for the Phase 5 remediation runbooks.

Asserts, per runbook: required parameters are declared, the guardrail step exists
(where applicable), and the snapshot is written before any mutating step.

Also executes the trust-policy rewrite logic of remove_trust_principal.yml
in-process to prove it strips both orphan forms (ARN + bare unique ID).
"""

import json
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


def _compute_new_trust_policy(role: dict[str, Any], orphans: list[str]) -> Any:
    """Run remove_trust_principal.yml's computeNewTrustPolicy script in-process."""
    doc = _doc("remove_trust_principal.yml")
    step = next(s for s in doc["mainSteps"] if s["name"] == "computeNewTrustPolicy")
    namespace: dict[str, Any] = {}
    exec(step["inputs"]["Script"], namespace)  # noqa: S102 — trusted runbook source
    events = {"RoleJson": json.dumps(role), "OrphanPrincipals": orphans}
    return namespace["handler"](events, None)


def test_trust_rewrite_removes_both_arn_and_bare_id_orphans() -> None:
    # The deleted-user case: a bare AIDA* id alongside an ARN-format orphan and one
    # valid principal. Both orphans must be stripped; the valid principal stays.
    valid = "arn:aws:iam::111111111111:role/valid"
    role = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            valid,
                            "arn:aws:iam::111111111111:user/deleted-user",
                            "AIDASITUILUEC7BNIGN7A",
                        ]
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    }
    result = _compute_new_trust_policy(
        role,
        orphans=["arn:aws:iam::111111111111:user/deleted-user", "AIDASITUILUEC7BNIGN7A"],
    )
    new_doc = json.loads(result["NewPolicyJson"])
    remaining = new_doc["Statement"][0]["Principal"]["AWS"]
    # A single remaining principal collapses to a string, per the runbook logic.
    assert remaining == valid
    assert "AIDASITUILUEC7BNIGN7A" not in json.dumps(new_doc)
    assert "deleted-user" not in json.dumps(new_doc)


def test_trust_rewrite_aborts_when_only_orphan_bare_id_would_be_removed() -> None:
    # If the sole principal is a bare-id orphan, removing it would leave the role
    # unassumable — the runbook must abort rather than write an empty policy.
    role = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "AIDASITUILUEC7BNIGN7A"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    }
    with pytest.raises(Exception, match="unassumable"):
        _compute_new_trust_policy(role, orphans=["AIDASITUILUEC7BNIGN7A"])


def test_trust_rewrite_drops_statement_left_with_empty_principal() -> None:
    # The MalformedPolicyDocument case: two statements, the second's SOLE principal
    # is a bare-id orphan. Removing the AWS key would leave an empty Principal,
    # which AWS rejects — so the whole statement must be dropped, leaving the
    # valid :root statement intact.
    root = "arn:aws:iam::111111111111:root"
    role = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": root},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "AIDASITUILUEO4F4JRVBG"},
                    "Action": "sts:AssumeRole",
                },
            ],
        }
    }
    result = _compute_new_trust_policy(role, orphans=["AIDASITUILUEO4F4JRVBG"])
    new_trust = json.loads(result["NewPolicyJson"])
    assert len(new_trust["Statement"]) == 1
    assert new_trust["Statement"][0]["Principal"]["AWS"] == root
    assert "AIDASITUILUEO4F4JRVBG" not in json.dumps(new_trust)


def test_trust_rewrite_keeps_statement_with_remaining_aws_principals() -> None:
    # Orphan is one of several AWS principals on a single statement: the statement
    # is kept with its principal list reduced, never dropped.
    root = "arn:aws:iam::111111111111:root"
    role = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [root, "AIDASITUILUEO4F4JRVBG"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    }
    result = _compute_new_trust_policy(role, orphans=["AIDASITUILUEO4F4JRVBG"])
    new_trust = json.loads(result["NewPolicyJson"])
    assert len(new_trust["Statement"]) == 1
    # Single remaining principal collapses to a string.
    assert new_trust["Statement"][0]["Principal"]["AWS"] == root


def test_trust_rewrite_keeps_statement_with_other_principal_kinds() -> None:
    # A mixed-trust statement (AWS + Service, e.g. a Lambda exec role): even when
    # ALL AWS principals are orphans, the statement survives because the Service
    # principal remains — only the now-empty AWS key is dropped.
    role = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "AIDASITUILUEO4F4JRVBG",
                        "Service": "lambda.amazonaws.com",
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    }
    result = _compute_new_trust_policy(role, orphans=["AIDASITUILUEO4F4JRVBG"])
    new_trust = json.loads(result["NewPolicyJson"])
    assert len(new_trust["Statement"]) == 1
    principal = new_trust["Statement"][0]["Principal"]
    assert principal == {"Service": "lambda.amazonaws.com"}
    assert "AWS" not in principal
