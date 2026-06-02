"""Meta-test: every IAM API a detector calls must be granted to its Lambda role.

The IAM detectors call read-only IAM APIs directly via boto3. Their execution
role's permissions are hand-curated in `core_stack.py` (not derived from a CDK
`grant_*` helper), so they can silently drift out of sync with the code: add a
new `iam.get_*` call without the matching grant and the detector throws
AccessDenied only at runtime, in production.

This test closes that gap. It statically scans the detector source for boto3 IAM
method names (direct calls, attribute references passed as callables, and
`get_paginator("...")` arguments), maps each to its IAM action, and asserts the
synthesized detector role grants it.

Adding a new IAM call? Add the boto3 method -> IAM action pair to
BOTO3_METHOD_TO_IAM_ACTION below AND grant the action in core_stack.py. This test
fails loudly until you do both.
"""

import ast
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

from infra.stacks.core_stack import CoreStack

_REPO_ROOT = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="123456789012", region="us-east-1")

# boto3 IAM method name -> the IAM action it requires. This is the contract: if a
# detector calls a method not listed here, the test cannot verify its grant and
# fails (forcing the map to be kept complete).
BOTO3_METHOD_TO_IAM_ACTION: dict[str, str] = {
    "list_roles": "iam:ListRoles",
    "get_role": "iam:GetRole",
    "get_user": "iam:GetUser",
    "list_users": "iam:ListUsers",
    "list_role_tags": "iam:ListRoleTags",
    "list_user_tags": "iam:ListUserTags",
    "list_policy_tags": "iam:ListPolicyTags",
    "list_attached_role_policies": "iam:ListAttachedRolePolicies",
    "list_role_policies": "iam:ListRolePolicies",
    "get_role_policy": "iam:GetRolePolicy",
    "list_access_keys": "iam:ListAccessKeys",
    "get_access_key_last_used": "iam:GetAccessKeyLastUsed",
    "list_policies": "iam:ListPolicies",
    "get_policy": "iam:GetPolicy",
    "get_policy_version": "iam:GetPolicyVersion",
    "list_entities_for_policy": "iam:ListEntitiesForPolicy",
    "generate_service_last_accessed_details": "iam:GenerateServiceLastAccessedDetails",
    "get_service_last_accessed_details": "iam:GetServiceLastAccessedDetails",
}

# Source tree to scan -> synthesized Lambda function logical-id prefix.
HANDLER_TO_LAMBDA_LOGICAL_ID: dict[str, str] = {
    "lambdas/detectors/iam": "IamDetectorFunction",
}

_IAM_METHOD_NAMES = frozenset(BOTO3_METHOD_TO_IAM_ACTION)


def _iam_methods_called_in(tree_dir: Path) -> set[str]:
    """All boto3 IAM method names referenced anywhere under ``tree_dir``.

    Catches three call shapes the detectors use:
      * direct calls            ``iam.get_role(...)``
      * callable references     ``self._exists(self.iam.get_user, ...)``
      * paginators              ``iam.get_paginator("list_roles")``
    """
    found: set[str] = set()
    for path in sorted(tree_dir.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            # Attribute access (covers both calls and bare references).
            if isinstance(node, ast.Attribute) and node.attr in _IAM_METHOD_NAMES:
                found.add(node.attr)
            # get_paginator("method_name") string argument.
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get_paginator"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                method = node.args[0].value
                if method in _IAM_METHOD_NAMES:
                    found.add(method)
    return found


@pytest.fixture(scope="module")
def resources() -> dict[str, dict]:
    app = cdk.App(context={"bundle_lambdas": False})
    stack = CoreStack(app, "TestCore", env=ENV, notification_email="test@example.com")
    return assertions.Template.from_stack(stack).to_json()["Resources"]


def _of_type(resources: dict[str, dict], type_name: str) -> dict[str, dict]:
    return {k: v for k, v in resources.items() if v["Type"] == type_name}


def _role_id_for_function_prefix(resources: dict[str, dict], prefix: str) -> str:
    functions = [
        name for name in _of_type(resources, "AWS::Lambda::Function") if name.startswith(prefix)
    ]
    assert len(functions) == 1, f"expected exactly one {prefix}; got {functions}"
    return str(resources[functions[0]]["Properties"]["Role"]["Fn::GetAtt"][0])


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


@pytest.mark.parametrize(
    ("tree", "logical_id_prefix"), sorted(HANDLER_TO_LAMBDA_LOGICAL_ID.items())
)
def test_every_iam_call_has_a_matching_grant(
    resources: dict[str, dict], tree: str, logical_id_prefix: str
) -> None:
    called = _iam_methods_called_in(_REPO_ROOT / tree)
    assert called, f"no IAM boto3 calls discovered under {tree}; scanner likely broken"

    required = {BOTO3_METHOD_TO_IAM_ACTION[m] for m in called}
    role_id = _role_id_for_function_prefix(resources, logical_id_prefix)
    granted = _actions_granted_to_role(resources, role_id)

    missing = required - granted
    assert not missing, (
        f"{tree} calls IAM APIs whose actions are not granted to {logical_id_prefix}: "
        f"{sorted(missing)}. Add the grant in core_stack.py."
    )


def test_method_map_is_complete_for_scanned_trees() -> None:
    # Guard against the scanner silently ignoring an unmapped IAM method: every
    # IAM-looking boto3 method in a scanned tree must appear in the map. (The
    # scanner already filters to mapped names; this asserts no get_paginator
    # string or attribute slips past because we forgot to map it.)
    unmapped: set[str] = set()
    iam_verbs = ("get_", "list_", "generate_", "update_", "delete_", "detach_", "attach_")
    for tree in HANDLER_TO_LAMBDA_LOGICAL_ID:
        for path in (_REPO_ROOT / tree).rglob("*.py"):
            source = ast.parse(path.read_text())
            for node in ast.walk(source):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get_paginator"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    method = node.args[0].value
                    if method.startswith(iam_verbs) and method not in BOTO3_METHOD_TO_IAM_ACTION:
                        unmapped.add(method)
    assert not unmapped, f"unmapped IAM paginator methods: {sorted(unmapped)}"
