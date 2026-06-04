"""Meta-test: every AWS API a detector calls must be granted to its Lambda role.

The detectors call read-only AWS APIs directly via boto3. Their execution-role
permissions are hand-curated in `core_stack.py` (not derived from a CDK `grant_*`
helper), so they can silently drift out of sync with the code: add a new call
without the matching grant and the detector throws AccessDenied only at runtime,
in production.

This test closes that gap. For each scanned detector tree it statically finds the
boto3 method names referenced (direct calls, attribute references passed as
callables, and `get_paginator("...")` arguments), maps each to its IAM action,
and asserts the synthesized detector role grants it.

Adding a new call? Add the boto3 method -> action pair to that tree's method map
below AND grant the action in core_stack.py. This test fails until you do both.
"""

import ast
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

from infra.stacks.core_stack import CoreStack

_REPO_ROOT = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="123456789012", region="us-east-1")

# boto3 method name -> the IAM action it requires, for the IAM detector tree.
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

# boto3 method name -> action, for the Lambda detector tree (lambda + cloudwatch).
BOTO3_METHOD_TO_LAMBDA_ACTION: dict[str, str] = {
    "list_functions": "lambda:ListFunctions",
    "list_tags": "lambda:ListTags",
    "get_metric_statistics": "cloudwatch:GetMetricStatistics",
}

# Each scanned detector tree, its synthesized Lambda logical-id prefix, and the
# method->action map that governs it.
SCAN_TARGETS = [
    ("lambdas/detectors/iam", "IamDetectorFunction", BOTO3_METHOD_TO_IAM_ACTION),
    ("lambdas/detectors/lambda_", "LambdaDetectorFunction", BOTO3_METHOD_TO_LAMBDA_ACTION),
]

# Verb prefixes that mark a boto3 call as an AWS API (for the completeness check).
_AWS_VERB_PREFIXES = (
    "get_",
    "list_",
    "generate_",
    "update_",
    "delete_",
    "detach_",
    "attach_",
)


def _methods_called_in(tree_dir: Path, method_names: frozenset[str]) -> set[str]:
    """All boto3 method names from ``method_names`` referenced under ``tree_dir``.

    Catches three call shapes: direct calls (``iam.get_role(...)``), bare callable
    references (``self._exists(self.iam.get_user, ...)``), and paginator strings
    (``client.get_paginator("list_roles")``).
    """
    found: set[str] = set()
    for path in sorted(tree_dir.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in method_names:
                found.add(node.attr)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get_paginator"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                method = node.args[0].value
                if method in method_names:
                    found.add(method)
    return found


def _paginator_strings_in(tree_dir: Path) -> set[str]:
    strings: set[str] = set()
    for path in tree_dir.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get_paginator"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                strings.add(node.args[0].value)
    return strings


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
    ("tree", "logical_id_prefix", "method_map"),
    SCAN_TARGETS,
    ids=[t[0] for t in SCAN_TARGETS],
)
def test_every_api_call_has_a_matching_grant(
    resources: dict[str, dict],
    tree: str,
    logical_id_prefix: str,
    method_map: dict[str, str],
) -> None:
    called = _methods_called_in(_REPO_ROOT / tree, frozenset(method_map))
    assert called, f"no mapped boto3 calls discovered under {tree}; scanner likely broken"

    required = {method_map[m] for m in called}
    role_id = _role_id_for_function_prefix(resources, logical_id_prefix)
    granted = _actions_granted_to_role(resources, role_id)

    missing = required - granted
    assert not missing, (
        f"{tree} calls APIs whose actions are not granted to {logical_id_prefix}: "
        f"{sorted(missing)}. Add the grant in core_stack.py."
    )


@pytest.mark.parametrize(
    ("tree", "logical_id_prefix", "method_map"),
    SCAN_TARGETS,
    ids=[t[0] for t in SCAN_TARGETS],
)
def test_method_map_is_complete_for_each_tree(
    tree: str, logical_id_prefix: str, method_map: dict[str, str]
) -> None:
    # An AWS-looking paginator method that isn't mapped would be silently ignored
    # by the scanner — fail loudly so the map can't fall behind.
    unmapped = {
        method
        for method in _paginator_strings_in(_REPO_ROOT / tree)
        if method.startswith(_AWS_VERB_PREFIXES) and method not in method_map
    }
    assert not unmapped, f"unmapped paginator methods in {tree}: {sorted(unmapped)}"
