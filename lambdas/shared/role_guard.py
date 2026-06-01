"""Protected-role guardrail (defense in depth).

AWS-managed / service-linked roles must never be remediated. The detector already
skips them, but the remediator re-checks here before invoking any destructive SSM
runbook, and the runbook asserts again at execution time. Three independent
layers, by design.

(The detector keeps its own copy of these patterns; this module is the shared
source used by the remediation path.)
"""

# Matched against the role name (last ARN segment).
PROTECTED_NAME_PREFIXES: tuple[str, ...] = (
    "AWSReservedSSO_",
    "cdk-hnb659fds-",
    "StackSet-",
    "OrganizationAccountAccessRole",
    "aws-controltower-",
    "aws-service-role/",
)
# Matched against the role ARN/path (service-linked roles).
PROTECTED_PATH_FRAGMENTS: tuple[str, ...] = ("/aws-service-role/",)


def role_name_from_arn(resource_arn: str) -> str:
    """Extract the IAM RoleName (last path segment) from a role ARN."""
    return resource_arn.split(":role/")[-1].split("/")[-1]


def is_protected_role(resource_arn: str) -> bool:
    if any(fragment in resource_arn for fragment in PROTECTED_PATH_FRAGMENTS):
        return True
    name = role_name_from_arn(resource_arn)
    return any(name.startswith(prefix) for prefix in PROTECTED_NAME_PREFIXES)
