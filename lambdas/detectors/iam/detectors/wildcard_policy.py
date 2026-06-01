"""iam.wildcard_policy detector (flag-only — never auto-remediated).

Flags overly-broad Allow statements in policies attached to roles:
  * Action `*` / `*:*`                          → HIGH  (god-mode)
  * Resource `*` with a broad `service:*` action → MEDIUM
  * `NotAction` (grants everything except listed) → LOW

Read-only. Wildcard policies frequently exist for legitimate reasons, so this
rule is intentionally prompt-only and has no remediation runbook.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import boto3

from shared.detector_base import Detector
from shared.models import Finding, Severity
from shared.role_guard import is_protected_role


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _classify_statement(statement: dict[str, Any]) -> tuple[Severity, str] | None:
    """Return (severity, matched_pattern) for a broad Allow statement, else None."""
    if statement.get("Effect") != "Allow":
        return None
    if "NotAction" in statement:
        return Severity.LOW, "not_action"

    actions = [str(a) for a in _as_list(statement.get("Action"))]
    resources = [str(r) for r in _as_list(statement.get("Resource"))]
    action_is_full = any(a in ("*", "*:*") for a in actions)
    resource_is_full = "*" in resources

    if action_is_full:
        return Severity.HIGH, "action_wildcard"
    if resource_is_full and any(a.endswith(":*") for a in actions):
        return Severity.MEDIUM, "resource_wildcard_broad_action"
    return None


def _worst_match(document: dict[str, Any]) -> tuple[Severity, str, int] | None:
    """Scan a policy document; return the most severe match with its statement index."""
    order = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
    best: tuple[Severity, str, int] | None = None
    for index, statement in enumerate(_as_list(document.get("Statement"))):
        if not isinstance(statement, dict):
            continue
        classified = _classify_statement(statement)
        if classified is None:
            continue
        severity, pattern = classified
        if best is None or order[severity] > order[best[0]]:
            best = (severity, pattern, index)
    return best


class WildcardPolicyDetector(Detector):
    rule_id = "iam.wildcard_policy"
    service = "iam"
    severity = Severity.HIGH

    def __init__(
        self, account: str, region: str, threshold: dict[str, Any], iam_client: Any | None = None
    ) -> None:
        super().__init__(account, region, threshold)
        self.iam: Any = iam_client or boto3.client("iam")

    def scan(self) -> Iterator[Finding]:
        for page in self.iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                if is_protected_role(role["Arn"]):
                    continue
                yield from self._scan_role(role["RoleName"])

    def _scan_role(self, role_name: str) -> Iterator[Finding]:
        for managed in self._attached_managed(role_name):
            document = self._managed_document(managed["PolicyArn"])
            finding = self._finding_for(
                document, managed["PolicyName"], managed["PolicyArn"], "managed"
            )
            if finding is not None:
                yield finding
        for policy_name in self._inline_names(role_name):
            document = self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            arn = f"arn:aws:iam::{self.account}:role/{role_name}#inline/{policy_name}"
            finding = self._finding_for(document, policy_name, arn, "inline")
            if finding is not None:
                yield finding

    def _attached_managed(self, role_name: str) -> list[dict[str, Any]]:
        policies: list[dict[str, Any]] = []
        for page in self.iam.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name
        ):
            policies.extend(page.get("AttachedPolicies", []))
        return policies

    def _inline_names(self, role_name: str) -> list[str]:
        names: list[str] = []
        for page in self.iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            names.extend(page.get("PolicyNames", []))
        return names

    def _managed_document(self, policy_arn: str) -> dict[str, Any]:
        version_id = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        document = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)[
            "PolicyVersion"
        ]["Document"]
        return _decode_document(document)

    def _finding_for(
        self, document: dict[str, Any], policy_name: str, policy_arn: str, policy_type: str
    ) -> Finding | None:
        match = _worst_match(document)
        if match is None:
            return None
        severity, pattern, statement_index = match
        now = datetime.now(UTC)
        return Finding(
            account=self.account,
            region=self.region,
            service="iam",
            resource_arn=policy_arn,
            rule_id=self.rule_id,
            severity=severity,
            detected_at=now,
            last_seen_at=now,
            details={
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "policy_type": policy_type,
                "matched_pattern": pattern,
                "statement_index": statement_index,
            },
        )


def _decode_document(document: Any) -> dict[str, Any]:
    # get_policy_version may return the document URL-encoded as a string.
    if isinstance(document, str):
        return json.loads(unquote(document))
    return document if isinstance(document, dict) else {}
