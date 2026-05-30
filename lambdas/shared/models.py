"""Core Pydantic models shared across the framework.

These mirror the data model in docs/architecture.md §4–§5 and are the source of
truth for every payload crossing a boundary (Lambda inputs, DynamoDB items, API
responses). See CLAUDE.md: "Use Pydantic models for all data crossing boundaries."
"""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PolicyAction(StrEnum):
    AUTO = "auto"
    PROMPT = "prompt"
    DRY_RUN = "dry_run"
    SKIP = "skip"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    SKIPPED = "skipped"


class Finding(BaseModel):
    account: str
    region: str
    service: Literal["iam", "lambda"]
    resource_arn: str
    rule_id: str
    status: FindingStatus = FindingStatus.OPEN
    severity: Severity
    detected_at: datetime
    last_seen_at: datetime
    details: dict[str, Any]
    policy_decision: PolicyAction | None = None


class RuleOverride(BaseModel):
    match: dict[str, str]  # e.g. {"tag.Environment": "nonprod"}
    action: PolicyAction
    approvers: list[str] = Field(default_factory=list)


class ForecastConfig(BaseModel):
    enabled: bool = False
    alert_at_days_remaining: int = 14


class Rule(BaseModel):
    rule_id: str = Field(alias="rule")
    enabled: bool = True
    schedule: str = "rate(1 hour)"
    threshold: dict[str, Any]
    forecast: ForecastConfig = Field(default_factory=ForecastConfig)
    policy_default: PolicyAction = Field(alias="policy.default", default=PolicyAction.PROMPT)
    overrides: list[RuleOverride] = Field(default_factory=list)
    notifications_channels: list[str] = Field(default_factory=lambda: ["eventbridge", "sns"])
