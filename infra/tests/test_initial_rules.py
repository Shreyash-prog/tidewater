"""Guardrail for the shipped POC rule YAML.

The POC rule deliberately uses aggressive, production-unsafe demo values
(idle_days: -1, grace_period_days: 0). These tests pin those values so the demo
keeps working AND so the production boundaries stay an explicit, reviewed choice
(see README "POC vs Production"). The rule isn't part of the synthesized template
(it ships as a BucketDeployment asset), so it's validated here from the file.
"""

from pathlib import Path

import yaml

from shared.rule_loader import _to_rule

POC_RULE = Path(__file__).resolve().parents[1] / "initial_rules" / "iam.unused_role.yaml"


def test_poc_rule_uses_aggressive_demo_threshold() -> None:
    raw = yaml.safe_load(POC_RULE.read_text())
    # POC-only: flags any role idle >= 0 days so the demo runs in seconds.
    assert raw["threshold"]["idle_days"] == -1
    # POC-only: no grace window before auto-remediation.
    assert raw["grace_period_days"] == 0


def test_poc_rule_parses_into_a_valid_rule() -> None:
    rule = _to_rule(yaml.safe_load(POC_RULE.read_text()))
    assert rule.rule_id == "iam.unused_role"
    assert rule.threshold == {"idle_days": -1}
    assert rule.grace_period_days == 0
