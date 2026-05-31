"""Tests for the S3-backed rule loader (moto)."""

from typing import Any

import boto3
import pytest
from moto import mock_aws

from shared import rule_loader
from shared.models import PolicyAction

REGION = "us-east-1"
BUCKET = "tidewater-rules-test"

VALID_RULE = """\
rule: iam.unused_role
enabled: true
schedule: on-demand
threshold:
  idle_days: 7
forecast:
  enabled: false
policy:
  default: dry_run
notifications:
  channels: [eventbridge, sns]
"""

DISABLED_RULE = """\
rule: iam.stale_access_key
enabled: false
threshold:
  age_days: 90
"""

OTHER_SERVICE_RULE = """\
rule: lambda.idle_function
enabled: true
threshold:
  idle_days: 30
"""

MALFORMED_YAML = "rule: iam.broken\n  bad: : indentation\n:::"

INVALID_RULE = """\
rule: iam.no_threshold
enabled: true
"""


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("RULES_BUCKET", BUCKET)
    rule_loader.clear_cache()


def _seed_bucket(objects: dict[str, str]) -> None:
    s3: Any = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET)
    for key, body in objects.items():
        s3.put_object(Bucket=BUCKET, Key=key, Body=body.encode())


@mock_aws
def test_loads_enabled_iam_rule() -> None:
    _seed_bucket({"rules/iam.unused_role.yaml": VALID_RULE})

    rules = rule_loader.load_enabled_rules_for_service("iam")

    assert len(rules) == 1
    rule = rules[0]
    assert rule.rule_id == "iam.unused_role"
    assert rule.threshold == {"idle_days": 7}
    assert rule.policy_default is PolicyAction.DRY_RUN
    assert rule.notifications_channels == ["eventbridge", "sns"]


@mock_aws
def test_skips_disabled_and_other_service_rules() -> None:
    _seed_bucket(
        {
            "rules/iam.unused_role.yaml": VALID_RULE,
            "rules/iam.stale_access_key.yaml": DISABLED_RULE,
            "rules/lambda.idle_function.yaml": OTHER_SERVICE_RULE,
        }
    )

    rules = rule_loader.load_enabled_rules_for_service("iam")

    assert [r.rule_id for r in rules] == ["iam.unused_role"]


@mock_aws
def test_malformed_and_invalid_rules_are_skipped_not_fatal() -> None:
    _seed_bucket(
        {
            "rules/iam.unused_role.yaml": VALID_RULE,
            "rules/iam.broken.yaml": MALFORMED_YAML,
            "rules/iam.no_threshold.yaml": INVALID_RULE,
        }
    )

    # A bad rule must not crash the loader — the good one still loads.
    rules = rule_loader.load_enabled_rules_for_service("iam")

    assert [r.rule_id for r in rules] == ["iam.unused_role"]


@mock_aws
def test_results_are_cached() -> None:
    _seed_bucket({"rules/iam.unused_role.yaml": VALID_RULE})
    first = rule_loader.load_enabled_rules_for_service("iam")

    # Deleting the object should not change the cached result within the TTL.
    boto3.client("s3", region_name=REGION).delete_object(
        Bucket=BUCKET, Key="rules/iam.unused_role.yaml"
    )
    second = rule_loader.load_enabled_rules_for_service("iam")
    assert [r.rule_id for r in second] == [r.rule_id for r in first]
