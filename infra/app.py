#!/usr/bin/env python3
"""CDK app entrypoint (run as `python -m infra.app` from the repo root).

Three stacks:
  * OidcStack     — GitHub Actions OIDC provider + deploy role. Deployed once
                    from a laptop (chicken-and-egg: CI can't assume a role that
                    doesn't exist yet). Rarely changed.
  * CoreStack     — everything the framework needs to run (docs/architecture.md §3, §9).
  * FixturesStack — demo-only resources; empty until Phase 7.
"""

import os

import aws_cdk as cdk

from infra.stacks.core_stack import CoreStack
from infra.stacks.fixtures_stack import FixturesStack
from infra.stacks.oidc_stack import OidcStack

# Single-account POC, us-east-1 only (docs/scope-poc.md §2, architecture.md §1).
# A concrete account is required because CoreStack reads the Powertools layer ARN
# via an SSM context lookup, which can't run against an environment-agnostic
# stack. The resolved value is cached in the committed cdk.context.json, so CI
# (no credentials) synthesizes from cache without hitting AWS. Override the
# account with CDK_DEFAULT_ACCOUNT for a different account (regenerate the cache
# with `make refresh-powertools`).
POC_ACCOUNT = "155936382216"
ENV = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT", POC_ACCOUNT),
    region="us-east-1",
)

# Applied to every resource in every stack (build-plan Phase 2 safety rules).
TAGS = {"Project": "Tidewater", "Environment": "POC"}

# Where budget alerts and SNS notifications are sent. Defaults to the email that
# owns the AWS account; override via `cdk ... -c notification_email=...` or the
# committed cdk.context.json.
DEFAULT_NOTIFICATION_EMAIL = "shreyashkalalwork@gmail.com"


def main() -> None:
    app = cdk.App()

    notification_email = app.node.try_get_context("notification_email") or (
        DEFAULT_NOTIFICATION_EMAIL
    )

    OidcStack(app, "PlatformHygiene-Oidc", env=ENV)
    CoreStack(app, "PlatformHygiene-Core", env=ENV, notification_email=notification_email)
    FixturesStack(app, "PlatformHygiene-Fixtures", env=ENV)  # no direct dep; SSM lookup later

    for key, value in TAGS.items():
        cdk.Tags.of(app).add(key, value)

    app.synth()


if __name__ == "__main__":
    main()
