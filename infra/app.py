#!/usr/bin/env python3
"""CDK app entrypoint (run as `python -m infra.app` from the repo root).

Three stacks:
  * OidcStack     — GitHub Actions OIDC provider + deploy role. Deployed once
                    from a laptop (chicken-and-egg: CI can't assume a role that
                    doesn't exist yet). Rarely changed.
  * CoreStack     — everything the framework needs to run (docs/architecture.md §3, §9).
  * FixturesStack — demo-only resources; empty until Phase 7.
"""

import aws_cdk as cdk

from infra.stacks.core_stack import CoreStack
from infra.stacks.fixtures_stack import FixturesStack
from infra.stacks.oidc_stack import OidcStack

# us-east-1 only (docs/architecture.md §1). Account is resolved from the
# deploying environment at synth/deploy time; left unset so `cdk synth` works
# without credentials in CI.
ENV = cdk.Environment(region="us-east-1")

# Applied to every resource in every stack (build-plan Phase 2 safety rules).
TAGS = {"Project": "Tidewater", "Environment": "POC"}


def main() -> None:
    app = cdk.App()

    OidcStack(app, "PlatformHygiene-Oidc", env=ENV)
    CoreStack(app, "PlatformHygiene-Core", env=ENV)
    FixturesStack(app, "PlatformHygiene-Fixtures", env=ENV)  # no direct dep; SSM lookup later

    for key, value in TAGS.items():
        cdk.Tags.of(app).add(key, value)

    app.synth()


if __name__ == "__main__":
    main()
