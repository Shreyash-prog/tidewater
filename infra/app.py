#!/usr/bin/env python3
"""CDK app entrypoint.

Two stacks (docs/architecture.md §9):
  * CoreStack     — everything the framework needs to run.
  * FixturesStack — demo-only resources; no direct dependency on CoreStack.

Both are intentionally empty in Phase 1; resources arrive in Phase 2.
"""

import aws_cdk as cdk

from stacks.core_stack import CoreStack
from stacks.fixtures_stack import FixturesStack


def main() -> None:
    app = cdk.App()
    CoreStack(app, "PlatformHygiene-Core")
    FixturesStack(app, "PlatformHygiene-Fixtures")  # no direct dep; uses SSM lookup later
    app.synth()


if __name__ == "__main__":
    main()
