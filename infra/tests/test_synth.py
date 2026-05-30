"""Synthesis smoke test: the CDK app must synthesize both stacks cleanly.

In Phase 1 the stacks are empty; this proves the app wiring and `cdk synth`
toolchain work. Phase 2 will grow this into a real template snapshot test.
"""

import aws_cdk as cdk
from aws_cdk import assertions

from stacks.core_stack import CoreStack
from stacks.fixtures_stack import FixturesStack


def test_stacks_synthesize() -> None:
    app = cdk.App()
    core = CoreStack(app, "TestCore")
    fixtures = FixturesStack(app, "TestFixtures")

    # Both produce a valid (empty) CloudFormation template without error.
    assert isinstance(assertions.Template.from_stack(core).to_json(), dict)
    assert isinstance(assertions.Template.from_stack(fixtures).to_json(), dict)
