"""Synthesis smoke test: the CDK app must synthesize all stacks cleanly."""

import aws_cdk as cdk
from aws_cdk import assertions

from infra.stacks.core_stack import CoreStack
from infra.stacks.fixtures_stack import FixturesStack
from infra.stacks.oidc_stack import OidcStack

ENV = cdk.Environment(account="123456789012", region="us-east-1")


def test_stacks_synthesize() -> None:
    app = cdk.App()
    core = CoreStack(app, "TestCore", env=ENV)
    fixtures = FixturesStack(app, "TestFixtures", env=ENV)
    oidc = OidcStack(app, "TestOidc", env=ENV)

    assert isinstance(assertions.Template.from_stack(core).to_json(), dict)
    assert isinstance(assertions.Template.from_stack(fixtures).to_json(), dict)
    assert isinstance(assertions.Template.from_stack(oidc).to_json(), dict)
