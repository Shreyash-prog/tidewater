"""FixturesStack — demo-only resources.

Empty in Phase 1 (repo skeleton). Phase 7 fills this in with ~100 stub Lambda
functions, ~30 IAM roles with violation patterns, 5 access keys, and a bootstrap
Lambda that seeds 90 days of synthetic metric history. Has no direct dependency
on CoreStack — it reads shared values via SSM lookup so it can be destroyed alone
(docs/architecture.md §9).
"""

from typing import Any

from aws_cdk import Stack
from constructs import Construct


class FixturesStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: Any) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # Resources added in Phase 7.
