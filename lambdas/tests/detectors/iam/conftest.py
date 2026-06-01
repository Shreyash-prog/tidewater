"""Shared helpers for IAM detector tests.

moto doesn't model IAM last-used / service-last-accessed data meaningfully (see
the Phase 3 note), so these tests drive the detectors with hand-built fake clients
whose paginators and method responses we control precisely.
"""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest


def _build_iam(pages: dict[str, list[dict[str, Any]]] | None = None, **methods: Any) -> MagicMock:
    """Build a fake IAM client.

    `pages` maps a paginator name (e.g. "list_roles") to the list of pages its
    `.paginate(...)` returns (kwargs ignored). `methods` maps a client method name
    to either a MagicMock (used as-is) or a plain value (wrapped as return_value).
    """
    pages = pages or {}
    client = MagicMock()

    def _get_paginator(name: str) -> MagicMock:
        paginator = MagicMock()
        paginator.paginate = MagicMock(return_value=pages.get(name, [{}]))
        return paginator

    client.get_paginator = MagicMock(side_effect=_get_paginator)
    for name, value in methods.items():
        setattr(
            client, name, value if isinstance(value, MagicMock) else MagicMock(return_value=value)
        )
    return client


@pytest.fixture
def make_iam() -> Callable[..., MagicMock]:
    return _build_iam
