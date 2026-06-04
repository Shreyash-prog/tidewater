"""Tests for the lambda.unused_function detector.

moto doesn't model CloudWatch Invocations metrics, so the detector is driven with
hand-built fake lambda + cloudwatch clients whose paginators and metric responses
we control precisely (the same approach as the IAM detector tests).
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from detectors.lambda_.detectors.unused_function import UnusedFunctionDetector
from shared.models import Severity

ACCOUNT = "111111111111"
REGION = "us-east-1"


def _arn(name: str) -> str:
    return f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"


def _function(name: str) -> dict[str, Any]:
    return {
        "FunctionName": name,
        "FunctionArn": _arn(name),
        "Runtime": "python3.12",
        "LastModified": "2026-01-01T00:00:00.000+0000",
        "CodeSize": 4096,
        "MemorySize": 128,
    }


def _make_clients(
    *,
    pages: list[dict[str, Any]],
    invocations: dict[str, list[float]],
    tags: dict[str, dict[str, str]] | None = None,
) -> tuple[MagicMock, MagicMock]:
    """Build (lambda_client, cloudwatch_client).

    `invocations` maps function name -> the list of per-datapoint Sum values the
    CloudWatch GetMetricStatistics call returns for it (empty list == never
    invoked). `tags` maps function ARN -> tag dict.
    """
    tags = tags or {}
    lam = MagicMock()

    paginator = MagicMock()
    paginator.paginate = MagicMock(return_value=pages)
    lam.get_paginator = MagicMock(return_value=paginator)
    lam.list_tags = MagicMock(side_effect=lambda Resource: {"Tags": tags.get(Resource, {})})

    cw = MagicMock()

    def _get_metric_statistics(**kwargs: Any) -> dict[str, Any]:
        (dimension,) = kwargs["Dimensions"]
        name = dimension["Value"]
        return {"Datapoints": [{"Sum": v} for v in invocations.get(name, [])]}

    cw.get_metric_statistics = MagicMock(side_effect=_get_metric_statistics)
    return lam, cw


def _detector(
    lam: MagicMock, cw: MagicMock, *, idle_days: int | None = 7
) -> UnusedFunctionDetector:
    threshold: dict[str, Any] = {} if idle_days is None else {"idle_days": idle_days}
    return UnusedFunctionDetector(
        ACCOUNT, REGION, threshold, lambda_client=lam, cloudwatch_client=cw
    )


def test_zero_invocations_is_flagged() -> None:
    lam, cw = _make_clients(
        pages=[{"Functions": [_function("idle-fn")]}],
        invocations={"idle-fn": [0.0, 0.0]},
    )
    findings = list(_detector(lam, cw).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].resource_arn == _arn("idle-fn")
    assert findings[0].details["invocations_in_window"] == 0
    assert findings[0].details["runtime"] == "python3.12"


def test_nonzero_invocations_not_flagged() -> None:
    lam, cw = _make_clients(
        pages=[{"Functions": [_function("busy-fn")]}],
        invocations={"busy-fn": [3.0, 0.0, 5.0]},
    )
    assert list(_detector(lam, cw).scan()) == []


def test_never_invoked_no_datapoints_is_flagged() -> None:
    # A function CloudWatch has no datapoints for (never invoked) sums to 0.
    lam, cw = _make_clients(
        pages=[{"Functions": [_function("never-fn")]}],
        invocations={"never-fn": []},
    )
    findings = list(_detector(lam, cw).scan())
    assert len(findings) == 1
    assert findings[0].details["function_name"] == "never-fn"


@pytest.mark.parametrize("idle_days", [7, 30])
def test_window_math_matches_threshold(idle_days: int) -> None:
    lam, cw = _make_clients(
        pages=[{"Functions": [_function("idle-fn")]}],
        invocations={"idle-fn": []},
    )
    before = datetime.now(UTC)
    list(_detector(lam, cw, idle_days=idle_days).scan())
    after = datetime.now(UTC)

    (_, kwargs) = cw.get_metric_statistics.call_args
    assert kwargs["Period"] == 86400
    assert kwargs["Statistics"] == ["Sum"]
    window = kwargs["EndTime"] - kwargs["StartTime"]
    # The window is idle_days wide (within the test's wall-clock slop).
    assert abs(window - timedelta(days=idle_days)) < (after - before) + timedelta(seconds=1)


def test_tags_propagated_from_list_tags() -> None:
    lam, cw = _make_clients(
        pages=[{"Functions": [_function("idle-fn")]}],
        invocations={"idle-fn": []},
        tags={_arn("idle-fn"): {"Environment": "nonprod", "team": "platform"}},
    )
    findings = list(_detector(lam, cw).scan())
    assert findings[0].details["tags"] == {"Environment": "nonprod", "team": "platform"}


def test_missing_idle_days_raises() -> None:
    lam, cw = _make_clients(pages=[{"Functions": []}], invocations={})
    with pytest.raises(ValueError, match="requires threshold.idle_days"):
        list(_detector(lam, cw, idle_days=None).scan())


def test_pagination_checks_every_function() -> None:
    page1 = {"Functions": [_function(f"fn-{i}") for i in range(50)]}
    page2 = {"Functions": [_function(f"fn-{i}") for i in range(50, 60)]}
    # Half idle (no datapoints), half busy.
    invocations = {f"fn-{i}": ([] if i % 2 == 0 else [1.0]) for i in range(60)}
    lam, cw = _make_clients(pages=[page1, page2], invocations=invocations)

    findings = list(_detector(lam, cw).scan())
    assert cw.get_metric_statistics.call_count == 60  # every function checked
    assert {f.details["function_name"] for f in findings} == {f"fn-{i}" for i in range(0, 60, 2)}
