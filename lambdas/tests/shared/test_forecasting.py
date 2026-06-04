"""Unit tests for shared.forecasting.compute_forecast (single model + guards)."""

from datetime import UTC, datetime, timedelta
from typing import Any

from shared.forecasting import compute_forecast

NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)
QUOTA = 10.0


def _history(values: list[float], *, step_days: float = 1.0, end: datetime = NOW) -> list[dict]:
    """Daily-spaced rows ending at `end`, oldest first (value[0] is oldest)."""
    n = len(values)
    rows: list[dict[str, Any]] = []
    for i, v in enumerate(values):
        ts = end - timedelta(days=step_days * (n - 1 - i))
        rows.append({"sk": ts.isoformat(), "value": v})
    return rows


def test_empty_history_insufficient_data() -> None:
    result = compute_forecast([], current_value=5, quota=QUOTA, now=NOW)
    assert result["status"] == "insufficient_data"
    assert result["data_points_used"] == 0


def test_five_points_insufficient_data() -> None:
    result = compute_forecast(_history([5, 6, 7, 8, 9]), current_value=9, quota=QUOTA, now=NOW)
    assert result["status"] == "insufficient_data"


def test_seven_identical_points_stable() -> None:
    result = compute_forecast(_history([7] * 7), current_value=7, quota=QUOTA, now=NOW)
    assert result["status"] == "stable"
    assert result["data_points_used"] == 7


def test_low_variance_points_stable() -> None:
    # stdev well under 0.5 — "not moving".
    result = compute_forecast(
        _history([7, 7, 7, 7, 7, 7, 8]), current_value=7, quota=QUOTA, now=NOW
    )
    assert result["status"] == "stable"


def test_noisy_points_no_clear_trend() -> None:
    # High variance, no linear relationship → R^2 < 0.5.
    result = compute_forecast(
        _history([2, 9, 3, 8, 2, 9, 3]), current_value=3, quota=QUOTA, now=NOW
    )
    assert result["status"] == "no_clear_trend"
    assert result["r_squared"] is not None and result["r_squared"] < 0.5


def test_clean_rising_trend_numeric_high_confidence() -> None:
    # Perfectly linear +1/day → R^2 == 1.0 → high confidence.
    result = compute_forecast(
        _history([1, 2, 3, 4, 5, 6, 7]), current_value=7, quota=QUOTA, now=NOW
    )
    assert result["status"] == "numeric"
    assert result["confidence"] == "high"
    assert result["rate_per_day"] == 1.0
    # 3 left to quota at +1/day → ~3 days.
    assert abs(result["days_to_breach"] - 3.0) < 1e-6
    assert result["projected_breach_at"] is not None


def test_mild_noisy_rising_trend_numeric_medium_or_low() -> None:
    # Rising but noisy enough that 0.5 <= R^2 <= 0.9.
    result = compute_forecast(
        _history([2, 2, 4, 3, 5, 5, 7]), current_value=7, quota=QUOTA, now=NOW
    )
    assert result["status"] == "numeric"
    assert result["confidence"] in {"medium", "low"}


def test_decreasing_trend_stable() -> None:
    # Negative slope — we never forecast a breach for a falling count.
    result = compute_forecast(
        _history([9, 8, 7, 6, 5, 4, 3]), current_value=3, quota=QUOTA, now=NOW
    )
    assert result["status"] == "stable"


def test_all_timestamps_equal_no_clear_trend() -> None:
    rows = [{"sk": NOW.isoformat(), "value": float(v)} for v in [1, 3, 2, 5, 4, 6, 7]]
    result = compute_forecast(rows, current_value=7, quota=QUOTA, now=NOW)
    # Variance is high so not "stable"; zero x-spread → no line can be fit.
    assert result["status"] == "no_clear_trend"


def test_already_breached_numeric_flag_set() -> None:
    # Rising trend, current already at/over quota → negative days_to_breach.
    result = compute_forecast(
        _history([8, 9, 10, 11, 12, 13, 14]), current_value=14, quota=QUOTA, now=NOW
    )
    assert result["status"] == "numeric"
    assert result["days_to_breach"] < 0
    assert result["already_breached"] is True


def test_points_outside_window_are_dropped() -> None:
    # Seven points but spaced 5 days apart → only ~3 fall in the 14-day window.
    result = compute_forecast(
        _history([1, 2, 3, 4, 5, 6, 7], step_days=5.0), current_value=7, quota=QUOTA, now=NOW
    )
    assert result["status"] == "insufficient_data"
