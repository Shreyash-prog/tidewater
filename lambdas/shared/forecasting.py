"""Trend forecasting for quota-shaped rules (single model + guards).

The model is deliberately simple: a linear regression over the most recent
``fit_days`` data points (default 7). Four guards decide whether that numeric
forecast is meaningful — only ``numeric`` ever escalates to a forecast finding:

* ``insufficient_data`` — fewer than ``fit_days`` points in the window.
* ``stable`` — values barely move (low variance), or the trend is flat/decreasing.
* ``no_clear_trend`` — the linear fit is too noisy (R^2 < 0.5).
* ``numeric`` — a clean, rising fit; a breach projection is emitted.

Stdlib-only math (no numpy/scipy): regression over 7 points is a few sums.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

_METHOD = "last_7_days_linear"
_STABLE_STDEV = 0.5  # population stdev below this == "not moving"
_MIN_R_SQUARED = 0.5  # below this == too noisy to trust


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _pstdev(values: list[float]) -> float:
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    return (sum((v - mean) ** 2 for v in values) / n) ** 0.5


def _linear_fit(points: list[tuple[float, float]]) -> tuple[float, float, float] | None:
    """Return (slope, intercept, r_squared), or None if x has no spread."""
    n = len(points)
    sum_x = sum(x for x, _ in points)
    sum_y = sum(y for _, y in points)
    sum_xy = sum(x * y for x, y in points)
    sum_xx = sum(x * x for x, _ in points)
    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:  # all x equal — no spread to fit a line through
        return None
    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n
    mean_y = sum_y / n
    ss_tot = sum((y - mean_y) ** 2 for _, y in points)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in points)
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    return slope, intercept, r_squared


def _confidence(r_squared: float) -> str:
    if r_squared > 0.9:
        return "high"
    if r_squared >= 0.7:
        return "medium"
    return "low"


def compute_forecast(
    history: list[dict[str, Any]],
    current_value: float,
    quota: float,
    window_days: int = 14,
    fit_days: int = 7,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply the single-model + guards forecast logic to a metric history.

    `history` is a list of metric_history rows (each with an ISO `sk` timestamp
    and a numeric `value`), in any order. Returns the forecast dict documented in
    the module docstring; see CLAUDE.md "Forecasting".
    """
    now = now or datetime.now(UTC)
    result: dict[str, Any] = {
        "status": "insufficient_data",
        "rate_per_day": None,
        "days_to_breach": None,
        "projected_breach_at": None,
        "confidence": None,
        "method": _METHOD,
        "r_squared": None,
        "data_points_used": 0,
    }

    # 1. Keep only points within the window, sorted oldest-first.
    cutoff = now - timedelta(days=window_days)
    points: list[tuple[datetime, float]] = []
    for row in history:
        ts = _parse_ts(row.get("sk"))
        if ts is None or ts < cutoff:
            continue
        try:
            points.append((ts, float(row["value"])))
        except (KeyError, TypeError, ValueError):
            continue
    points.sort(key=lambda p: p[0])

    # 2. Insufficient data.
    if len(points) < fit_days:
        result["data_points_used"] = len(points)
        return result

    # 3. Fit the most recent `fit_days` points (x = days since the window start).
    fit = points[-fit_days:]
    result["data_points_used"] = len(fit)
    values = [v for _, v in fit]

    # 4. Stable: values barely move.
    if _pstdev(values) < _STABLE_STDEV:
        result["status"] = "stable"
        return result

    t0 = fit[0][0]
    xy = [(((ts - t0).total_seconds() / 86400.0), v) for ts, v in fit]
    fit_result = _linear_fit(xy)
    if fit_result is None:
        result["status"] = "no_clear_trend"
        return result
    slope, _intercept, r_squared = fit_result
    result["r_squared"] = round(r_squared, 4)

    # 5. No clear trend: fit too noisy.
    if r_squared < _MIN_R_SQUARED:
        result["status"] = "no_clear_trend"
        return result

    # 6. Stable: never forecast a breach for a flat/decreasing trend.
    if slope <= 0:
        result["status"] = "stable"
        return result

    # 7. Numeric forecast.
    days_to_breach = (quota - current_value) / slope
    projected = now + timedelta(days=days_to_breach)
    result.update(
        {
            "status": "numeric",
            "rate_per_day": slope,
            "days_to_breach": days_to_breach,
            "projected_breach_at": projected.isoformat(),
            "confidence": _confidence(r_squared),
            # Already over quota — the current-state finding should also fire.
            "already_breached": days_to_breach < 0,
        }
    )
    return result
