"""Tests for the iam.stale_access_key detector (hand-built clients)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from detectors.iam.detectors.stale_access_key import StaleAccessKeyDetector
from shared.models import Severity

ACCOUNT = "111111111111"
REGION = "us-east-1"


def _ago(days: float) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


def _detector(
    make_iam: Callable[..., MagicMock],
    *,
    status: str = "Active",
    create_days: float,
    last_used_days: float | None,
    idle_days: int = 7,
    tags: dict[str, str] | None = None,
) -> StaleAccessKeyDetector:
    last_used = (
        {"AccessKeyLastUsed": {"LastUsedDate": _ago(last_used_days)}}
        if last_used_days is not None
        else {"AccessKeyLastUsed": {}}
    )
    client = make_iam(
        pages={"list_users": [{"Users": [{"UserName": "u"}]}]},
        list_access_keys={
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAEXAMPLE", "Status": status, "CreateDate": _ago(create_days)}
            ]
        },
        list_user_tags={"Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()]},
        get_access_key_last_used=last_used,
    )
    return StaleAccessKeyDetector(ACCOUNT, REGION, {"idle_days": idle_days}, iam_client=client)


def test_never_used_old_key_flagged_high(make_iam: Callable[..., MagicMock]) -> None:
    findings = list(_detector(make_iam, create_days=30, last_used_days=None).scan())
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].details["last_used_date"] is None
    assert findings[0].details["access_key_id"] == "AKIAEXAMPLE"


def test_never_used_recent_key_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    assert list(_detector(make_iam, create_days=3, last_used_days=None).scan()) == []


def test_recently_used_key_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    assert list(_detector(make_iam, create_days=100, last_used_days=2).scan()) == []


def test_stale_used_key_flagged_medium(make_iam: Callable[..., MagicMock]) -> None:
    findings = list(_detector(make_iam, create_days=100, last_used_days=30).scan())
    assert len(findings) == 1 and findings[0].severity is Severity.MEDIUM


def test_exactly_at_threshold_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    assert list(_detector(make_iam, create_days=100, last_used_days=7, idle_days=7).scan()) == []


def test_inactive_key_not_flagged(make_iam: Callable[..., MagicMock]) -> None:
    keys = list(_detector(make_iam, status="Inactive", create_days=365, last_used_days=None).scan())
    assert keys == []


def test_missing_idle_days_skips_run(make_iam: Callable[..., MagicMock]) -> None:
    client = make_iam(pages={"list_users": [{"Users": [{"UserName": "u"}]}]})
    detector = StaleAccessKeyDetector(ACCOUNT, REGION, {}, iam_client=client)
    assert list(detector.scan()) == []


def test_user_tags_included_in_details(make_iam: Callable[..., MagicMock]) -> None:
    finding = next(
        iter(
            _detector(
                make_iam, create_days=30, last_used_days=None, tags={"Environment": "nonprod"}
            ).scan()
        )
    )
    assert finding.details["tags"] == {"Environment": "nonprod"}
