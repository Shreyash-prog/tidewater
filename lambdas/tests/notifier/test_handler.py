"""End-to-end notifier handler tests (all external calls mocked)."""

from types import SimpleNamespace
from typing import Any

import pytest

from notifier import handler as nh

TOPIC = "arn:aws:sns:us-east-1:111:tidewater-notifications"


class _Spy:
    def __init__(self, return_value: Any = None) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self._return = return_value

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        return self._return


def _context() -> Any:
    return SimpleNamespace(
        function_name="notifier",
        memory_limit_in_mb=256,
        invoked_function_arn="arn:aws:lambda:us-east-1:111:function:notifier",
        aws_request_id="req-1",
    )


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("NOTIFICATIONS_TOPIC_ARN", TOPIC)
    monkeypatch.setenv("FINDINGS_TABLE", "findings-test")
    monkeypatch.setenv("STALENESS_DAYS", "7")
    sns_client = SimpleNamespace(publish=_Spy())
    monkeypatch.setattr(nh, "_sns", lambda: sns_client)
    monkeypatch.setattr(nh, "_findings_table", lambda: SimpleNamespace())
    claim = _Spy(return_value=True)
    monkeypatch.setattr(nh, "claim_notification_slot", claim)
    return SimpleNamespace(publish=sns_client.publish, claim=claim)


def _finding_event(detail_type: str, **detail: Any) -> dict[str, Any]:
    base = {
        "account": "111",
        "region": "us-east-1",
        "service": "iam",
        "resource_arn": "arn:aws:iam::111:policy/p",
        "rule_id": "iam.wildcard_policy",
        "severity": "high",
        "policy_decision": "prompt",
        "details": {},
    }
    base.update(detail)
    return {"detail-type": detail_type, "detail": base}


def test_worthy_event_claims_and_publishes(wired: Any) -> None:
    result = nh.handler(_finding_event("Finding.updated"), _context())
    assert result == {"sent": True, "event_type": "Finding.updated"}
    assert len(wired.claim.calls) == 1
    assert len(wired.publish.calls) == 1
    (_, kwargs) = wired.publish.calls[0]
    assert kwargs["TopicArn"] == TOPIC
    assert kwargs["Subject"].startswith("[Tidewater] HIGH")
    # The derived keys passed to dedupe match the composite finding key shape.
    (claim_args, _) = wired.claim.calls[0]
    _table, pk, sk = claim_args
    assert pk == "111#us-east-1#iam"
    assert sk == "arn:aws:iam::111:policy/p#iam.wildcard_policy"


def test_deduped_event_does_not_publish(wired: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nh, "claim_notification_slot", _Spy(return_value=False))
    result = nh.handler(_finding_event("Finding.updated"), _context())
    assert result == {"sent": False, "reason": "deduped"}
    assert wired.publish.calls == []


def test_filtered_event_does_not_claim_or_publish(wired: Any) -> None:
    # MEDIUM + prompt → filtered out before dedupe is even attempted.
    result = nh.handler(_finding_event("Finding.updated", severity="medium"), _context())
    assert result == {"sent": False, "reason": "filter"}
    assert wired.claim.calls == []
    assert wired.publish.calls == []


def test_remediation_failed_publishes_without_finding_model(wired: Any) -> None:
    event = {
        "detail-type": "remediation.failed",
        "detail": {
            "finding_pk": "111#us-east-1#iam",
            "finding_sk": "arn:aws:iam::111:role/r#iam.unused_role",
            "rule_id": "iam.unused_role",
            "resource_arn": "arn:aws:iam::111:role/r",
            "reason": "protected role — remediation refused",
        },
    }
    result = nh.handler(event, _context())
    assert result["sent"] is True
    (claim_args, _) = wired.claim.calls[0]
    _table, pk, sk = claim_args
    assert pk == "111#us-east-1#iam"
    assert sk == "arn:aws:iam::111:role/r#iam.unused_role"
    assert len(wired.publish.calls) == 1
