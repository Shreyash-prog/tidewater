"""Approval decision route tests (moto-backed; remediator invoke + events mocked)."""

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from dashboard_api.routes import approvals as ap

PK = "111#us-east-1#iam"
SK = "arn:aws:iam::111:role/r#iam.unused_role"


class _Spy:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"StatusCode": 202}


@pytest.fixture
def wired(aws: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    spy = _Spy()
    monkeypatch.setattr(ap, "_lambda_client", lambda: spy)
    emit_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(ap, "emit_event", lambda *a, **k: emit_calls.append((a, k)))
    aws.invoke_spy = spy
    aws.emit_calls = emit_calls
    return aws


def _seed(aws: Any, *, status: str = "pending", pk: str = PK, sk: str = SK) -> str:
    approval_id = ap.approval_id_for(pk, sk)
    now = datetime.now(UTC).isoformat()
    aws.approvals.put_item(
        Item={
            "approval_id": approval_id,
            "metadata": "metadata",
            "finding_pk": pk,
            "finding_sk": sk,
            "requested_at": now,
            "status": status,
        }
    )
    aws.put_finding(aws.findings, pk=pk, sk=sk, status="open", policy_decision="prompt")
    return approval_id


def _event(approval_id: str, body: dict[str, Any]) -> dict[str, Any]:
    return {"pathParameters": {"approval_id": approval_id}, "body": json.dumps(body)}


def _ok(result: Any) -> dict[str, Any]:
    assert isinstance(result, dict), f"expected 200 dict, got {result!r}"
    return result


def _err(result: Any) -> tuple[dict[str, Any], int]:
    assert isinstance(result, tuple), f"expected (body, status) tuple, got {result!r}"
    return result


def test_approve_happy_path(wired: Any) -> None:
    aid = _seed(wired)
    result = _ok(ap.decide(_event(aid, {"action": "approve", "approver": "alice"})))
    assert result["status"] == "approved"
    assert result["decided_by"] == "alice"

    approval = wired.approvals.get_item(Key={"approval_id": aid, "metadata": "metadata"})["Item"]
    assert approval["status"] == "approved"
    finding = wired.findings.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert finding["status"] == "in_remediation"
    assert finding["decision_reason"] == "approved by alice"
    # Remediator invoked async (fire-and-forget).
    assert len(wired.invoke_spy.calls) == 1
    assert wired.invoke_spy.calls[0]["InvocationType"] == "Event"
    assert wired.invoke_spy.calls[0]["FunctionName"] == "remediator-test"
    # Audit record written to S3 + event emitted.
    audit = wired.s3.list_objects_v2(Bucket="audit-test", Prefix="audit/")
    assert audit.get("KeyCount", 0) >= 1
    assert wired.emit_calls and wired.emit_calls[0][0][0] == "Approval.granted"


def test_reject_happy_path(wired: Any) -> None:
    aid = _seed(wired)
    result = _ok(ap.decide(_event(aid, {"action": "reject", "approver": "bob"})))
    assert result["status"] == "rejected"
    finding = wired.findings.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert finding["status"] == "skipped"
    assert finding["decision_reason"] == "rejected by bob: no reason given"
    # No remediation on reject.
    assert wired.invoke_spy.calls == []
    assert wired.emit_calls[0][0][0] == "Approval.denied"


def test_reject_with_reason_stores_reason(wired: Any) -> None:
    aid = _seed(wired)
    result = _ok(
        ap.decide(_event(aid, {"action": "reject", "approver": "bob", "reason": "legit prod role"}))
    )
    assert result["reason"] == "legit prod role"
    approval = wired.approvals.get_item(Key={"approval_id": aid, "metadata": "metadata"})["Item"]
    assert approval["reason"] == "legit prod role"
    finding = wired.findings.get_item(Key={"pk": PK, "sk": SK})["Item"]
    assert finding["decision_reason"] == "rejected by bob: legit prod role"


def test_duplicate_approve_returns_409(wired: Any) -> None:
    aid = _seed(wired, status="approved")
    body, status = _err(ap.decide(_event(aid, {"action": "approve", "approver": "alice"})))
    assert status == 409
    assert body["status"] == "approved"
    assert wired.invoke_spy.calls == []  # no second remediation


def test_duplicate_reject_returns_409(wired: Any) -> None:
    aid = _seed(wired, status="rejected")
    body, status = _err(ap.decide(_event(aid, {"action": "reject", "approver": "bob"})))
    assert status == 409


def test_missing_approver_returns_400(wired: Any) -> None:
    aid = _seed(wired)
    body, status = _err(ap.decide(_event(aid, {"action": "approve", "approver": "  "})))
    assert status == 400


def test_approver_too_long_returns_400(wired: Any) -> None:
    aid = _seed(wired)
    body, status = _err(ap.decide(_event(aid, {"action": "approve", "approver": "x" * 101})))
    assert status == 400


def test_reason_too_long_returns_400(wired: Any) -> None:
    aid = _seed(wired)
    body, status = _err(
        ap.decide(_event(aid, {"action": "reject", "approver": "bob", "reason": "x" * 201}))
    )
    assert status == 400


def test_invalid_action_returns_400(wired: Any) -> None:
    aid = _seed(wired)
    body, status = _err(ap.decide(_event(aid, {"action": "maybe", "approver": "bob"})))
    assert status == 400


def test_approval_not_found_returns_404(wired: Any) -> None:
    body, status = _err(
        ap.decide(_event("appr_doesnotexist", {"action": "approve", "approver": "a"}))
    )
    assert status == 404


def test_approval_id_mismatch_returns_500(wired: Any) -> None:
    # Seed an approval whose stored finding identity does not hash to its id.
    wired.approvals.put_item(
        Item={
            "approval_id": "appr_tampered000000000000",
            "metadata": "metadata",
            "finding_pk": PK,
            "finding_sk": SK,
            "status": "pending",
        }
    )
    body, status = _err(
        ap.decide(_event("appr_tampered000000000000", {"action": "approve", "approver": "a"}))
    )
    assert status == 500


def test_approve_drops_any_reason(wired: Any) -> None:
    aid = _seed(wired)
    result = _ok(
        ap.decide(_event(aid, {"action": "approve", "approver": "alice", "reason": "ignored"}))
    )
    assert result["reason"] is None
