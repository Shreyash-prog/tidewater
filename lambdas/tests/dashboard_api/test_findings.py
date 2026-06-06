"""Findings route tests (moto-backed)."""

from typing import Any
from urllib.parse import quote

from dashboard_api.routes import findings as fr

PK = "111#us-east-1#iam"
SK = "arn:aws:iam::111:role/r#iam.unused_role"


def _list_event(**params: str) -> dict[str, Any]:
    return {"queryStringParameters": params or None}


def _detail_event(pk: str, sk: str) -> dict[str, Any]:
    return {"pathParameters": {"pk": quote(pk, safe=""), "sk": quote(sk, safe="")}}


def test_list_findings_returns_all(aws: Any) -> None:
    aws.put_finding(aws.findings)
    result = fr.list_findings(_list_event())
    assert result["count"] == 1
    assert result["items"][0]["rule_id"] == "iam.unused_role"
    # Decimal coerced to a JSON-safe number.
    assert result["items"][0]["details"]["days_idle"] == 42


def test_list_findings_filters_by_severity(aws: Any) -> None:
    aws.put_finding(aws.findings)  # high
    aws.put_finding(
        aws.findings,
        sk="arn:aws:iam::111:role/x#iam.unused_role",
        resource_arn="arn:aws:iam::111:role/x",
        severity="medium",
    )
    high = fr.list_findings(_list_event(severity="high"))
    assert high["count"] == 1
    assert high["items"][0]["severity"] == "high"


def test_list_findings_filters_by_status_reserved_word(aws: Any) -> None:
    aws.put_finding(aws.findings)  # open
    aws.put_finding(
        aws.findings,
        sk="arn:aws:iam::111:role/y#iam.unused_role",
        resource_arn="arn:aws:iam::111:role/y",
        status="resolved",
    )
    result = fr.list_findings(_list_event(status="resolved"))
    assert result["count"] == 1
    assert result["items"][0]["status"] == "resolved"


def test_list_findings_pagination_token_roundtrips(aws: Any) -> None:
    for i in range(5):
        aws.put_finding(
            aws.findings,
            sk=f"arn:aws:iam::111:role/r{i}#iam.unused_role",
            resource_arn=f"arn:aws:iam::111:role/r{i}",
        )
    page1 = fr.list_findings(_list_event(limit="2"))
    assert page1["count"] == 2
    assert "next_token" in page1
    page2 = fr.list_findings(_list_event(limit="2", next_token=page1["next_token"]))
    assert page2["count"] >= 1


def test_get_finding_returns_item(aws: Any) -> None:
    aws.put_finding(aws.findings)
    result = fr.get_finding(_detail_event(PK, SK))
    assert result["pk"] == PK and result["sk"] == SK


def test_get_finding_not_found(aws: Any) -> None:
    result = fr.get_finding(_detail_event(PK, "missing#rule"))
    assert result == {"error": "finding not found"}


def test_get_finding_audit_filters_by_identity(aws: Any) -> None:
    import json

    lines = [
        json.dumps(
            {
                "finding_pk": PK,
                "finding_sk": SK,
                "event_type": "policy_decided",
                "timestamp": "2026-06-01T00:00:00Z",
            }
        ),
        json.dumps(
            {
                "finding_pk": "other",
                "finding_sk": "other",
                "event_type": "x",
                "timestamp": "2026-06-02T00:00:00Z",
            }
        ),
    ]
    aws.s3.put_object(
        Bucket="audit-test", Key="audit/2026/06/01/00/a.jsonl", Body=("\n".join(lines)).encode()
    )
    result = fr.get_finding_audit(_detail_event(PK, SK))
    assert result["count"] == 1
    assert result["items"][0]["event_type"] == "policy_decided"


def test_get_finding_snapshot_presigned_url(aws: Any) -> None:
    aws.put_finding(aws.findings, snapshot_s3_key="iam/role/r/ts.json")
    aws.s3.put_object(Bucket="snapshots-test", Key="iam/role/r/ts.json", Body=b"{}")
    result = fr.get_finding_snapshot(_detail_event(PK, SK))
    assert result["expires_in"] == 300
    assert "iam/role/r/ts.json" in result["url"]


def test_get_finding_snapshot_absent(aws: Any) -> None:
    aws.put_finding(aws.findings)  # no snapshot_s3_key
    result = fr.get_finding_snapshot(_detail_event(PK, SK))
    assert result == {"error": "no snapshot for this finding"}
