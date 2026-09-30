"""Focused contracts for the #2165 private operator task."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "issue_2165_sidecar_operator", ROOT / "scripts/issue_2165_sidecar_operator.py"
)
assert SPEC and SPEC.loader
operator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator)


@pytest.fixture(autouse=True)
def config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CORELINK_INTERNAL_AUTH_KEY", "i" * 40)
    monkeypatch.setenv("CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY", "a" * 40)
    monkeypatch.setenv("ISSUE_2165_RUN_ID", "123456789")
    monkeypatch.setenv("ISSUE_2165_TARGET_DEPLOYMENT_SHA", "a" * 40)
    monkeypatch.setenv("ISSUE_2165_TENANTS_JSON", '["tenant-stage-one","tenant-stage-two"]')
    monkeypatch.setenv("ISSUE_2165_PAT_A", "pat-a-" + "1" * 40)
    monkeypatch.setenv("ISSUE_2165_PAT_B", "pat-b-" + "2" * 40)
    monkeypatch.setenv("ISSUE_2165_STORAGE_QUOTA_BYTES", "1048576")
    monkeypatch.setenv("ISSUE_2165_APP_ORIGIN", "http://10.20.30.40:50051")
    monkeypatch.setenv("ISSUE_2165_CMK_KEY_ID", "arn:aws:kms:us-east-1:123456789012:key/staging")
    monkeypatch.setenv("ISSUE_2165_CMK_REGION", "us-east-1")
    monkeypatch.setenv("ISSUE_2165_TCS_WRAPPED_B64_A", base64.b64encode(b"wrapped-test-ciphertext-a").decode())
    monkeypatch.setenv("ISSUE_2165_TCS_WRAPPED_B64_B", base64.b64encode(b"wrapped-test-ciphertext-b").decode())
    state_dir = tmp_path / "issue-2165"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    monkeypatch.setattr(operator, "CAS_STATE_DIR", str(state_dir))
    monkeypatch.setattr(operator, "CAS_STATE_PATH", str(state_dir / "objects.json"))


class Response:
    def __init__(self, status: int, body: bytes = b"ok") -> None:
        self.status = status
        self.body = body

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        return self.body[:amount]


def test_admission_uses_exact_v2_scenario_signature_and_unique_nonce() -> None:
    cas = operator._admission("cas", now_ms=1_000)
    byok = operator._admission("byok", now_ms=1_000)
    assert cas != operator._admission("cas", now_ms=1_000)
    payload, tag = cas.rsplit(".", 1)
    expected = hmac.new(
        b"a" * 40,
        b"corelink/staging-load-admission-auth/v2\0" + payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(tag, expected)
    assert payload.startswith("v2.123456789.cas.staging." + "a" * 40 + ".1000.61000.")
    assert ".byok." in byok


def test_blake3_matches_standard_vectors() -> None:
    assert blake3(b"").hexdigest() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert blake3(b"abc").hexdigest() == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"


def _route_fake(requests: list[object], store: dict[str, bytes]):
    def send(request, timeout):
        requests.append(request)
        assert timeout == operator.TIMEOUT_SECONDS
        path = request.full_url.removeprefix("http://10.20.30.40:50051")
        method = request.method
        if path.startswith("/v1/admin/byok/activate"):
            return Response(202, b"accepted")
        if path.startswith("/v1/admin/byok/deactivate"):
            return Response(200, b"cancelled")
        if method == "PUT":
            store[path] = request.data
            return Response(201, path.rsplit("/", 1)[1].encode())
        if method == "GET" and path.startswith("/v1/cas/tenant-stage-one/") and request.get_header("Authorization") == "Bearer pat-b-" + "2" * 40:
            return Response(403, b"cross-tenant")
        if method == "GET" and path in store:
            return Response(200, store[path])
        if method == "DELETE":
            store.pop(path, None)
            return Response(204, b"")
        if method == "GET":
            return Response(404, b"not found")
        raise AssertionError("unexpected request")

    return send


def test_lifecycle_roundtrips_each_tenant_and_rejects_cross_tenant_read() -> None:
    calls: list[object] = []
    store: dict[str, bytes] = {}
    with patch.object(operator, "urlopen", _route_fake(calls, store)):
        rows = operator.run_phase("lifecycle")
    assert len(calls) == 7
    assert [row["step"] for row in rows] == ["activate", "activate", "cas-put", "cas-get", "cas-put", "cas-get", "cross-tenant-deny"]
    for row in rows[:2]:
        started = datetime.fromisoformat(row["request_started_at_utc"].replace("Z", "+00:00"))
        observed = datetime.fromisoformat(row["observed_at_utc"].replace("Z", "+00:00"))
        assert started.tzinfo == timezone.utc and observed.tzinfo == timezone.utc
        assert 0 <= (observed - started).total_seconds() <= operator.TIMEOUT_SECONDS + 1
        assert row["request_body_sha256"] == hashlib.sha256(
            json.dumps({
                "mode": "byok", "crypto_mode": "convergent", "cmk_provider": "aws",
                "cmk_key_id": os.environ["ISSUE_2165_CMK_KEY_ID"], "cmk_region": "us-east-1",
                "tcs_wrapped_b64": os.environ[f"ISSUE_2165_TCS_WRAPPED_B64_{'A' if row['slot'] == 'tenant_a' else 'B'}"],
                "tenant": json.loads(os.environ["ISSUE_2165_TENANTS_JSON"])[0 if row["slot"] == "tenant_a" else 1],
            }, separators=(",", ":")).encode()
        ).hexdigest()
    assert rows[-1]["status"] == 403
    assert rows[-1]["slot"] == "tenant_b_to_a"
    assert all("tenant-stage" not in json.dumps(row) for row in rows)
    put_requests = [request for request in calls if request.method == "PUT"]
    assert len(put_requests) == 2
    for index, request in enumerate(put_requests):
        assert request.get_header("X-corelink-tenant-id") == f"tenant-stage-{'one' if index == 0 else 'two'}"
        assert request.get_header("X-corelink-scope") == "cas:rw"
        assert request.get_header("X-corelink-storage-quota-bytes") == "1048576"
        assert request.get_header("X-corelink-staging-load-admission").startswith("v2.123456789.cas.staging.")
        path_hash = request.full_url.rsplit("/", 1)[1]
        assert path_hash == blake3(request.data).hexdigest()
    b_cross = calls[-1]
    assert b_cross.method == "GET"
    assert b_cross.get_header("X-corelink-tenant-id") == "tenant-stage-two"
    assert b_cross.get_header("Authorization") == "Bearer pat-b-" + "2" * 40
    state = Path(operator.CAS_STATE_PATH)
    assert state.stat().st_mode & 0o777 == 0o600
    saved = json.loads(state.read_text())
    assert saved["schema"] == "corelink.issue-2165-cas-cleanup.v1"
    assert len(saved["objects"]) == 2


def test_cleanup_deletes_exact_refs_reads_back_absence_then_cancels() -> None:
    calls: list[object] = []
    store: dict[str, bytes] = {}
    fake = _route_fake(calls, store)
    with patch.object(operator, "urlopen", fake):
        operator.run_phase("lifecycle")
        rows = operator.run_phase("cleanup")
    assert [row["step"] for row in rows] == [
        "cas-delete", "cas-delete-readback", "cas-delete", "cas-delete-readback", "deactivate", "deactivate"
    ]
    deletes = [request for request in calls if request.method == "DELETE"]
    assert len(deletes) == 2
    assert all(request.full_url.startswith("http://10.20.30.40:50051/v1/cas/") for request in deletes)
    assert not store
    assert not Path(operator.CAS_STATE_PATH).exists()


def test_pregrant_phase_requires_two_authenticated_admitted_denials() -> None:
    requests = []

    def send(request, timeout):
        requests.append(request)
        assert request.full_url == "http://10.20.30.40:50051/v1/admin/byok/activate"
        assert request.get_header("X-corelink-internal-auth") == "i" * 40
        assert request.get_header("X-corelink-staging-load-admission").startswith("v2.123456789.byok.staging.")
        return Response(501, b"opaque not-available body")

    with patch.object(operator, "urlopen", send):
        rows = operator.run_phase("pregrant-deny")
    assert len(requests) == len(rows) == 2
    assert [row["status"] for row in rows] == [501, 501]
    assert all("request_started_at_utc" in row for row in rows)
    assert all(re.fullmatch(r"[a-f0-9]{64}", row["request_body_sha256"]) for row in rows)
    assert "tcs_wrapped_b64" not in json.dumps(rows)
    assert "tenant-stage" not in json.dumps(rows)


def test_activation_fails_before_http_when_request_start_clock_unavailable() -> None:
    with patch.object(operator, "urlopen") as send, patch.object(
        operator, "_timestamp", side_effect=operator.OperatorError("clock unavailable")
    ):
        with pytest.raises(operator.OperatorError, match="clock unavailable"):
            operator.run_phase("pregrant-deny")
    send.assert_not_called()


def test_duplicate_tenant_bound_wrapped_secrets_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    same = base64.b64encode(b"shared-wrapped-value").decode()
    monkeypatch.setenv("ISSUE_2165_TCS_WRAPPED_B64_A", same)
    monkeypatch.setenv("ISSUE_2165_TCS_WRAPPED_B64_B", same)
    with patch.object(operator, "urlopen") as send:
        with pytest.raises(operator.OperatorError, match="must be distinct"):
            operator.run_phase("pregrant-deny")
    send.assert_not_called()


@pytest.mark.parametrize("tenant_json", ['["same","same"]', '["only-one"]', '[]', 'not-json'])
def test_invalid_tenant_pair_fails_before_network(monkeypatch: pytest.MonkeyPatch, tenant_json: str) -> None:
    monkeypatch.setenv("ISSUE_2165_TENANTS_JSON", tenant_json)
    with patch.object(operator, "urlopen") as send:
        with pytest.raises(operator.OperatorError, match="tenant list"):
            operator.run_phase("lifecycle")
    send.assert_not_called()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ISSUE_2165_PAT_A", ""),
        ("ISSUE_2165_PAT_B", "short"),
        ("ISSUE_2165_STORAGE_QUOTA_BYTES", ""),
        ("ISSUE_2165_STORAGE_QUOTA_BYTES", "0"),
        ("ISSUE_2165_STORAGE_QUOTA_BYTES", "31"),
        ("ISSUE_2165_STORAGE_QUOTA_BYTES", "not-a-number"),
    ],
)
def test_missing_pat_or_quota_fails_before_network(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    monkeypatch.setenv(name, value)
    with patch.object(operator, "urlopen") as send:
        with pytest.raises(operator.OperatorError):
            operator.run_phase("lifecycle")
    send.assert_not_called()


def test_wrong_cross_tenant_status_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    store: dict[str, bytes] = {}
    fake = _route_fake(calls, store)

    def wrong_status(request, timeout):
        if request.method == "GET" and request.full_url.startswith("http://10.20.30.40:50051/v1/cas/tenant-stage-one/") and request.get_header("Authorization") == "Bearer pat-b-" + "2" * 40:
            calls.append(request)
            return Response(200, b"forbidden bytes")
        return fake(request, timeout)

    with patch.object(operator, "urlopen", wrong_status):
        with pytest.raises(operator.OperatorError, match="cross-tenant"):
            operator.run_phase("lifecycle")
    assert len([r for r in calls if getattr(r, "method", "") == "PUT"]) == 2


def test_redacted_json_output_never_contains_pats_tenants_or_blob_bytes(capsys) -> None:
    calls: list[object] = []
    store: dict[str, bytes] = {}
    with patch.object(operator, "urlopen", _route_fake(calls, store)):
        assert operator.main(["--phase", "lifecycle"]) == 0
    captured = capsys.readouterr()
    assert "tenant-stage-one" not in captured.out + captured.err
    assert "tenant-stage-two" not in captured.out + captured.err
    assert "pat-a-" not in captured.out + captured.err
    assert "pat-b-" not in captured.out + captured.err
    assert "i" * 40 not in captured.out + captured.err
    assert "wrapped-test-ciphertext" not in captured.out + captured.err
    rows = [json.loads(line) for line in captured.out.splitlines()]
    assert len(rows) == 7
    assert all("digest" in row or row["step"] in {"activate", "deactivate"} for row in rows)
