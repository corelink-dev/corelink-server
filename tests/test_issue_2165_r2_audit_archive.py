import base64
import hashlib
import hmac
import json
import sys
from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue_2165_r2_audit_archive as archive


def source_receipts():
    return [
        {
            "step": step,
            "occurred_at_utc": "2026-09-30T12:00:00Z",
            "source": {
                "kind": "runtime",
                "event_ref": f"receipt:{step}",
                "digest": hashlib.sha256(step.encode()).hexdigest(),
            },
        }
        for step in sorted(archive.SOURCE_STEPS)
    ]


def manifest():
    return {
        "account": "a" * 32,
        "bucket": "isolated-audit",
        "endpoint": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        "key": "issue-2165/12345/audit/receipts.ndjson",
    }


def env():
    return {
        archive.PARENT_ID: "parent-id",
        archive.PARENT_SECRET: "parent-secret-for-test-only",
        "GITHUB_RUN_ID": "12345",
    }


def decode_segment(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


class MissingObject(Exception):
    response = {"Error": {"Code": "404"}, "ResponseMetadata": {"HTTPStatusCode": 404}}


def test_jwt_claims_and_derived_credentials_are_exactly_scoped():
    paths = ["issue-2165/123/audit/source-receipts.ndjson", "issue-2165/123/audit/receipts.ndjson"]
    creds = archive._jwt_credentials("acct", "https://acct.r2.cloudflarestorage.com", "bucket", paths, "kid", "secret", now=100, ttl=900)
    jwt = base64.b64decode(creds["session_token"]).decode()[4:]
    head, payload, signature = jwt.split(".")
    assert decode_segment(head) == {"alg": "HS256", "typ": "JWT"}
    assert hmac.compare_digest(signature, archive._b64url(hmac.new(b"secret", f"{head}.{payload}".encode(), hashlib.sha256).digest()))
    assert decode_segment(payload) == {
        "bucket": "bucket",
        "scope": "object-read-write",
        "actions": ["PutObject", "GetObject", "HeadObject"],
        "paths": {"prefixPaths": [], "objectPaths": paths},
        "sub": "acct",
        "iss": "kid",
        "aud": "acct.r2.cloudflarestorage.com",
        "iat": 100,
        "exp": 1000,
    }
    assert creds["access_key_id"] == "kid"
    assert creds["secret_access_key"] == hashlib.sha256(jwt.encode()).hexdigest()
    with pytest.raises(archive.ArchiveError):
        archive._jwt_credentials("acct", "https://acct.r2.cloudflarestorage.com", "bucket", "key", "kid", "secret", ttl=901)


def test_exact_key_archive_generates_audit_refs_only_after_full_readback():
    operations = []
    stored = {}
    client_credentials = {}

    class Body:
        def __init__(self, payload):
            self.payload = payload

        def read(self):
            operations.append("get-body-read")
            return self.payload

    class Client:
        def head_object(self, **kwargs):
            operations.append(("head", kwargs))
            if (kwargs["Bucket"], kwargs["Key"]) not in stored:
                raise MissingObject()
            return {"ContentLength": len(stored[(kwargs["Bucket"], kwargs["Key"])])}

        def put_object(self, **kwargs):
            operations.append(("put", kwargs))
            assert kwargs["IfNoneMatch"] == "*"
            assert kwargs["Bucket"] == manifest()["bucket"]
            stored[(kwargs["Bucket"], kwargs["Key"])] = kwargs["Body"]
            self.payload = kwargs["Body"]

        def get_object(self, **kwargs):
            operations.append(("get", kwargs))
            return {"Body": Body(stored[(kwargs["Bucket"], kwargs["Key"])])}

    def factory(**kwargs):
        client_credentials.update(kwargs)
        return Client()

    captured = archive.archive(manifest(), source_receipts(), env(), s3_factory=factory, now=lambda: datetime(2026, 9, 30, tzinfo=timezone.utc))
    assert [op[0] for op in operations if isinstance(op, tuple)] == ["head", "head", "put", "head", "get", "put", "head", "get"]
    assert operations[-1] == "get-body-read"
    assert captured["object_sha256"] == "sha256:" + hashlib.sha256(stored[(manifest()["bucket"], manifest()["key"])]).hexdigest()
    assert set(captured["lifecycle"]) == archive.REQUIRED_STEPS
    assert all(item["receipt_reference"].startswith(f"audit://{step}/") for step, item in captured["lifecycle"].items())
    assert client_credentials["aws_access_key_id"] == "parent-id"
    assert client_credentials["aws_secret_access_key"] != env()[archive.PARENT_SECRET]
    assert env()[archive.PARENT_SECRET] not in client_credentials.values()
    claims = decode_segment(base64.b64decode(client_credentials["aws_session_token"]).decode()[4:].split(".")[1])
    assert claims["paths"]["objectPaths"] == [
        "issue-2165/12345/audit/source-receipts.ndjson",
        "issue-2165/12345/audit/receipts.ndjson",
    ]


def test_existing_object_is_never_overwritten():
    class Client:
        puts = 0

        def head_object(self, **kwargs):
            return {"ContentLength": 1}

        def put_object(self, **kwargs):
            self.puts += 1

    client = Client()
    with pytest.raises(archive.ArchiveError, match="overwrite"):
        archive.archive(manifest(), source_receipts(), env(), s3_factory=lambda **kwargs: client)
    assert client.puts == 0


def test_preexisting_final_object_rejects_before_any_put():
    class Client:
        puts = 0

        def head_object(self, **kwargs):
            if kwargs["Key"].endswith("source-receipts.ndjson"):
                raise MissingObject()
            return {"ContentLength": 1}

        def put_object(self, **kwargs):
            self.puts += 1

    client = Client()
    with pytest.raises(archive.ArchiveError, match="overwrite"):
        archive.archive(manifest(), source_receipts(), env(), s3_factory=lambda **kwargs: client)
    assert client.puts == 0


def test_source_object_conditional_write_conflict_never_retries_or_writes_final():
    class Conflict(Exception):
        response = {"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}

    class Client:
        def __init__(self):
            self.puts = []

        def head_object(self, **kwargs):
            raise MissingObject()

        def put_object(self, **kwargs):
            self.puts.append(kwargs["Key"])
            raise Conflict()

    client = Client()
    with pytest.raises(archive.ArchiveError, match="PUT/HEAD/GET failed"):
        archive.archive(manifest(), source_receipts(), env(), s3_factory=lambda **kwargs: client)
    assert client.puts == ["issue-2165/12345/audit/source-receipts.ndjson"]


def test_missing_parent_key_pair_fails_before_client_creation():
    called = False

    def factory(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("client must not be created")

    protected = {"GITHUB_RUN_ID": "12345", archive.PARENT_ID: "parent-id"}
    with pytest.raises(archive.ArchiveError, match="key pair"):
        archive.archive(manifest(), source_receipts(), protected, s3_factory=factory)
    assert called is False


def test_missing_step_fails_before_s3_factory_or_put():
    called = False

    def factory(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("client must not be constructed")

    with pytest.raises(archive.ArchiveError, match="exactly nine"):
        archive.archive(manifest(), source_receipts()[:-1], env(), s3_factory=factory)
    assert called is False


def test_tampered_source_and_duplicate_source_refs_fail_closed():
    rows = source_receipts()
    rows[0]["source"]["digest"] = "not-a-digest"
    with pytest.raises(archive.ArchiveError, match="digest"):
        archive.validate_source_receipts(rows)
    rows = source_receipts()
    rows[1]["source"]["event_ref"] = rows[0]["source"]["event_ref"]
    with pytest.raises(archive.ArchiveError, match="unique"):
        archive.validate_source_receipts(rows)
    rows = source_receipts()
    rows[0]["source"]["event_ref"] = "sidecar-jsonl:sha256:" + rows[0]["source"]["digest"]
    with pytest.raises(archive.ArchiveError, match="local content hash"):
        archive.validate_source_receipts(rows)


def test_manifest_binds_cf5128_endpoint_bucket_and_exact_run_object(tmp_path):
    target = tmp_path / "target.json"
    account = "a" * 32
    record = {
        "cloudflare": {
            "account_alias": "cf5128",
            "account_id": account,
            "r2": {"binding": "B083_R2", "region": "auto", "endpoint": f"https://{account}.r2.cloudflarestorage.com", "bucket": "isolated-audit"},
        },
        "audit_sink": {"r2_bucket": "isolated-audit", "r2_archive_key": "issue-2165/12345/audit/receipts.ndjson"},
    }
    target.write_text(json.dumps(record))
    target.chmod(0o600)
    protected = {
        "RUNNER_TEMP": str(tmp_path),
        "B083_TARGET_MANIFEST_SECRET_ARN": "arn:protected",
        "GITHUB_RUN_ID": "12345",
        "B083_CF_ACCOUNT_ID": account,
        "B083_R2_S3_ENDPOINT": f"https://{account}.r2.cloudflarestorage.com",
    }
    assert archive._protected_manifest(target, protected)["key"] == record["audit_sink"]["r2_archive_key"]
    record["audit_sink"]["r2_archive_key"] = "issue-2165/another/audit/receipts.ndjson"
    target.write_text(json.dumps(record))
    target.chmod(0o600)
    with pytest.raises(archive.ArchiveError, match="exact protected"):
        archive._protected_manifest(target, protected)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda doc: doc["cloudflare"].update(account_id="b" * 32), "manifest account"),
        (lambda doc: doc["cloudflare"]["r2"].update(bucket="wrong-bucket"), "audit sink bucket"),
        (lambda doc: doc["cloudflare"]["r2"].update(endpoint="https://wrong.r2.cloudflarestorage.com"), "protected account-bound endpoint"),
        (lambda doc: doc["cloudflare"].update(account_alias="prod6a"), "cf5128"),
    ],
)
def test_manifest_rejects_wrong_account_bucket_or_endpoint(tmp_path, mutation, match):
    account = "a" * 32
    target = tmp_path / "target.json"
    record = {
        "cloudflare": {
            "account_alias": "cf5128",
            "account_id": account,
            "r2": {"binding": "B083_R2", "region": "auto", "endpoint": f"https://{account}.r2.cloudflarestorage.com", "bucket": "isolated-audit"},
        },
        "audit_sink": {"r2_bucket": "isolated-audit", "r2_archive_key": "issue-2165/12345/audit/receipts.ndjson"},
    }
    mutation(record)
    target.write_text(json.dumps(record))
    target.chmod(0o600)
    protected = {
        "RUNNER_TEMP": str(tmp_path),
        "B083_TARGET_MANIFEST_SECRET_ARN": "arn:protected",
        "GITHUB_RUN_ID": "12345",
        "B083_CF_ACCOUNT_ID": account,
        "B083_R2_S3_ENDPOINT": f"https://{account}.r2.cloudflarestorage.com",
    }
    with pytest.raises(archive.ArchiveError, match=match):
        archive._protected_manifest(target, protected)


def test_readback_mismatch_emits_no_audit_refs_and_does_not_leak_secret():
    class Body:
        def read(self):
            return b"tampered"

    class Client:
        def __init__(self):
            self.put_body = b""

        def head_object(self, **kwargs):
            if self.put_body:
                return {"ContentLength": len(self.put_body)}
            raise MissingObject()

        def put_object(self, **kwargs):
            self.put_body = kwargs["Body"]

        def get_object(self, **kwargs):
            return {"Body": Body()}

    with pytest.raises(archive.ArchiveError, match="readback") as raised:
        archive.archive(manifest(), source_receipts(), env(), s3_factory=lambda **kwargs: Client())
    assert "parent-secret-for-test-only" not in str(raised.value)


def test_cli_failure_writes_no_audit_refs_or_result_file(tmp_path, monkeypatch, capsys):
    account = "a" * 32
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "cloudflare": {
            "account_alias": "cf5128",
            "account_id": account,
            "r2": {"binding": "B083_R2", "region": "auto", "endpoint": f"https://{account}.r2.cloudflarestorage.com", "bucket": "isolated-audit"},
        },
        "audit_sink": {"r2_bucket": "isolated-audit", "r2_archive_key": "issue-2165/12345/audit/receipts.ndjson"},
    }))
    manifest_path.chmod(0o600)
    receipts_path = tmp_path / "source-receipts.json"
    receipts_path.write_text(json.dumps(source_receipts()))
    receipts_path.chmod(0o600)
    output_path = tmp_path / "archive-result.json"

    class Body:
        def read(self):
            return b"tampered"

    class Client:
        def __init__(self):
            self.objects = {}

        def head_object(self, **kwargs):
            identity = (kwargs["Bucket"], kwargs["Key"])
            if identity not in self.objects:
                raise MissingObject()
            return {"ContentLength": len(self.objects[identity])}

        def put_object(self, **kwargs):
            self.objects[(kwargs["Bucket"], kwargs["Key"])] = kwargs["Body"]

        def get_object(self, **kwargs):
            return {"Body": Body()}

    client = Client()
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda **kwargs: client))
    for key, value in {
        "RUNNER_TEMP": str(tmp_path),
        "B083_TARGET_MANIFEST_SECRET_ARN": "arn:protected",
        "GITHUB_RUN_ID": "12345",
        "B083_CF_ACCOUNT_ID": account,
        "B083_R2_S3_ENDPOINT": f"https://{account}.r2.cloudflarestorage.com",
        archive.PARENT_ID: "parent-id",
        archive.PARENT_SECRET: "parent-secret-for-test-only",
    }.items():
        monkeypatch.setenv(key, value)

    result = archive.main(["--manifest", str(manifest_path), "--receipts", str(receipts_path), "--output", str(output_path)])
    assert result == 2
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "audit://" not in stderr
    assert "parent-secret-for-test-only" not in stderr
