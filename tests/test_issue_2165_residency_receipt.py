from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import issue_2165_residency_receipt as receipt  # noqa: E402


def _source(name: str, body: dict) -> dict:
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"provider_ref": f"{name}:direct-readback/abc123", "raw_sha256": digest, "observed_at_utc": "2026-09-30T12:00:00Z"}


def fixture() -> tuple[dict, dict, dict]:
    tenants = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"]
    database_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    image = "registry.example/b083@sha256:" + "a" * 64
    manifest = {
        "schema": receipt.MANIFEST_SCHEMA,
        "environment": receipt.ENVIRONMENT,
        "aws": {"region": "us-east-1", "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/isolated",
                "task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/app:3",
                "runtime_role_arn": "arn:aws:iam::123456789012:role/app-runtime", "image_uri": image},
        "cloudflare": {"account_alias": "cf5128", "account_id": "51284495e71acdb5a7677e7383ab026b",
                       "d1": {"binding": "B083_D1", "database_id": database_id, "region": "iad"},
                       "r2": {"binding": "B083_R2", "endpoint": "https://cf5128.r2.example", "bucket": "b083-cache", "region": "auto"},
                       "r2_prefixes": [{"tenant_id": tenants[0], "region": "iad", "prefix": "iad/aaaaaaaaaaaaaaaa/"},
                                       {"tenant_id": tenants[1], "region": "lhr", "prefix": "lhr/bbbbbbbbbbbbbbbb/"}]},
        "disposable_tenants": tenants,
    }
    app_raw = {"task_id": "task-1", "task_definition": "taskdef-3", "image_digest": "sha256:" + "a" * 64}
    d1_raw = {"result": [{"meta": {"changed_db": False, "rows_written": 0, "changes": 0}}], "rows": ["tenant-a", "tenant-b"]}
    r2_raw = {"bucket": "b083-cache", "objects": []}
    d1_control_raw = {"success": True, "result": {"uuid": database_id, "jurisdiction": "eu",
                                                    "read_replication": {"mode": "auto"}}}
    sources = {
        "schema": receipt.INPUT_SCHEMA,
        "app": {"method": "ecs-describe-tasks+describe-task-definition", "source": _source("ecs", app_raw),
                "task": {"last_status": "RUNNING", "task_definition_arn": manifest["aws"]["task_definition_arn"],
                         "cluster_arn": manifest["aws"]["cluster_arn"], "region": "us-east-1", "availability_zone": "us-east-1a",
                         "image_digest": "sha256:" + "a" * 64},
                "task_definition": {"task_definition_arn": manifest["aws"]["task_definition_arn"],
                                    "task_role_arn": manifest["aws"]["runtime_role_arn"], "image_uri": image}},
        "d1": {"method": "parameterized-select-post", "account_alias": "cf5128", "account_id": manifest["cloudflare"]["account_id"],
               "binding": "B083_D1", "database_id": database_id, "region": "iad", "changed_db": False,
               "rows_written": 0, "changes": 0,
               "tenant_rows": [{"tenant_slot": "tenant_a", "tenant_id": tenants[0]}, {"tenant_slot": "tenant_b", "tenant_id": tenants[1]}],
               "source": _source("d1", d1_raw)},
        "r2": {"method": "s3-list-objects-v2-read-only", "binding": "B083_R2", "account_id": manifest["cloudflare"]["account_id"],
               "endpoint": "https://cf5128.r2.example", "bucket": "b083-cache", "region": "auto",
               "prefix_inventory": manifest["cloudflare"]["r2_prefixes"], "source": _source("r2", r2_raw)},
        "d1_control_plane": {"method": "authenticated-get", "account_id": manifest["cloudflare"]["account_id"],
                             "database_id": database_id,
                             "endpoint": f"https://api.cloudflare.com/client/v4/accounts/51284495e71acdb5a7677e7383ab026b/d1/database/{database_id}",
                             "raw_sha256": hashlib.sha256(json.dumps(d1_control_raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                             "observed_at_utc": "2026-09-30T12:00:00Z"},
    }
    raw = {"ecs": app_raw, "d1_select": d1_raw, "r2_inventory": r2_raw, "d1_control_plane": d1_control_raw}
    return manifest, sources, raw


def test_emits_one_redacted_source_backed_residency_row() -> None:
    result = receipt.validate(*fixture())
    assert result["schema"] == receipt.OUTPUT_SCHEMA
    assert len(result["rows"]) == 1
    assert result["rows"][0]["step"] == "residency"
    assert result["rows"][0]["status"] == "verified"
    assert result["rows"][0]["targets"]["aws_region"] == "us-east-1"
    assert result["rows"][0]["targets"]["d1_jurisdiction"] == "eu"
    assert result["rows"][0]["targets"]["residency_scope"] == "cloudflare-d1-only"
    assert "11111111" not in json.dumps(result)


@pytest.mark.parametrize("mutate", [
    lambda m, s, r: s["d1"].update(account_id="wrong-account"),
    lambda m, s, r: s["d1"]["tenant_rows"].__setitem__(1, {"tenant_slot": "tenant_b", "tenant_id": "33333333-3333-4333-8333-333333333333"}),
    lambda m, s, r: s["r2"].update(region="lhr"),
    lambda m, s, r: s["app"]["task"].update(image_digest="sha256:" + "b" * 64),
])
def test_rejects_wrong_account_tenant_region_or_image(mutate) -> None:
    m, s, r = fixture()
    mutate(m, s, r)
    with pytest.raises(receipt.ResidencyError):
        receipt.validate(m, s, r)


def test_fails_closed_when_live_d1_metadata_readback_is_missing() -> None:
    m, s, r = fixture()
    del s["d1_control_plane"]
    with pytest.raises(receipt.ResidencyError, match="sources.d1_control_plane"):
        receipt.validate(m, s, r)


@pytest.mark.parametrize("change,match", [
    (lambda response: response.update(success=False), "unsuccessful or malformed"),
    (lambda response: response["result"].update(uuid="other-db"), "different database UUID"),
    (lambda response: response["result"].update(jurisdiction=None), "jurisdiction is not EU"),
    (lambda response: response["result"].update(jurisdiction="us"), "jurisdiction is not EU"),
    (lambda response: response["result"].update(jurisdiction="fedramp"), "jurisdiction is not EU"),
    (lambda response: response["result"].update(read_replication={}), "read_replication.mode is missing or malformed"),
    (lambda response: response["result"].update(read_replication={"mode": "replicate-everywhere"}), "read_replication.mode is missing or malformed"),
])
def test_rejects_unsuccessful_or_wrong_d1_metadata(change, match) -> None:
    m, s, r = fixture()
    change(r["d1_control_plane"])
    with pytest.raises(receipt.ResidencyError, match=match):
        receipt.validate(m, s, r)


def test_rejects_control_plane_endpoint_for_wrong_account_or_database() -> None:
    m, s, r = fixture()
    s["d1_control_plane"]["endpoint"] = "https://support.cloudflare.com/attachments/fake"
    with pytest.raises(receipt.ResidencyError, match="exact authenticated database GET"):
        receipt.validate(m, s, r)


@pytest.mark.parametrize("target_change", [
    lambda m: m["cloudflare"].update(account_id="../" + "a" * 29),
    lambda m: m["cloudflare"]["d1"].update(database_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee?fields=uuid"),
    lambda m: m["cloudflare"]["d1"].update(database_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee#fragment"),
])
def test_rejects_url_metacharacters_in_bound_d1_target(target_change) -> None:
    m, s, r = fixture()
    target_change(m)
    with pytest.raises(receipt.ResidencyError, match="account id|UUID path segment"):
        receipt.validate(m, s, r)


def test_rejects_tampered_d1_control_plane_response_digest() -> None:
    m, s, r = fixture()
    r["d1_control_plane"]["result"]["version"] = "tampered"
    with pytest.raises(receipt.ResidencyError, match="raw evidence digest does not match d1_control_plane"):
        receipt.validate(m, s, r)


def test_raw_source_digest_must_match_exact_private_evidence() -> None:
    m, s, r = fixture()
    r["r2_inventory"]["bucket"] = "other"
    with pytest.raises(receipt.ResidencyError, match="raw evidence digest"):
        receipt.validate(m, s, r)
