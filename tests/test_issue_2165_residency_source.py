from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).parent))
import issue_2165_residency_source as producer  # noqa: E402
from test_issue_2165_residency_receipt import fixture  # noqa: E402


def env_for(manifest: dict) -> dict[str, str]:
    aws = manifest["aws"]
    cloudflare = manifest["cloudflare"]
    return {"B083_AWS_ACCOUNT_ID": aws.get("account_id", "123456789012"),
            "B083_AWS_REGION": aws["region"], "B083_AWS_CLUSTER_ARN": aws["cluster_arn"],
            "B083_AWS_TASK_DEFINITION_ARN": aws["task_definition_arn"],
            "B083_AWS_RUNTIME_ROLE_ARN": aws["runtime_role_arn"], "B083_IMAGE_URI": aws["image_uri"],
            "B083_CF_ACCOUNT_ID": cloudflare["account_id"],
            "B083_D1_DATABASE_ID": cloudflare["d1"]["database_id"],
            "B083_D1_REGION": cloudflare["d1"]["region"]}


def inputs():
    manifest, sources, raw = fixture()
    manifest["aws"]["account_id"] = "123456789012"
    return manifest, sources, raw, env_for(manifest)


def test_outputs_only_one_archive_compatible_redacted_row() -> None:
    manifest, sources, raw, env = inputs()
    row = producer.archive_row(manifest, sources, raw, env)
    assert set(row) == {"step", "occurred_at_utc", "source"}
    assert row["step"] == "residency"
    assert row["source"]["kind"] == "d1"
    expected_ref = ("https://api.cloudflare.com/client/v4/accounts/"
                    f"{manifest['cloudflare']['account_id']}/d1/database/{manifest['cloudflare']['d1']['database_id']}")
    assert row["source"]["event_ref"] == expected_ref
    assert len(row["source"]["digest"]) == 64
    assert "11111111" not in json.dumps(row)
    assert "tenant_rows" not in json.dumps(row)


def test_does_not_accept_opaque_cloudflare_support_reference_as_source() -> None:
    manifest, sources, raw, env = inputs()
    sources["d1_control_plane"]["endpoint"] = "https://support.cloudflare.com/attachments/placement-attestation-opaque-42"
    with pytest.raises(producer.validator.ResidencyError, match="exact authenticated database GET"):
        producer.archive_row(manifest, sources, raw, env)


def test_rejects_caller_supplied_physical_placement_url() -> None:
    manifest, sources, raw, env = inputs()
    del sources["d1_control_plane"]
    sources["d1_physical_placement"] = {"source": {"provider_ref": "https://api.cloudflare.com/fake"}}
    with pytest.raises(producer.validator.ResidencyError, match="sources.d1_control_plane"):
        producer.archive_row(manifest, sources, raw, env)


def test_rejects_wrong_d1_account_or_database_endpoint() -> None:
    manifest, sources, raw, env = inputs()
    sources["d1_control_plane"]["endpoint"] = "https://api.cloudflare.com/client/v4/accounts/wrong/d1/database/database-1"
    with pytest.raises(producer.validator.ResidencyError, match="exact authenticated database GET"):
        producer.archive_row(manifest, sources, raw, env)


@pytest.mark.parametrize("database_id", [
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee?fields=uuid",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee#fragment",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/extra",
])
def test_rejects_url_metacharacters_in_database_path_segment(database_id: str) -> None:
    manifest, sources, raw, env = inputs()
    manifest["cloudflare"]["d1"]["database_id"] = database_id
    env["B083_D1_DATABASE_ID"] = database_id
    with pytest.raises(producer.validator.ResidencyError, match="UUID path segment"):
        producer.archive_row(manifest, sources, raw, env)


def test_rejects_missing_d1_control_plane_readback() -> None:
    manifest, sources, raw, env = inputs()
    del sources["d1_control_plane"]
    with pytest.raises(producer.validator.ResidencyError, match="sources.d1_control_plane"):
        producer.archive_row(manifest, sources, raw, env)


@pytest.mark.parametrize("mutation", [
    lambda m, s: s["d1"].update(account_id="other-account"),
    lambda m, s: s["app"]["task"].update(image_digest="sha256:" + "c" * 64),
    lambda m, s: s["r2"].update(region="iad"),
    lambda m, s: s["d1"]["tenant_rows"].__setitem__(1, {"tenant_slot": "tenant_b", "tenant_id": "33333333-3333-4333-8333-333333333333"}),
])
def test_rejects_target_mismatch(mutation) -> None:
    manifest, sources, raw, env = inputs()
    sources = copy.deepcopy(sources)
    mutation(manifest, sources)
    with pytest.raises(producer.validator.ResidencyError):
        producer.archive_row(manifest, sources, raw, env)


def test_rejects_protected_manifest_environment_mismatch() -> None:
    manifest, sources, raw, env = inputs()
    env["B083_CF_ACCOUNT_ID"] = "wrong"
    with pytest.raises(producer.validator.ResidencyError, match="protected AWS/CF target variables"):
        producer.archive_row(manifest, sources, raw, env)


def test_protected_workflow_fetches_exact_d1_database_metadata_live() -> None:
    workflow = (Path(__file__).parents[1] / ".github/workflows/issue-2165-kms-real.yml").read_text(encoding="utf-8")
    assert 'd1_control_path = f"/accounts/{target[\'account_id\']}/d1/database/{target[\'database_id\']}"' in workflow
    assert 'cf._api_json("GET", d1_control_path, os.environ["B083_CF_API_TOKEN"])' in workflow
    assert '"d1_control_plane": d1_control_payload' in workflow
    assert "physical_placement_attestation" not in workflow
