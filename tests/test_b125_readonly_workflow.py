"""Static contract checks for the B-125 read-only D1 evidence lane."""

from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import subprocess
import sys
import textwrap
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from b125_readonly_diagnostics import (  # noqa: E402
    MAX_PROVIDER_OUTPUT_BYTES,
    make_provider_diagnostic,
    mark_query_started,
    record_provider_failure,
    validate_provider_diagnostic,
)


WORKFLOW = ROOT / ".github/workflows/b125-audit-throughput-read-only.yml"
FIXTURE_NAMES = (
    "b125-d1-aggregate-direct.json",
    "b125-d1-aggregate-wrangler.json",
)
REQUIRED_COLUMNS = {
    "window_start_utc",
    "window_end_utc",
    "arrivals",
    "sealed_rows",
    "boundary_unsealed",
}


def _result_blocks(document: object) -> list[dict[str, object]]:
    """Mirror the workflow's accepted Wrangler/D1 result envelopes."""
    if isinstance(document, list):
        blocks = document
    elif isinstance(document, dict):
        result = document.get("result")
        if isinstance(result, list):
            blocks = result
        elif isinstance(result, dict):
            blocks = [result]
        elif isinstance(document.get("results"), (list, dict)):
            blocks = [document]
        else:
            blocks = []
    else:
        blocks = []
    if isinstance(blocks, dict):
        blocks = [blocks]
    assert isinstance(blocks, list) and blocks
    return blocks  # type: ignore[return-value]


def _rows(document: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for block in _result_blocks(document):
        assert block.get("success") is not False
        result_rows = block.get("results") or []
        assert isinstance(result_rows, list)
        rows.extend(result_rows)  # type: ignore[arg-type]
    return rows


def _hourly_sql() -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"^\s*SQL\[hourly\]='([^']+)'$", source, re.MULTILINE)
    assert match, "hourly SQL must remain an explicit shell allowlist entry"
    return match.group(1)


def _latency_sql() -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"^\s*SQL\[latency\]='([^']+)'$", source, re.MULTILINE)
    assert match, "latency SQL must remain an explicit shell allowlist entry"
    return match.group(1)


def test_hourly_sql_is_one_select_only_aggregate_with_six_offsets() -> None:
    sql = _hourly_sql()
    assert sql.startswith("WITH hour_offsets")
    assert ";" not in sql
    assert not re.search(r"\b(?:INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|CREATE|PRAGMA|ATTACH|DETACH)\b", sql)
    assert "aggregate_counts AS" in sql
    assert sql.count("COUNT(CASE WHEN") == 13
    assert "enqueued_at < c.anchor_s * 1000 AND (emitted_at IS NULL OR emitted_at >= c.anchor_s * 1000)" in sql
    assert {int(value) for value in re.findall(r"arrivals_(\d)", sql)} == set(range(6))
    assert {int(value) for value in re.findall(r"sealed_(\d)", sql)} == set(range(6))


def test_hourly_sql_executes_as_six_row_sqlite_aggregate() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE audit_outbox (enqueued_at INTEGER, emitted_at INTEGER)")
    anchor_ms = int(datetime.now(timezone.utc).timestamp()) // 3600 * 3600 * 1000
    connection.executemany(
        "INSERT INTO audit_outbox VALUES (?, ?)",
        [
            (anchor_ms - 7 * 3600_000, anchor_ms - 5 * 3600_000),
            (anchor_ms - 3 * 3600_000, anchor_ms),
            (anchor_ms - 2 * 3600_000, None),
            (anchor_ms + 1_000, None),
        ],
    )
    result = connection.execute(_hourly_sql()).fetchall()
    assert len(result) == 6
    assert all(len(row) == 5 for row in result)
    # The current partial hour is excluded; a seal exactly at the boundary
    # still counted as unsealed at that boundary.
    assert all(row[4] == 2 for row in result)


def test_latency_sql_uses_conventional_even_sample_median() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE audit_outbox (enqueued_at INTEGER, emitted_at INTEGER)")
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    anchor_ms = now_ms // 3_600_000 * 3_600_000
    connection.executemany(
        "INSERT INTO audit_outbox VALUES (?, ?)",
        [(anchor_ms - 100_000, anchor_ms - 100_000 + latency) for latency in (1_000, 2_000, 3_000, 4_000)],
    )
    row = connection.execute(_latency_sql()).fetchone()
    assert row is not None
    assert row[0] == 4
    assert row[1:4] == (1_000, 2_500, 4_000)
    assert row[4] == 2_500
    assert row[5] == 4_000

    connection.execute("DELETE FROM audit_outbox")
    connection.executemany(
        "INSERT INTO audit_outbox VALUES (?, ?)",
        [(anchor_ms - 100_000, anchor_ms - 100_000 + latency) for latency in (1_000, 2_000, 4_000)],
    )
    assert connection.execute(_latency_sql()).fetchone()[4] == 2_000


def test_aggregate_fixtures_preserve_six_row_redacted_shape() -> None:
    expected: list[dict[str, object]] | None = None
    for name in FIXTURE_NAMES:
        document = json.loads((ROOT / "tests/fixtures" / name).read_text(encoding="utf-8"))
        rows = _rows(document)
        assert len(rows) == 6
        assert all(set(row) == REQUIRED_COLUMNS for row in rows)
        assert all(isinstance(row["arrivals"], int) and row["arrivals"] >= 0 for row in rows)
        assert all(isinstance(row["sealed_rows"], int) and row["sealed_rows"] >= 0 for row in rows)
        assert all(row["boundary_unsealed"] == 0 for row in rows)
        if expected is None:
            expected = rows
        else:
            assert rows == expected


def test_workflow_keeps_all_required_query_ids_and_remote_only_execution() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "for query_id in population partition hourly latency heads burst integrity replay head_tail; do" in source
    assert "--remote --command \"$sql\" --json" in source
    assert "--local" not in source
    assert "contents: read" in source
    assert "persist-credentials: false" in source
    assert "environment: production" in source
    assert '[[ "$GITHUB_REF" == "refs/heads/main" ]]' in source
    assert "deployment_receipt_ref:" in source
    assert "capture_mode:" in source
    assert "hourly_diagnostic" in source
    assert 'hourly_diagnostic) [[ "$CONFIRM" == "diagnose-b125-hourly" ]]' in source
    assert 'if [[ "$CAPTURE_MODE" == "hourly_diagnostic" ]]; then\n            run_query hourly\n            fail_closed "diagnostic_only_capture_not_closure_evidence"' in source
    assert "deployment_receipt_reference_invalid" in source
    assert "deployment_receipt_comment_unavailable" in source
    assert "deployment_receipt_comment_mismatch" in source
    assert 'gh api "repos/HuGR-dev/corelink-server/issues/comments/$comment_id"' in source
    assert "issues: read" in source
    assert 'if ! python3 - "$runtime_summary" <<\'PY\'' in source
    assert 'token = os.environ.get("CF_API_TOKEN", "")' in source
    assert 'python3 - "$CF_API_TOKEN" "$runtime_summary"' not in source
    assert 'require(app["healthy"] == 16 and app["active"] == 0' in source
    assert 'api.request("GET", APP_PATH)' in source
    assert 'api.request("GET", ROLLOUTS_PATH)' in source
    assert "active_repaired_image_mismatch" in source
    assert "completed_repaired_rollout_missing" in source
    assert 'item.get("target_version") == app["version"]' in source
    assert "active_repaired_container_readback_failed" in source
    assert 'datetime(2026, 10, 1, 2, 5, tzinfo=timezone.utc)' in source
    assert 'first_post_repair_bucket = datetime(2026, 9, 30, 20, 0, tzinfo=timezone.utc)' in source
    assert "post_repair_six_hour_window_not_settled" in source
    assert source.index("post_repair_six_hour_window_not_settled") < source.index(
        "for query_id in population partition hourly latency heads burst integrity replay head_tail; do"
    )
    assert "cloudflare_account_target_mismatch" in source
    assert "database_target_mismatch" in source
    assert "production_image_pin_mismatch" in source
    assert "production_config_blob_mismatch" in source
    assert "production_config_sha256_mismatch" in source
    assert '"production_config_sha256": config_sha256' in source
    assert '"production_config_blob_sha": config_blob_sha' in source
    assert '"target_account_id": account_id' in source
    assert '"repair_source_sha": source_sha' in source
    assert '"repair_image_digest": image_digest' in source
    assert '"runtime_digest_verified_by_workflow": True' in source
    assert '"scope": "IAD production Container application only; other regional pins are config-verified, not runtime-verified"' in source
    assert "issuecomment-5861728482" in source


def test_workflow_database_target_matches_canonical_signup_worker_uuid() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    config = (ROOT / "apps/signup-worker/wrangler.toml").read_text(encoding="utf-8")
    canonical_ids = set(
        re.findall(r'^database_id\s*=\s*"([0-9a-f-]{36})"\s*$', config, re.MULTILINE)
    )
    assert len(canonical_ids) == 1
    canonical_id = next(iter(canonical_ids))

    def matches_canonical_target(workflow_source: str) -> bool:
        expected_ids = re.findall(
            r'^\s*expected_database_id="([0-9a-f-]{36})"$',
            workflow_source,
            re.MULTILINE,
        )
        return len(expected_ids) == 1 and expected_ids[0] == canonical_id

    assert matches_canonical_target(source)

    transposed_id = canonical_id.replace("ff02e3f", "ff02f3e")
    assert transposed_id != canonical_id
    transposed_source = source.replace(
        f'expected_database_id="{canonical_id}"',
        f'expected_database_id="{transposed_id}"',
        1,
    )
    assert not matches_canonical_target(transposed_source)


def test_workflow_pins_the_frozen_b063_repair_across_all_five_prod_images() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    config = (ROOT / "wrangler.toml").read_text(encoding="utf-8")
    assert 'repair_source_sha="46e2d1cbe7c00a303c0942e8f46751dce75e5c14"' in source
    assert 'repair_image_digest="sha256:ecd63379d2040c6a891edaeb140fd388f26b5ffc181987c9c777060ced633e8a"' in source
    assert 'expected_config_blob_sha="5ffec8b882bcb99dcaf1df964c609e9d2c35838d"' in source
    assert 'expected_config_sha256="568d0e6994ce1156542e350520a9750924a0f3f416e67af07c7275682e24c7a6"' in source
    assert hashlib.sha256(config.encode()).hexdigest() == "568d0e6994ce1156542e350520a9750924a0f3f416e67af07c7275682e24c7a6"
    for region in ("", "-sam", "-lhr", "-nrt", "-syd"):
        repository = f"corelink-prod{region}-corelinkserver-prod"
        assert f"/{repository}:46e2d1cbe-r1" in source
        assert config.count(f'image = "registry.cloudflare.com/6a1fc1c626fc2628823e60b9db01f5cd/{repository}:46e2d1cbe-r1"') == 1


def _inline_gate(source: str, command: str) -> str:
    match = re.search(re.escape(command) + r" <<'PY'\n(.*?)\n          PY", source, re.DOTALL)
    assert match, f"missing executable workflow gate: {command}"
    return textwrap.dedent(match.group(1))


def test_deployment_comment_gate_accepts_only_existing_matching_1648_receipt(tmp_path: Path) -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    command = 'python3 - "$comment_path" "$DEPLOYMENT_RECEIPT_REF" "$repair_source_sha" "$repair_image_digest"'
    script = _inline_gate(source, command)
    source_sha = "46e2d1cbe7c00a303c0942e8f46751dce75e5c14"
    digest = "sha256:ecd63379d2040c6a891edaeb140fd388f26b5ffc181987c9c777060ced633e8a"
    url = "https://github.com/HuGR-dev/corelink-server/issues/1648#issuecomment-5869999999"
    path = tmp_path / "comment.json"

    def check(comment: dict[str, object], expected_url: str = url) -> bool:
        path.write_text(json.dumps(comment), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-", str(path), expected_url, source_sha, digest],
            input=script, text=True, capture_output=True, check=False,
        )
        return result.returncode == 0

    valid = {
        "html_url": url,
        "issue_url": "https://api.github.com/repos/HuGR-dev/corelink-server/issues/1648",
        "body": f"ROLLOUT_COMPLETE\n{source_sha}\n{digest}",
    }
    assert check(valid)
    assert not check({**valid, "issue_url": "https://api.github.com/repos/HuGR-dev/corelink-server/issues/1649"})
    assert not check({**valid, "body": f"ROLLOUT_COMPLETE\n{source_sha}\nsha256:{'0' * 64}"})
    assert not check({**valid, "html_url": "https://github.com/HuGR-dev/corelink-server/issues/1648#issuecomment-1234567"})
    assert not check({"html_url": url, "issue_url": valid["issue_url"], "body": None})


def test_runtime_gate_checks_live_iad_digest_health_and_completed_rollout(tmp_path: Path) -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    command = 'python3 - "$runtime_summary"'
    script = _inline_gate(source, command)
    module_root = tmp_path / "fake_modules"
    fake_scripts = module_root / "scripts"
    fake_scripts.mkdir(parents=True)
    (fake_scripts / "__init__.py").write_text("", encoding="utf-8")
    (fake_scripts / "issue_1648_image_only.py").write_text(textwrap.dedent('''\
        import json, os
        class GateError(Exception): pass
        APP_PATH = "/containers/applications/a033572c-0803-4866-b3a3-61f4812843b1"
        ROLLOUTS_PATH = APP_PATH + "/rollouts"
        NEW_REF = "registry.cloudflare.com/6a1fc1c626fc2628823e60b9db01f5cd/corelink-prod-corelinkserver-prod@sha256:ecd63379d2040c6a891edaeb140fd388f26b5ffc181987c9c777060ced633e8a"
        def require(condition, reason):
            if not condition: raise GateError(reason)
        class API:
            def __init__(self, token):
                if len(token) < 20: raise GateError("credential_not_bound")
            def request(self, method, path):
                assert method == "GET"
                if os.environ.get("FIXTURE_MODE") == "unavailable": raise GateError("provider_result_unknown")
                if path == APP_PATH:
                    return json.load(open(os.environ["APP_FIXTURE"], encoding="utf-8"))
                return json.load(open(os.environ["ROLLOUT_FIXTURE"], encoding="utf-8"))
        def app_snapshot(result):
            require(result.get("id") == "a033572c-0803-4866-b3a3-61f4812843b1", "app_id_drift")
            require(result.get("name") == "corelink-prod-corelinkserver-prod", "app_name_drift")
            health = result["health"]["instances"]
            require(health["healthy"] + health["active"] == 16 and health["failed"] == 0, "health_not_ready")
            require(result["active_rollout_id"] in (None, ""), "app_rollout_active")
            return {"image": result["configuration"]["image"], "version": result["version"], "healthy": health["healthy"], "active": health["active"], "failed": health["failed"]}
        def no_active_rollout(result, app):
            require(not any(item.get("status") in ("pending", "progressing") for item in result), "rollout_active")
    '''), encoding="utf-8")

    expected_ref = "registry.cloudflare.com/6a1fc1c626fc2628823e60b9db01f5cd/corelink-prod-corelinkserver-prod@sha256:ecd63379d2040c6a891edaeb140fd388f26b5ffc181987c9c777060ced633e8a"
    def app(image: str, healthy: int = 16, active: int = 0) -> dict[str, object]:
        return {
            "id": "a033572c-0803-4866-b3a3-61f4812843b1",
            "name": "corelink-prod-corelinkserver-prod",
            "version": 182,
            "configuration": {"image": image},
            "active_rollout_id": None,
            "health": {"instances": {"healthy": healthy, "active": active, "failed": 0}},
        }
    def run(mode: str, image: str = expected_ref, rollout_image: str = expected_ref,
            rollout_version: int = 182, healthy: int = 16, active: int = 0) -> bool:
        app_path, rollout_path, output_path = (tmp_path / "app.json", tmp_path / "rollouts.json", tmp_path / "summary.json")
        app_path.write_text(json.dumps(app(image, healthy, active)), encoding="utf-8")
        rollout_path.write_text(json.dumps([{"status": "completed", "target_version": rollout_version,
                                             "target_configuration": {"image": rollout_image}}]), encoding="utf-8")
        env = {**dict(__import__("os").environ), "PYTHONPATH": str(module_root),
               "APP_FIXTURE": str(app_path), "ROLLOUT_FIXTURE": str(rollout_path),
               "FIXTURE_MODE": mode, "CF_API_TOKEN": "a" * 24}
        result = subprocess.run([sys.executable, "-", str(output_path)], input=script,
                                text=True, capture_output=True, env=env, check=False)
        return result.returncode == 0 and output_path.exists()

    assert run("ready")
    assert not run("ready", image=expected_ref.replace("ecd63379", "00000000"))
    assert not run("ready", rollout_image=expected_ref.replace("ecd63379", "00000000"))
    assert not run("ready", rollout_version=181)
    assert not run("ready", healthy=15, active=1)
    assert not run("unavailable")


def test_all_production_control_queries_are_single_read_only_selects() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    query_ids = ("population", "partition", "hourly", "latency", "heads", "burst", "integrity", "replay", "head_tail")
    queries: dict[str, str] = {}
    for query_id in query_ids:
        match = re.search(rf"^\s*SQL\[{query_id}\]='([^']+)'$", source, re.MULTILINE)
        assert match, f"missing explicit {query_id} SELECT allowlist entry"
        sql = match.group(1)
        assert sql.startswith(("SELECT ", "WITH "))
        assert ";" not in sql
        assert not re.search(r"\b(?:INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|CREATE|PRAGMA|ATTACH|DETACH)\b", sql)
        queries[query_id] = sql

    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE audit_outbox (tenant_id TEXT, region TEXT, enqueued_at INTEGER, emitted_at INTEGER, "
        "sequence_number INTEGER, prev_hash TEXT, chain_hash TEXT, canonical_jcs TEXT, chained_at INTEGER)"
    )
    connection.execute(
        "CREATE TABLE audit_chain_head (tenant_id TEXT, region TEXT, head_signature TEXT, "
        "next_sequence INTEGER, head_hash TEXT)"
    )
    connection.execute(
        "INSERT INTO audit_outbox VALUES ('tenant', 'region', 0, 0, 0, 'prev', 'hash', '{}', 0)"
    )
    for query_id, sql in queries.items():
        rows = connection.execute(sql).fetchall()
        expected_rows = 6 if query_id == "hourly" else 1
        assert len(rows) == expected_rows, f"{query_id} returned {len(rows)} rows"
        if query_id == "hourly":
            assert all(len(row) == 5 and row[4] == rows[0][4] for row in rows)
            starts = [
                datetime.strptime(row[0], "%Y-%m-%dT%H:00:00Z").replace(tzinfo=timezone.utc)
                for row in rows
            ]
            ends = [
                datetime.strptime(row[1], "%Y-%m-%dT%H:00:00Z").replace(tzinfo=timezone.utc)
                for row in rows
            ]
            assert all(end - start == timedelta(hours=1) for start, end in zip(starts, ends))
            assert all(ends[index - 1] == starts[index] for index in range(1, 6))
            assert ends[-1] <= datetime.now(timezone.utc)

    hourly_sql = queries["hourly"]
    assert 'CAST(strftime("%s", "now") AS INTEGER) / 3600 * 3600 AS anchor_s' in hourly_sql
    for offset in range(6):
        upper = "c.anchor_s" if offset == 0 else f"(c.anchor_s - {offset * 3600})"
        lower = f"(c.anchor_s - {(offset + 1) * 3600})"
        assert f"enqueued_at >= {lower} * 1000 AND enqueued_at < {upper} * 1000" in hourly_sql
        assert f"emitted_at >= {lower} * 1000 AND emitted_at < {upper} * 1000" in hourly_sql


def test_failure_receipt_is_bounded_data_free_and_keeps_provider_shape(tmp_path: Path) -> None:
    diagnostic = make_provider_diagnostic(
        "hourly",
        1,
        json.dumps(
            {
                "success": False,
                "errors": [{"code": 7500, "message": "account=db row=private token=private"}],
                "results": [{"event_id": "private"}],
            }
        ),
        "D1_ERROR: tenant=private credential=private",
    )
    validate_provider_diagnostic(diagnostic)
    assert (diagnostic["query_stage"], diagnostic["query_id"]) == ("wrangler_d1_execute", "hourly")
    assert (diagnostic["error_class"], diagnostic["provider_code"]) == ("D1_ERROR", "7500")
    assert diagnostic["semantic_error_category"] == "unknown"
    assert diagnostic["schema_shape"]["root_keys"] == ["errors", "results", "success"]
    assert diagnostic["schema_shape"]["error_entry_keys"] == ["code", "message"]
    assert "private" not in json.dumps(diagnostic)

    receipt = tmp_path / "receipt.json"
    stdout = tmp_path / "stdout.json"
    stderr = tmp_path / "stderr.txt"
    receipt.write_text('{"issue":1668,"queries":[]}\n', encoding="utf-8")
    stdout.write_text("private-value" * (MAX_PROVIDER_OUTPUT_BYTES // 8), encoding="utf-8")
    stderr.write_text(
        "D1_ERROR: " + ("private-value" * (MAX_PROVIDER_OUTPUT_BYTES // 8)), encoding="utf-8"
    )

    record_provider_failure(receipt, "hourly", 1, stdout, stderr)
    recorded = json.loads(receipt.read_text(encoding="utf-8"))["provider_failure"]
    validate_provider_diagnostic(recorded)
    assert recorded["schema_shape"]["stdout_truncated"] is True
    assert recorded["schema_shape"]["stderr_truncated"] is True
    assert "private-value" not in json.dumps(recorded)
    assert len(json.dumps(recorded)) < 2000


def test_provider_query_start_clears_stale_preflight_failure_marker(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_text(
        json.dumps({"failure_reasons": ["read_not_started"], "queries": []}),
        encoding="utf-8",
    )

    mark_query_started(receipt, "population")

    recorded = json.loads(receipt.read_text(encoding="utf-8"))
    assert recorded["failure_reasons"] == []
    assert recorded["provider_queries_started"] == ["population"]


def test_workflow_clears_preflight_marker_after_allowlist_checks_before_provider_call() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    query = source[source.index("run_query() {"):source.index("for query_id in population")]
    marker = 'python3 scripts/b125_readonly_diagnostics.py mark-started "$receipt" "$id"'
    provider = 'CI=1 pnpm --silent dlx wrangler@4.111.0 d1 execute'
    assert marker in query
    assert query.index('[[ ! "$sql" =~') < query.index(marker) < query.index(provider)


def test_singular_wrangler_error_is_classified_without_retaining_message() -> None:
    diagnostic = make_provider_diagnostic(
        "hourly",
        1,
        json.dumps({"error": {"code": 7500, "message": "SQLITE_ERROR: private query data"}}),
        "",
    )
    validate_provider_diagnostic(diagnostic)
    assert diagnostic["error_class"] == "SQLITE_ERROR"
    assert diagnostic["provider_code"] == "7500"
    assert diagnostic["schema_shape"]["root_keys"] == ["error"]
    assert diagnostic["schema_shape"]["error_entry_keys"] == ["code", "message"]
    assert "private query data" not in json.dumps(diagnostic)


def test_singular_string_error_keeps_only_its_shape() -> None:
    diagnostic = make_provider_diagnostic(
        "hourly", 1, '{"error":"SQLITE_ERROR: private column name"}', ""
    )
    validate_provider_diagnostic(diagnostic)
    assert diagnostic["error_class"] == "SQLITE_ERROR"
    assert diagnostic["provider_code"] is None
    assert diagnostic["schema_shape"]["error_entry_kind"] == "string"
    assert diagnostic["schema_shape"]["error_entry_keys"] == []
    assert "private column name" not in json.dumps(diagnostic)


def test_provider_error_categories_are_allowlisted_and_never_retain_messages() -> None:
    cases = {
        "syntax": 'SQLITE_ERROR: near "tenant_secret": syntax error',
        "missing_table": "no such table: audit_private",
        "missing_column": "no such column: tenant_private.secret",
        "bind_mismatch": "Incorrect number of bindings supplied; private=token-secret",
        "unsupported_function": "no such function: secret_function",
        "memory_limit": "SQLITE_NOMEM: out of memory for private tenant",
        "query_timeout": "D1 query execution timed out for private tenant",
        "unknown": "provider failed for tenant=private token=secret",
    }
    for expected, message in cases.items():
        diagnostic = make_provider_diagnostic(
            "hourly", 1, json.dumps({"error": {"code": 7500, "message": message}}), ""
        )
        validate_provider_diagnostic(diagnostic)
        assert diagnostic["semantic_error_category"] == expected
        serialized = json.dumps(diagnostic)
        assert "tenant_secret" not in serialized
        assert "audit_private" not in serialized
        assert "token-secret" not in serialized
        assert "secret_function" not in serialized
        assert "private tenant" not in serialized


def test_diagnostic_mutations_that_add_values_or_identifiers_are_rejected() -> None:
    diagnostic = make_provider_diagnostic(
        "hourly",
        1,
        '{"success":false,"errors":[{"code":7500,"message":"private-value"}]}',
        "D1_ERROR: private-value",
    )
    mutations = []

    with_raw_message = deepcopy(diagnostic)
    with_raw_message["provider_message"] = "private-value"
    mutations.append(with_raw_message)

    with_identifier = deepcopy(diagnostic)
    with_identifier["database_id"] = "database-PRIVATE"
    mutations.append(with_identifier)

    with_unknown_schema_key = deepcopy(diagnostic)
    with_unknown_schema_key["schema_shape"]["root_keys"].append("account_id")
    mutations.append(with_unknown_schema_key)

    with_leaked_schema_count = deepcopy(diagnostic)
    with_leaked_schema_count["schema_shape"]["root_unknown_key_count"] = "account-PRIVATE"
    mutations.append(with_leaked_schema_count)

    with_oversized_exit = deepcopy(diagnostic)
    with_oversized_exit["exit_code"] = 10**1000
    mutations.append(with_oversized_exit)

    with_oversized_key_count = deepcopy(diagnostic)
    with_oversized_key_count["schema_shape"]["root_unknown_key_count"] = 10**1000
    mutations.append(with_oversized_key_count)

    for mutated in mutations:
        try:
            validate_provider_diagnostic(mutated)
        except ValueError:
            continue
        raise AssertionError("unsafe provider diagnostic mutation was accepted")


def test_workflow_keeps_unredacted_provider_output_out_of_artifacts_and_logs() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    assert 'raw_dir="$RUNNER_TEMP/b125-d1"' in source
    assert '2>"$stderr"' in source
    assert 'b125_readonly_diagnostics.py record' in source
    assert 'path: artifacts/b125-audit-throughput-receipt.json' in source
    assert 'path: "$raw_dir"' not in source
    assert 'echo "$stderr"' not in source
    assert 'echo "$raw"' not in source


def _final_receipt_script(now: datetime | None = None) -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    after_queries = source.split(
        "for query_id in population partition hourly latency heads burst integrity replay head_tail; do", 1
    )[1]
    match = re.search(r'python3 - "\$receipt" <<\'PY\'\n(.*?)\n          PY', after_queries, re.DOTALL)
    assert match, "final workflow receipt gate must remain executable Python"
    script = textwrap.dedent(match.group(1))
    clock = now or datetime(2026, 10, 1, 2, 5, tzinfo=timezone.utc)
    fixed_clock = f"datetime({clock.year}, {clock.month}, {clock.day}, {clock.hour}, {clock.minute}, tzinfo=timezone.utc)"
    return script.replace("datetime.now(timezone.utc)", fixed_clock) + "\n"


def _complete_receipt(arrivals: int = 3141, seals: int = 3141, boundary: int = 0,
                      anchor: datetime | None = None) -> dict:
    anchor = anchor or datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc)
    hourly = [
        {
            "window_start_utc": (anchor - timedelta(hours=6-index)).strftime("%Y-%m-%dT%H:00:00Z"),
            "window_end_utc": (anchor - timedelta(hours=5-index)).strftime("%Y-%m-%dT%H:00:00Z"),
            "arrivals": arrivals,
            "sealed_rows": seals,
            "boundary_unsealed": boundary,
        }
        for index in range(6)
    ]
    rows = {
        "population": {"total_rows": 20_000, "unsealed_rows": boundary, "oldest_unsealed_age_ms": 0},
        "partition": {"partition_count": 1, "partition_rows": 20_000, "partition_unsealed_rows": boundary},
        "hourly": hourly,
        "latency": {"valid_latency_rows": 18_846, "min_latency_ms": 1, "mean_latency_ms": 1000,
                    "median_latency_ms": 1000, "p90_latency_ms": 1000, "max_latency_ms": 1000},
        "heads": {"chain_heads": 1, "signed_heads": 1},
        "burst": {"populated_hours": 6, "peak_hour_arrivals": max(arrivals, 513)},
        "integrity": {"sealed_rows": 18_846, "malformed_seals": 0, "negative_latency_rows": 0,
                      "duplicate_chain_hash_rows": 0},
        "replay": {"repeated_sequence_rows": 0, "sequence_gap_rows": 0, "duplicate_sequence_groups": 0},
        "head_tail": {"head_tail_mismatches": 0, "head_behind": 0, "head_ahead": 0,
                      "head_hash_mismatches": 0},
    }
    return {"queries": [{"id": key, "rows": value if isinstance(value, list) else [value]} for key, value in rows.items()]}


def _evaluate_receipt(tmp_path: Path, payload: dict, now: datetime | None = None) -> tuple[int, dict]:
    path = tmp_path / "b125-receipt.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-S", "-", str(path)], input=_final_receipt_script(now), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    return result.returncode, json.loads(path.read_text(encoding="utf-8"))


def test_real_receipt_gate_reconstructs_six_hours_and_applies_owner_threshold(tmp_path: Path) -> None:
    code, receipt = _evaluate_receipt(tmp_path, _complete_receipt())
    assert code == 0
    assert receipt["valid"] is True
    assert receipt["owner_threshold"]["status"] == "PASS"
    assert receipt["owner_threshold"]["qualified_bucket_count"] == 6
    assert all(row["opening_unsealed"] == row["closing_unsealed"] == 0 for row in receipt["measurements"]["hourly"])


def test_real_receipt_gate_rejects_six_complete_hours_with_pre_repair_rows(tmp_path: Path) -> None:
    code, receipt = _evaluate_receipt(
        tmp_path,
        _complete_receipt(anchor=datetime(2026, 10, 1, 1, 0, tzinfo=timezone.utc)),
        now=datetime(2026, 10, 1, 1, 5, tzinfo=timezone.utc),
    )
    assert code != 0
    assert receipt["valid"] is False
    assert "hourly_window_includes_pre_repair_data" in receipt["failure_reasons"]


def test_real_receipt_gate_rejects_invalid_or_inconclusive_boundaries(tmp_path: Path) -> None:
    mutations = []
    null_boundary = _complete_receipt()
    null_boundary["queries"][2]["rows"][0]["boundary_unsealed"] = None
    mutations.append((null_boundary, "INVALID", "hourly_count_null_negative_or_invalid"))
    negative_boundary = _complete_receipt()
    negative_boundary["queries"][2]["rows"][0]["boundary_unsealed"] = -1
    mutations.append((negative_boundary, "INVALID", "hourly_count_null_negative_or_invalid"))
    inconsistent_boundary = _complete_receipt()
    inconsistent_boundary["queries"][2]["rows"][0]["boundary_unsealed"] = 1
    mutations.append((inconsistent_boundary, "INVALID", "hourly_boundary_backlog_inconsistent"))
    empty_hour = _complete_receipt()
    empty_hour["queries"][2]["rows"][0]["arrivals"] = 0
    mutations.append((empty_hour, "INVALID", "hourly_bucket_empty_arrivals_or_seals"))
    negative_reconstruction = _complete_receipt(arrivals=3142, seals=3141)
    mutations.append((negative_reconstruction, "INVALID", "hourly_reconstructed_backlog_negative"))
    wrong_hour = _complete_receipt()
    wrong_hour["queries"][2]["rows"][-1]["window_end_utc"] = "2026-01-01T00:00:00Z"
    mutations.append((wrong_hour, "INVALID", "hourly_window_labels_not_six_complete_consecutive_utc_buckets"))
    no_qualified_demand = _complete_receipt(arrivals=12, seals=12)
    mutations.append((no_qualified_demand, "INCONCLUSIVE", "throughput_capacity_inconclusive_no_qualified_hour"))
    slow_without_demand = _complete_receipt(arrivals=12, seals=12)
    slow_without_demand["queries"][3]["rows"][0]["p90_latency_ms"] = 4_200_001
    mutations.append((slow_without_demand, "FAIL", "p90_seal_latency_above_70_minutes_or_invalid"))
    missing_latency_metric = _complete_receipt()
    del missing_latency_metric["queries"][3]["rows"][0]["median_latency_ms"]
    mutations.append((missing_latency_metric, "INVALID", "latency_median_latency_ms_missing_negative_or_invalid"))
    negative_latency_metric = _complete_receipt()
    negative_latency_metric["queries"][3]["rows"][0]["mean_latency_ms"] = -1
    mutations.append((negative_latency_metric, "INVALID", "latency_mean_latency_ms_missing_negative_or_invalid"))
    nonfinite_latency_metric = _complete_receipt()
    nonfinite_latency_metric["queries"][3]["rows"][0]["max_latency_ms"] = float("inf")
    mutations.append((nonfinite_latency_metric, "INVALID", "latency_max_latency_ms_missing_negative_or_invalid"))
    below_throughput = _complete_receipt(arrivals=3141, seals=3140, boundary=6)
    mutations.append((below_throughput, "FAIL", "throughput_below_3141_bucket_0"))
    growing_backlog = _complete_receipt(arrivals=3142, seals=3141, boundary=6)
    mutations.append((growing_backlog, "FAIL", "six_hour_backlog_growth"))
    for payload, expected_status, expected_reason in mutations:
        code, receipt = _evaluate_receipt(tmp_path, payload)
        assert code != 0
        assert receipt["valid"] is False
        assert receipt["owner_threshold"]["status"] == expected_status
        assert expected_reason in receipt["failure_reasons"]
