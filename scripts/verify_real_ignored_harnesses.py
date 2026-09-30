#!/usr/bin/env python3
"""Static and mutation checks for the B-068 real-harness executor.

This verifier is intentionally dependency-free.  The executor is an allow-list
of exact test targets, so a successful grep for a phrase in a comment is not
evidence that a harness is wired.  The checks below ignore comment-only lines,
then run negative mutations for the failure modes that previously made this
backlog item look closed: partial selection, wrong tests, secret exposure,
comment bait, and missing workflow triggers.
"""

from __future__ import annotations

import hashlib
import json
import re
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/real-ignored-harnesses.yml"
CONTRACT_WORKFLOW_PATH = ROOT / ".github/workflows/issue-1650-real-integration-contract.yml"
CAMPAIGN_WORKFLOW_PATH = ROOT / ".github/workflows/campaign-ci.yml"
RUNNER_PATH = ROOT / "scripts/run-real-ignored-harnesses.sh"
MANIFEST_PATH = ROOT / "scripts/real-ignored-harness-manifest.json"
SEED_PATH = ROOT / "crates/corelink-pat/tests/emit_e2e_seed.rs"

REQUIRED_D1 = (
    "d1_acquire_lock_then_held_then_release",
    "d1_dpa_and_active_subscription_reads",
    "d1_persist_free_active_does_not_count_as_a_subscription",
    "d1_http_blob_meta_round_trip",
    "d1_http_tenant_admin_lookup_round_trip",
    "d1_audit_write_blocking_records_oaudit_phase",
)
REQUIRED_R2 = (
    "r2_cas_list_durable_audit_failure_precedes_storage",
    "storage_r2_round_trip",
    "cas_idempotent_rewrite_reports_durable_false",
    "delete_if_present_credits_size_once_then_none",
    "r2_cas_exists_batch_fails_closed_on_bad_audit_creds",
)
REQUIRED_STRIPE = (
    "live_create_customer",
    "live_get_customer_404",
    "live_create_checkout_session_starter",
    "live_idempotent_checkout_returns_same_session",
    "live_billing_portal_session",
    "live_authentication_failure_bad_token",
)
REQUIRED_NEON = (
    "sync_chunk_persists_rows_against_live_postgres",
    "sync_chunk_is_idempotent_on_replay",
    "aggregate_event_count_against_live_postgres",
    "aggregate_timeline_against_live_postgres",
    "rls_policy_isolates_tenants_against_live_postgres",
)

REQUIRED_TARGET_SOURCES = {
    **{target: "crates/corelink-container/src/routes/tier_select_store.rs" for target in REQUIRED_D1[:3]},
    "d1_http_blob_meta_round_trip": "crates/corelink-container/src/storage/d1_http.rs",
    "d1_http_tenant_admin_lookup_round_trip": "crates/corelink-container/src/storage/d1_http.rs",
    "d1_audit_write_blocking_records_oaudit_phase": "crates/corelink-container/src/storage/d1_audit_sink/tests_phase_attribution.rs",
    "r2_cas_list_durable_audit_failure_precedes_storage": "crates/corelink-container/src/storage/r2_s3_parts/tests_1_network.rs",
    "storage_r2_round_trip": "crates/corelink-container/src/storage/r2_s3_parts/tests_1_network.rs",
    "cas_idempotent_rewrite_reports_durable_false": "crates/corelink-container/src/storage/r2_s3_parts/tests_1_network.rs",
    "delete_if_present_credits_size_once_then_none": "crates/corelink-container/src/storage/r2_s3_parts/tests_1_network.rs",
    "r2_cas_exists_batch_fails_closed_on_bad_audit_creds": "crates/corelink-container/src/storage/r2_s3_parts/tests_2.rs",
    **{target: "crates/corelink-stripe-real/tests/live_integration.rs" for target in REQUIRED_STRIPE},
    **{target: "crates/corelink-audit-chain/tests/neon_shadow_real.rs" for target in REQUIRED_NEON},
}

# Byte-locked source manifest for the exact files containing the selected
# harnesses. This is intentionally reviewed data, not a generated claim: any
# legitimate source edit (including cfg_attr/raw/unicode/macro changes) must
# update this manifest in the same reviewed change before semantic checks can
# run. The self-hosted runner's PATH/toolchain remains the infrastructure trust
# boundary; this manifest binds the repository-owned selector/source inputs.
SOURCE_SHA256 = {
    "crates/corelink-container/src/routes/tier_select_store.rs": "2c8420e87367772276ac807dee0a9c386f304afecbb842e1214a91be3c120602",
    "crates/corelink-container/src/storage/d1_http.rs": "258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5",
    "crates/corelink-container/src/storage/d1_audit_sink/tests_phase_attribution.rs": "474d45a030f333bfb73d7152bc2a802d9d29b8af2d559c5310f9a683bc74e717",
    "crates/corelink-container/src/storage/r2_s3_parts/tests_1_network.rs": "2148abe19ae9b119dc17eca0f242e983b47f8f6100d8d6fbba0536aafcc88af7",
    "crates/corelink-container/src/storage/r2_s3_parts/tests_2.rs": "1589c0bf78b5ecee786f39e71e66feb3bcd387ba1465d4ad5f22133cdcf14b4e",
    "crates/corelink-stripe-real/tests/live_integration.rs": "5f7a38a426c1ecbb7002e399df6cdcaf8c5a425500278c6dcf741271d7cbab40",
    "crates/corelink-audit-chain/tests/neon_shadow_real.rs": "dfd22738e96d82695b40addf64b3dbaf611fbd8026346f0b4e33b28f10fe79eb",
}

# The #1700 delivery changes this source and its staging topology together.
# Keep the trusted preimage usable until that exact delivery lands, then bind
# the source to the new topology state so reverting only the Rust file fails.
STAGING_D1_PROXY_TOPOLOGY_PATH = "infra/staging/topology.json"
STAGING_D1_PROXY_SOURCE_PATH = "crates/corelink-container/src/storage/d1_http.rs"
STAGING_D1_PROXY_TOPOLOGY_PREIMAGE_SHA256 = (
    "586665e34c11bf91a34fb83247fdbafec9fdfb8e7a336ba4da6f5bda8266dd99"
)
STAGING_D1_PROXY_TOPOLOGY_TARGET_SHA256 = (
    "a55b4e72f63569b74539e9b42a8c0b34bd964f9213a5696b535fb2eb4ca24b14"
)
STAGING_D1_PROXY_SOURCE_PREIMAGE_SHA256 = (
    "57df01654b44a12c57663d4543b1290125c87346e014e3b8210624a2d9cb6dd2"
)
STAGING_D1_PROXY_SOURCE_TARGET_SHA256 = (
    "258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5"
)


def safe_failure_diagnostic(raw_output: str) -> str:
    """Map private Cargo output to a small, non-sensitive diagnostic class.

    Never return a matched line, provider body, source location, URL, or test
    payload. Every result is either a fixed label or a compiler/HTTP status
    code selected by a narrow numeric expression.
    """

    if match := re.search(r"\berror\[(E[0-9]{4})\]", raw_output):
        return f"rustc_{match.group(1)}"
    if re.search(r"(?i)\bcould not compile\b", raw_output):
        return "rust_compile_error"
    if match := re.search(r"(?i)\b(?:d1\s+http|http\s+status|status(?:_code)?|status\s+code)\s*[:= ]\s*([1-5][0-9]{2})\b", raw_output):
        return f"provider_http_{match.group(1)}"
    if re.search(r"(?i)\bconnection refused\b", raw_output):
        return "network_connection_refused"
    if re.search(r"(?i)\b(?:timed out|timeout)\b", raw_output):
        return "network_timeout"
    if re.search(r"(?i)\b(?:name or service not known|temporary failure in name resolution|dns resolution failed)\b", raw_output):
        return "network_dns_failure"
    if re.search(r"(?i)\bpanicked at\b", raw_output):
        return "test_panic"
    if re.search(r"(?m)^test result:\s+FAILED\b", raw_output):
        return "test_assertion_failure"
    return "unclassified_failure"


def failure_diagnostic_negative_controls() -> None:
    """Prove classification retains no token, DSN, payload, or personal data."""

    secret = "CF_DIAGNOSTIC_SENTINEL_never_emit"
    dsn = "postgresql://private-user:private-pass@private.example.test/db"
    personal = "private.person@example.test"
    fixtures = (
        (f"error[E0433]: {secret} {dsn} {personal}", "rustc_E0433"),
        (f"D1 HTTP 503: {secret} DSN={dsn} user={personal}", "provider_http_503"),
        (f"thread 'd1' panicked at {secret} {dsn} {personal}", "test_panic"),
        (f"opaque provider response {secret} {dsn} {personal}", "unclassified_failure"),
    )
    for raw_output, expected in fixtures:
        summary = safe_failure_diagnostic(raw_output)
        if summary != expected:
            fail(f"failure diagnostic fixture expected {expected}, received {summary}")
        if any(marker in summary for marker in (secret, dsn, personal, raw_output)):
            fail("failure diagnostic exposed private input material")

CONTRACT_TRIGGER_INPUTS = (
    ".github/workflows/issue-1650-real-integration-contract.yml",
    ".github/workflows/campaign-ci.yml",
    ".github/workflows/real-ignored-harnesses.yml",
    "scripts/run-real-ignored-harnesses.sh",
    "scripts/real-ignored-harness-manifest.json",
    "scripts/verify_real_ignored_harnesses.py",
    "scripts/probe_i2563_d1_token_scope.py",
    "scripts/verify_i1650_real_integration_readiness.py",
    "docs/handoff/2026-09-22-i1650-real-integration-readiness.json",
    "crates/corelink-pat/tests/emit_e2e_seed.rs",
    "crates/corelink-stripe-real/src/client.rs",
    "scripts/verify_stripe_harness_cleanup_receipt.py",
    "tests/test_stripe_harness_cleanup_receipt.py",
    "scripts/stripe_test_mode_evidence.py",
    "tests/test_stripe_test_mode_evidence.py",
    ".github/workflows/issue-1649-stripe-test-mode.yml",
    *SOURCE_SHA256.keys(),
)


def code_lines(text: str) -> list[str]:
    """Return non-blank, non-comment lines.

    We deliberately do not use a broad regex over the raw file: an attacker
    (or a stale handoff) must not be able to satisfy a gate by leaving the
    required command only in a comment.
    """

    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def code_text(text: str) -> str:
    return "\n".join(code_lines(text))


def workflow_run_lines(text: str) -> list[str]:
    """Extract active YAML run scalars, excluding inline comment bait."""
    runs: list[str] = []
    in_block = False
    indent = 0
    block_lines = 0
    for raw in text.splitlines():
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if in_block:
            current = len(raw) - len(stripped)
            if current <= indent:
                in_block = False
            else:
                runs.append(stripped.split(" #", 1)[0].rstrip())
                block_lines += 1
                continue
        match = re.match(r"^(\s*)run:\s*([|>])?\s*(.*)$", raw)
        if not match:
            continue
        if match.group(2):
            in_block = True
            indent = len(match.group(1))
            block_lines = 0
            continue
        value = match.group(3).split(" #", 1)[0].rstrip()
        if value:
            runs.append(value)
    if in_block and block_lines == 0:
        raise AssertionError("workflow run block is unterminated")
    return runs


def case_branch(text: str, label: str) -> str:
    """Return one executable branch from the runner's allow-list case."""

    lines = code_lines(text)
    marker = f"{label})"
    try:
        start = next(i for i, line in enumerate(lines) if line.strip().startswith(marker))
    except StopIteration as exc:
        raise AssertionError(f"runner case branch is missing: {label}") from exc
    first_remainder = lines[start].strip()[len(marker) :].strip()
    if ";;" in first_remainder:
        return first_remainder.split(";;", 1)[0].strip()
    body: list[str] = [first_remainder] if first_remainder else []
    for line in lines[start + 1 :]:
        if line.strip() == ";;":
            return "\n".join(body)
        body.append(line)
    raise AssertionError(f"runner case branch is unterminated: {label}")


def function_body(text: str, name: str) -> str:
    """Extract a simple shell function body for side-effect checks."""

    marker = f"{name}() {{"
    start = text.find(marker)
    if start < 0:
        fail(f"runner function is missing: {name}")
    end = text.find("\n}", start)
    if end < 0:
        fail(f"runner function is unterminated: {name}")
    return text[start:end]


def fail(message: str) -> None:
    raise AssertionError(message)


def verify_source_digests(root: Path = ROOT, overrides: dict[str, bytes] | None = None) -> None:
    """Fail before semantic parsing if any bound source byte changed."""
    def read(relative: str) -> bytes:
        if overrides and relative in overrides:
            return overrides[relative]
        return (root / relative).read_bytes()

    expected_sources = dict(SOURCE_SHA256)
    topology_digest = hashlib.sha256(read(STAGING_D1_PROXY_TOPOLOGY_PATH)).hexdigest()
    source_digest = {
        STAGING_D1_PROXY_TOPOLOGY_PREIMAGE_SHA256: STAGING_D1_PROXY_SOURCE_PREIMAGE_SHA256,
        STAGING_D1_PROXY_TOPOLOGY_TARGET_SHA256: STAGING_D1_PROXY_SOURCE_TARGET_SHA256,
    }.get(topology_digest)
    if source_digest is None:
        fail("staging topology digest is outside the reviewed D1 source transition")
    expected_sources[STAGING_D1_PROXY_SOURCE_PATH] = source_digest
    for relative, expected in expected_sources.items():
        target = root / relative
        body = overrides[relative] if overrides and relative in overrides else target.read_bytes()
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            fail(f"source digest mismatch (reviewed manifest required): {relative}")


def verify_source_binding_manifest(
    target_sources: dict[str, str] | None = None,
) -> None:
    """Require every selected source, and no unselected source, to be digest-bound."""
    bound_sources = REQUIRED_TARGET_SOURCES if target_sources is None else target_sources
    if set(bound_sources.values()) != set(SOURCE_SHA256):
        fail("target/source binding is not closed over the reviewed digest manifest")


def verify_stripe_cleanup_contract(root: Path = ROOT) -> None:
    """Bind the wallet-broker-only cleanup and public receipt controls."""
    client = (root / "crates/corelink-stripe-real/src/client.rs").read_text(encoding="utf-8")
    harness = (root / "crates/corelink-stripe-real/tests/live_integration.rs").read_text(encoding="utf-8")
    runner = (root / "scripts/run-real-ignored-harnesses.sh").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/real-ignored-harnesses.yml").read_text(encoding="utf-8")
    pr_workflow = (root / ".github/workflows/issue-1650-real-integration-contract.yml").read_text(encoding="utf-8")
    receipt = (root / "scripts/verify_stripe_harness_cleanup_receipt.py").read_text(encoding="utf-8")
    required = (
        (client, "metadata[test_run_id]"),
        (client, "pub fn cleanup_harness_checkout"),
        (client, "pub fn cleanup_harness_customer"),
        (client, "payment_status"),
        (client, "/v1/payment_intents?customer="),
        (client, ".delete(&url)"),
        (client, 'env::var("GITHUB_RUN_ID")'),
        (client, '"GITHUB_EVENT_NAME"'),
        (client, '"GITHUB_WORKFLOW"'),
        (harness, "impl Drop for HarnessCleanup"),
        (harness, "fn current_test_selector()"),
        (harness, "fn repo_receipt_dir()"),
        (harness, "fn safe_run_id(value: &str)"),
        (harness, "catch_unwind"),
        (harness, "id_sha256"),
        (harness, "panic_still_attempts_guarded_cleanup_and_receipt_redacts_ids"),
        (harness, "failed_checkout_creation_cleans_customer_before_returning_error"),
        (harness, "missing_checkout_url_expires_session_then_deletes_customer_without_ids_in_error"),
        (runner, "GITHUB_RUN_ID must be a bounded numeric run selector"),
        (runner, 'readonly RECEIPT_DIR="${GITHUB_WORKSPACE:-.}/artifacts/real-ignored-harnesses"'),
        (runner, 'if cargo test --locked "$@" "$expected" -- --ignored --nocapture'),
        (runner, "verify_stripe_harness_cleanup_receipt.py"),
        (workflow, "inputs.profile == 'stripe' || inputs.profile == 'all'"),
        (workflow, "GITHUB_RUN_ID alone is not"),
        (receipt, "expired_readback_pass"),
        (receipt, "deleted_readback_pass"),
        (receipt, '"id_sha256"'),
    )
    if missing := [fragment for source, fragment in required if fragment not in source]:
        fail(f"Stripe cleanup contract is missing reviewed gate(s): {missing}")
    hosted_required = (
        "pull_request:",
        "ref: ${{ github.event.pull_request.head.sha }}",
        'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"',
        "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8",
        "toolchain: 1.91.1",
        "arduino/setup-protoc@f4d5893b897028ff5739576ea0409746887fa536",
        "cargo test --locked -p corelink-stripe-real --features live-integration --test live_integration cleanup_fault_injection -- --nocapture",
        "persist-credentials: false",
    )
    if missing := [fragment for fragment in hosted_required if fragment not in pr_workflow]:
        fail(f"credentialless hosted Rust fault-injection gate is incomplete: {missing}")
    if "${{ secrets." in pr_workflow:
        fail("credentialless hosted Rust fault-injection gate must not reference provider secrets")


def verify_exact_manifest() -> None:
    """Keep the human-reviewed test inventory closed over the executor."""
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"exact test manifest is unreadable: {exc}")
    profiles = manifest.get("profiles")
    if manifest.get("schema_version") != 1 or not isinstance(profiles, dict):
        fail("exact test manifest schema is invalid")
    expected_names = {
        "d1": REQUIRED_D1,
        "r2": REQUIRED_R2,
        "stripe": REQUIRED_STRIPE,
        "neon": REQUIRED_NEON,
    }
    expected_packages = {
        "d1": ("corelink-server", "lib", ()),
        "r2": ("corelink-server", "lib", ()),
        "stripe": ("corelink-stripe-real", "test/live_integration", ("live-integration",)),
        "neon": ("corelink-audit-chain", "test/neon_shadow_real", ("neon-real",)),
    }
    expected_env = {
        "d1": ("CLOUDFLARE_ACCOUNT_ID", "CF_API_TOKEN", "D1_DATABASE_ID"),
        "r2": ("CLOUDFLARE_ACCOUNT_ID", "CF_API_TOKEN", "D1_DATABASE_ID", "R2_S3_ENDPOINT", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY", "R2_TEST_BUCKET"),
        "stripe": ("HUGR_WALLET_BASE", "HUGR_WALLET_TOKEN", "HUGR_STRIPE_REF", "STRIPE_AUTH_MODE", "STRIPE_PRICE_ID_STARTER"),
        "neon": ("NEON_TEST_DSN",),
    }
    if set(profiles) != set(expected_names):
        fail("exact test manifest profile set drifted")
    for profile, names in expected_names.items():
        entry = profiles[profile]
        package, target, features = expected_packages[profile]
        if entry.get("package") != package or entry.get("target") != target:
            fail(f"exact test manifest command drifted: {profile}")
        if tuple(entry.get("features", ())) != features:
            fail(f"exact test manifest features drifted: {profile}")
        if tuple(entry.get("required_env", ())) != expected_env[profile]:
            fail(f"exact test manifest environment gate drifted: {profile}")
        tests = entry.get("tests")
        if not isinstance(tests, list) or tuple(item.get("name") for item in tests) != names:
            fail(f"exact test manifest test names drifted: {profile}")
        for item in tests:
            if item.get("source") != REQUIRED_TARGET_SOURCES.get(item.get("name")):
                fail(f"exact test manifest source binding drifted: {profile}/{item.get('name')}")


def rust_code_without_comments_and_strings(body: str) -> str:
    """Blank Rust comments/strings (including raw strings) but keep newlines."""
    out: list[str] = []
    state = "code"
    block_depth = 0
    raw_hashes = 0
    escaped = False
    i = 0
    while i < len(body):
        char = body[i]
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out.extend("  "); i += 2; state = "line"; continue
            if char == "/" and nxt == "*":
                out.extend("  "); i += 2; block_depth = 1; state = "block"; continue
            if char == "r":
                marker = re.match(r'r(#{0,255})"', body[i:])
                if marker:
                    raw_hashes = len(marker.group(1)); out.extend(" " * len(marker.group(0)))
                    i += len(marker.group(0)); state = "raw"; continue
            if char in ('"', "'"):
                out.append(" "); i += 1; state = char; escaped = False; continue
            out.append(char); i += 1; continue
        if state == "line":
            out.append("\n" if char == "\n" else " "); i += 1
            if char == "\n": state = "code"
            continue
        if state == "block":
            if char == "/" and nxt == "*": out.extend("  "); i += 2; block_depth += 1; continue
            if char == "*" and nxt == "/":
                out.extend("  "); i += 2; block_depth -= 1
                if block_depth == 0: state = "code"
                continue
            out.append("\n" if char == "\n" else " "); i += 1; continue
        if state == "raw":
            closing = '"' + ('#' * raw_hashes)
            if body.startswith(closing, i):
                out.extend(" " * len(closing)); i += len(closing); state = "code"; continue
            out.append("\n" if char == "\n" else " "); i += 1; continue
        out.append("\n" if char == "\n" else " "); i += 1
        if escaped: escaped = False
        elif char == "\\": escaped = True
        elif char == state: state = "code"
    return "".join(out)


def exact_ignored_source(
    body: str,
    target: str,
    *,
    allowed_cfg: str | None = None,
) -> bool:
    code = rust_code_without_comments_and_strings(body)
    pattern = rf"(?m)^[ \t]*(?:(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+{re.escape(target)}\s*\()"
    declarations = list(re.finditer(pattern, code))
    if len(declarations) != 1:
        return False
    declaration = declarations[0]

    def balanced_end(opening: int) -> int:
        matching = {"{": "}", "(": ")", "[": "]"}
        stack = [code[opening]]
        cursor = opening + 1
        while cursor < len(code) and stack:
            char = code[cursor]
            if char in matching:
                stack.append(char)
            elif char == matching[stack[-1]]:
                stack.pop()
            cursor += 1
        return cursor

    # A macro_rules! body is not an executable test declaration: Cargo can
    # compile it successfully while never expanding/invoking it. Rust macro
    # bodies may use any of {}, (), or [] as their outer delimiter.
    for macro in re.finditer(r"macro_rules!\s*[A-Za-z_][A-Za-z0-9_]*\s*([\{\(\[])", code):
        end = balanced_end(macro.start(1))
        if macro.end() <= declaration.start() < end:
            return False

    # cfg on the crate/module containing this harness can silently remove the
    # test from the compiled target. These real harnesses must always compile;
    # reject every cfg attribute rather than trying to evaluate expressions.
    crate_cfg = re.findall(
        r"(?m)^\s*#!\[\s*cfg\s*\(([^\n]*)\)\s*\]\s*$",
        body[: declaration.start()],
    )
    if crate_cfg:
        if allowed_cfg is None or crate_cfg != [allowed_cfg]:
            return False

    line_start = code.rfind("\n", 0, declaration.start()) + 1
    prior = code[:line_start].splitlines()
    attrs: list[str] = []
    while prior and re.fullmatch(r"\s*#\[[^\n]*\]\s*", prior[-1]):
        attrs.insert(0, prior.pop().strip())
    if not attrs or not re.fullmatch(r"#\[ignore(?:\s*=\s*[^]]+)?\]", attrs[-1]):
        return False
    if not any(re.search(r"#\[\s*(?:tokio::)?test(?:\s*\(|\s*\])", attr, re.IGNORECASE) for attr in attrs):
        return False
    if any(re.match(r"#\[\s*cfg(?:\s*\(|\s*\])", attr, re.IGNORECASE) for attr in attrs):
        return False

    # Find enclosing module items and inspect only their contiguous attributes;
    # unrelated cfg modules elsewhere in the source do not taint this target.
    for module in re.finditer(r"(?m)^[ \t]*(?:(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{)", code):
        end = balanced_end(code.find("{", module.start(), module.end()))
        if module.end() <= declaration.start() < end:
            module_line = code.rfind("\n", 0, module.start()) + 1
            module_prior = code[:module_line].splitlines()
            module_attrs: list[str] = []
            while module_prior and re.fullmatch(r"\s*#\[[^\n]*\]\s*", module_prior[-1]):
                module_attrs.insert(0, module_prior.pop().strip())
            if any(re.match(r"#\[\s*cfg(?:\s*\(|\s*\])", attr, re.IGNORECASE) for attr in module_attrs):
                module_cfg = re.findall(
                    r"(?m)^\s*#\[\s*cfg\s*\(([^\n]*)\)\s*\]\s*$",
                    body[:module.start()],
                )
                if allowed_cfg is None or module_cfg != [allowed_cfg]:
                    return False
    return True


def assert_contract(workflow: str, runner: str) -> None:
    # Digest binding is the first source gate; parser/attribute checks are
    # defense in depth and must never silently bless a changed source file.
    verify_exact_manifest()
    verify_source_binding_manifest()
    verify_source_digests()
    verify_stripe_cleanup_contract()
    wf = code_text(workflow)
    sh = code_text(runner)
    real_job = workflow_job(workflow, "real-integration")
    runs = workflow_run_lines(real_job)

    # The only event that may inject credentials is a deliberate operator
    # dispatch.  Anchoring to YAML keys keeps prose/comment bait irrelevant.
    if not re.search(r"(?m)^on:\s*$", wf):
        fail("workflow has no top-level on block")
    if not re.search(r"(?m)^\s{2}workflow_dispatch:\s*(?:\{\})?\s*$", wf):
        fail("workflow_dispatch trigger is missing")
    for event in ("pull_request", "pull_request_target", "push", "schedule", "workflow_call"):
        if re.search(rf"(?m)^\s{{2}}{re.escape(event)}:\s*", wf):
            fail(f"untrusted/automatic trigger is present: {event}")
    if 'test "$GITHUB_REF" = "refs/heads/main"' not in wf:
        fail("executor is not pinned to the protected main ref")
    if 'test "$GITHUB_EVENT_NAME" = "workflow_dispatch"' not in wf:
        fail("executor does not fail closed on event type")
    if "github.repository == 'HuGR-dev/corelink-server'" not in wf or 'test "$GITHUB_REPOSITORY" = "HuGR-dev/corelink-server"' not in wf:
        fail("executor is not scoped to the canonical server repository")
    if "github.repository_id == '1232040291'" not in wf or 'test "$GITHUB_REPOSITORY_ID" = "1232040291"' not in wf:
        fail("executor is not scoped to the stable server repository ID")
    if "if: github.repository == 'HuGR-dev/corelink-server' && github.repository_id == '1232040291' && github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected && inputs.profile != 'all'" not in wf:
        fail("real executor job lacks canonical repository, stable-ID, protected-main dispatch guard")
    reject_job = workflow_job(workflow, "reject-all")
    if "inputs.profile == 'all'" not in reject_job or "exit 1" not in workflow_run_lines(reject_job):
        fail("all profile is not explicitly rejected without D1 credentials")
    if re.search(r"\b(?:secrets|vars)\.", code_text(reject_job)) or re.search(r"(?m)^\s*environment:\s*", code_text(reject_job)):
        fail("all-profile refusal job accesses a protected environment or secret")
    if not re.search(r"(?m)^\s{4}runs-on:\s*ubuntu-24\.04\s*$", real_job):
        fail("real executor must use a GitHub-hosted runner")

    # The workflow must have a selectable, bounded profile set.
    for profile in ("d1", "r2", "stripe", "neon"):
        if not re.search(rf"(?m)^\s+-\s+{profile}\s*$", wf):
            fail(f"workflow profile option is missing: {profile}")
    if re.search(r"(?m)^\s+-\s+all\s*$", wf) or "default: all" in wf:
        fail("unsafe multi-provider all profile remains selectable")
    expected_environment = "environment: ${{ inputs.profile == 'd1' && 'real-d1-2563' || 'real-integration' }}"
    if expected_environment not in wf:
        fail("D1 isolated environment routing is missing")
    if "persist-credentials: false" not in wf:
        fail("checkout credential persistence is not disabled")
    if "python3 scripts/verify_real_ignored_harnesses.py" not in wf:
        fail("workflow does not run the semantic executor guard")
    if 'REAL_HARNESS_PROFILE: ${{ inputs.profile }}' not in wf:
        fail("workflow does not pass the profile through an environment variable")
    if 'bash scripts/run-real-ignored-harnesses.sh "$REAL_HARNESS_PROFILE"' not in wf:
        fail("workflow interpolates the dispatch input into shell source")
    if 'bash scripts/run-real-ignored-harnesses.sh "${{ inputs.profile }}"' in wf:
        fail("dispatch input is interpolated directly into shell source")
    for name in ("R2_S3_ENDPOINT", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY"):
        expected = f"{name}: ${{{{ (inputs.profile == 'r2' || inputs.profile == 'all') && secrets.{name} || '' }}}}"
        if expected not in wf:
            fail(f"R2 credential is not restricted to the R2/all profile: {name}")
    expected_bucket = "R2_TEST_BUCKET: ${{ (inputs.profile == 'r2' || inputs.profile == 'all') && vars.R2_TEST_BUCKET || '' }}"
    if expected_bucket not in wf:
        fail("R2 test bucket is not restricted to the R2/all profile")
    expected_neon = "NEON_TEST_DSN: ${{ (inputs.profile == 'neon' || inputs.profile == 'all') && secrets.NEON_TEST_DSN || '' }}"
    if expected_neon not in wf:
        fail("Neon credential is not restricted to the Neon/all profile")
    expected_probe = (
        'if [[ "$REAL_HARNESS_PROFILE" == "d1" ]]; then',
        'python3 -S scripts/probe_i2563_d1_token_scope.py',
        'fi',
    )
    if not all(line in runs for line in expected_probe):
        fail("D1 token scope preflight is missing")
    probe_start = runs.index(expected_probe[0])
    probe_end = runs.index(expected_probe[2], probe_start + 1)
    if runs[probe_start + 1:probe_end] != [
        'echo "::add-mask::${CF_API_TOKEN:-}"',
        expected_probe[1],
    ] or probe_end >= runs.index('bash scripts/run-real-ignored-harnesses.sh "$REAL_HARNESS_PROFILE"'):
        fail("D1 token scope preflight is not isolated before the real executor")
    probe_source = (ROOT / "scripts/probe_i2563_d1_token_scope.py").read_text(encoding="utf-8")
    for required in (
        'ACCOUNT = "51284495e71acdb5a7677e7383ab026b"',
        'OLD_ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd"',
        'DB_NAME_PREFIX = "corelink-issue-2563-d1-"',
        'old_status not in (401, 403)',
        'target_status != 200',
    ):
        if required not in probe_source:
            fail("D1 token scope probe target or denial contract changed")
    if runs.count("python3 scripts/verify_real_ignored_harnesses.py") != 1:
        fail("semantic executor guard is missing or only comment bait")
    if runs.count('bash scripts/run-real-ignored-harnesses.sh "$REAL_HARNESS_PROFILE"') != 1:
        fail("real executor wiring is missing or only comment bait")
    if 'readonly RECEIPT_SHA="${GITHUB_SHA:-}"' not in sh:
        fail("receipt does not bind results to the GitHub run SHA")
    if '[[ "$RECEIPT_SHA" =~ ^[0-9a-f]{40}$ ]]' not in sh:
        fail("receipt does not reject a missing or malformed exact Git SHA")
    if '{"sha":"%s","profile":"%s"' not in sh or '"$RECEIPT_SHA" "$profile"' not in sh:
        fail("test receipt entries do not carry the exact Git SHA")
    if '2>&1 | tee "$log_file"' in sh:
        fail("raw Cargo output is copied into an uploadable artifact")
    if ' >"$raw_log" 2>&1' not in sh or 'tee "$log_file"' in sh:
        fail("raw Cargo output is not isolated from Actions logs and artifacts")
    if 'LAST_DIAGNOSTIC_CLASS="$(python3 scripts/verify_real_ignored_harnesses.py --classify-failure "$raw_log")"' not in sh:
        fail("failed Cargo output is not reduced to a sanitized diagnostic class")
    if 'status=failed diagnostic_class=%s' not in sh:
        fail("failed test artifact omits its sanitized diagnostic class")
    if '"diagnostic_class":"%s"' not in sh:
        fail("failed test receipt omits its sanitized diagnostic class")
    for status in ("failed", "not-discovered", "passed"):
        if f"sha=%s profile=%s test=%s status={status}" not in sh:
            fail(f"redacted test log summary is missing status: {status}")
    if 'rm -f -- "$raw_log"' not in sh or 'for raw_log in "${RAW_LOGS[@]}"' not in sh:
        fail("private raw output temp files are not deterministically cleaned up")

    # No path in this executor may receive the PAT signing key or invoke the
    # side-effecting seed.  Check executable content, not explanatory comments.
    forbidden = ("CORELINK_PAT_SIGNING_KEY_HEX", "emit_e2e_seed", "PAT_PLAINTEXT", "SEED_SQL")
    for token in forbidden:
        if token in wf or token in sh:
            fail(f"PAT seed/secret reached the executor: {token}")
    if "CORELINK_PAT_SIGNING_KEY_HEX" in workflow or "emit_e2e_seed" in workflow:
        fail("workflow comments must not create a seed/secret-shaped selector")

    # Exact target coverage: every real ignored class has an executor, and the
    # executor cannot quietly replace one with an unrelated test.
    expected_runner_targets = [
        (profile, target)
        for profile, targets in (
            ("d1", REQUIRED_D1),
            ("r2", REQUIRED_R2),
            ("stripe", REQUIRED_STRIPE),
            ("neon", REQUIRED_NEON),
        )
        for target in targets
    ]
    actual_runner_targets = [
        (match.group(1), match.group(2))
        for line in runner.splitlines()
        if (match := re.match(r"^\s*run_cargo\s+(d1|r2|stripe|neon)\s+([A-Za-z0-9_]+)\s+", line))
    ]
    if actual_runner_targets != expected_runner_targets:
        fail("runner target order/set does not match the exact test manifest")
    for target in REQUIRED_D1 + REQUIRED_R2 + REQUIRED_STRIPE + REQUIRED_NEON:
        if target not in sh:
            fail(f"required real target is not selected: {target}")
    required_fragments = (
        "run_cargo stripe live_create_customer --package corelink-stripe-real --features live-integration --test live_integration",
        "run_cargo neon sync_chunk_persists_rows_against_live_postgres --package corelink-audit-chain --features neon-real --test neon_shadow_real",
        'case "$PROFILE" in',
        "d1) preflight_d1; run_d1",
        "r2) preflight_r2; run_r2",
        "stripe) preflight_stripe; run_stripe",
        "neon) preflight_neon; run_neon",
        "all)",
        'die "unknown harness profile:',
        "--ignored --nocapture",
    )
    for fragment in required_fragments:
        if fragment not in sh:
            fail(f"executor allow-list fragment is missing: {fragment}")

    # Preflights must be pure checks.  In particular, `all` must finish every
    # check before its first cargo invocation, otherwise a missing late secret
    # could leave earlier real tests with external side effects.
    for name in ("preflight_d1", "preflight_r2", "preflight_stripe", "preflight_neon"):
        body = code_text(function_body(runner, name))
        if "run_cargo" in body or re.search(r"\bcargo\b", body):
            fail(f"preflight has a side effect: {name}")
    all_branch = case_branch(runner, "all")
    expected_preflights = ("preflight_d1", "preflight_r2", "preflight_stripe", "preflight_neon")
    positions = [all_branch.find(name) for name in expected_preflights]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail("all profile does not run every preflight in order")
    first_run = all_branch.find("run_d1")
    if first_run < 0 or first_run < positions[-1]:
        fail("all profile invokes a harness before the final preflight")
    for profile, preflight, runner_fn in (
        ("d1", "preflight_d1", "run_d1"),
        ("r2", "preflight_r2", "run_r2"),
        ("stripe", "preflight_stripe", "run_stripe"),
        ("neon", "preflight_neon", "run_neon"),
    ):
        branch = case_branch(runner, profile)
        if branch.find(preflight) < 0 or branch.find(runner_fn) < branch.find(preflight):
            fail(f"{profile} profile does not preflight before execution")

    # Environment preconditions are part of correctness: absent credentials
    # must fail before a test can fall back to an in-memory adapter. Keep the
    # set closed across profiles while each profile gates only its own inputs.
    for name in (
        "CLOUDFLARE_ACCOUNT_ID",
        "CF_API_TOKEN",
        "D1_DATABASE_ID",
        "R2_S3_ENDPOINT",
        "R2_S3_ACCESS_KEY_ID",
        "R2_S3_SECRET_ACCESS_KEY",
        "R2_TEST_BUCKET",
        "HUGR_WALLET_BASE",
        "HUGR_WALLET_TOKEN",
        "HUGR_STRIPE_REF",
        "STRIPE_AUTH_MODE",
        "STRIPE_PRICE_ID_STARTER",
        "NEON_TEST_DSN",
    ):
        if name not in sh:
            fail(f"credential/config precondition is missing: {name}")
    if '[[ "$HUGR_STRIPE_REF" == stripe-prod-test ]]' not in runner:
        fail("Stripe profile is not pinned to the test wallet reference")
    if '[[ "$HUGR_WALLET_TOKEN" == hugrw_* ]]' not in runner:
        fail("Stripe profile does not validate wallet-token shape")
    if '[[ "$STRIPE_AUTH_MODE" == wallet-broker ]]' not in runner:
        fail("Stripe profile does not force wallet-broker auth")
    if '[[ "$STRIPE_PRICE_ID_STARTER" == price_* ]]' not in runner:
        fail("Stripe profile does not validate Starter price id")

    # A generic caller must not be able to select an arbitrary cargo target.
    if re.search(r"(?m)^\s*cargo\s+test\s+.*--ignored", wf):
        fail("workflow invokes cargo ignored tests directly instead of the allow-list")
    if re.search(r"(?m)^\s*cargo\s+test\s+--ignored", sh):
        fail("runner contains an unscoped cargo --ignored invocation")
    if "CARGO_BIN" in sh or "CARGO_BIN" in wf:
        fail("executor must not honor a caller-controlled CARGO_BIN override")
    if 'cargo test --locked "$@" "$expected" -- --ignored --nocapture' not in sh:
        fail("runner does not execute the trusted image Cargo through PATH")

    for target, source_path in REQUIRED_TARGET_SOURCES.items():
        source = ROOT / source_path
        if not source.is_file():
            fail(f"source for real target is missing: {target}: {source_path}")
        body = source.read_text(encoding="utf-8")
        allowed_cfg = (
            'feature = "live-integration"'
            if source_path == "crates/corelink-stripe-real/tests/live_integration.rs"
            else (
                'all(feature = "neon-real", not(target_arch = "wasm32"))'
                if source_path == "crates/corelink-audit-chain/tests/neon_shadow_real.rs"
                else None
            )
        )
        if not exact_ignored_source(body, target, allowed_cfg=allowed_cfg):
            fail(f"real target source declaration/ignore association is not exact: {target}")
        if not re.search(rf"(?m)^\s*run_cargo\b[^\n]*\b{re.escape(target)}\b", sh):
            fail(f"runner does not execute exact source target: {target}")

    # The PAT seed itself remains deliberately ignored and secret-shaped.  This
    # assertion prevents a future cleanup from deleting the safety boundary.
    seed = SEED_PATH.read_text(encoding="utf-8")
    if "#[ignore" not in seed or "CORELINK_PAT_SIGNING_KEY_HEX" not in seed:
        fail("PAT seed safety boundary changed: it must remain ignored and key-gated")
    if "PAT_PLAINTEXT" not in seed or "SEED_SQL" not in seed:
        fail("PAT seed output markers changed; review before changing executor policy")


def assert_hosted_contract_workflow(workflow: str) -> None:
    """Require the static/mutation contract to run on hosted CI without credentials."""
    active = code_text(workflow)
    if not re.search(r"(?m)^on:\s*$", active) or not re.search(r"(?m)^\s{2}pull_request:\s*$", active):
        fail("credentialless contract must run as a pull_request check")
    if re.search(r"(?m)^\s{2}(?:pull_request_target|push|schedule|workflow_dispatch|workflow_call):", active):
        fail("credentialless contract has an unexpected trigger")
    if not re.search(r"(?m)^\s{4}runs-on:\s*ubuntu-24\.04\s*$", workflow):
        fail("credentialless contract must use a GitHub-hosted runner")
    if re.search(r"(?im)^\s*environment\s*:", active) or re.search(r"\b(?:secrets|vars)\.", active):
        fail("credentialless contract references a protected environment or credential")
    if not re.search(r"(?m)^\s{2}contents:\s*read\s*$", active):
        fail("credentialless contract permissions must be read-only")
    if "persist-credentials: false" not in active:
        fail("credentialless contract checkout must not persist credentials")
    if "python3 -S scripts/verify_real_ignored_harnesses.py" not in active:
        fail("credentialless contract does not run the static/mutation verifier")
    if "python3 -S scripts/verify_i1650_real_integration_readiness.py" not in active:
        fail("credentialless contract does not run the readiness verifier")
    if "python3 -S scripts/probe_i2563_d1_token_scope.py --self-test" not in active:
        fail("credentialless contract does not run D1 scope negative fixtures")
    triggered_paths = set(re.findall(r'(?m)^\s{6}- "([^\"]+)"\s*$', active))
    missing = [path for path in CONTRACT_TRIGGER_INPUTS if path not in triggered_paths]
    if missing:
        fail(f"credentialless contract PR path filter omits verifier inputs: {', '.join(missing)}")


def workflow_job(text: str, name: str) -> str:
    """Return one top-level GitHub Actions job without neighboring job text."""
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    if match is None:
        fail(f"workflow job is missing: {name}")
    return match.group(0)


def assert_campaign_i1650_pack(workflow: str) -> None:
    """Keep the manual #1650 pack separate from the heavy shared campaign job."""
    active = code_text(workflow)
    if not re.search(r"(?m)^on:\s*$", active) or not re.search(r"(?m)^\s{2}workflow_dispatch:\s*$", active):
        fail("campaign pack must be manual-only")
    if re.search(r"(?m)^\s{2}(?:pull_request|pull_request_target|push|schedule|workflow_call):", active):
        fail("campaign pack has an automatic trigger")
    if active.count("- i1650-contract") != 1:
        fail("campaign suite choice does not contain exactly one i1650-contract entry")

    job = code_text(workflow_job(workflow, "i1650-contract"))
    if "inputs.suite == 'i1650-contract'" not in job:
        fail("i1650 campaign job is not bound to its closed suite selector")
    for marker in (
        "runs-on: ubuntu-24.04",
        "timeout-minutes: 5",
        "contents: read",
        "persist-credentials: false",
        "python3 -S scripts/verify_real_ignored_harnesses.py",
        "python3 -S scripts/verify_i1650_real_integration_readiness.py",
    ):
        if marker not in job:
            fail(f"i1650 campaign job is missing safety marker: {marker}")
    if re.search(r"(?im)^\s*environment\s*:", job) or re.search(r"\b(?:secrets|vars)\.", job):
        fail("i1650 campaign job references a protected environment or credential")
    expected_blank_env = (
        "CLOUDFLARE_ACCOUNT_ID",
        "CF_API_TOKEN",
        "D1_DATABASE_ID",
        "R2_S3_ENDPOINT",
        "R2_S3_ACCESS_KEY_ID",
        "R2_S3_SECRET_ACCESS_KEY",
        "HUGR_WALLET_TOKEN",
        "NEON_TEST_DSN",
    )
    blank_env = re.findall(r'(?m)^          ([A-Z][A-Z0-9_]*):\s*(.*)$', job)
    if tuple(name for name, _ in blank_env) != expected_blank_env or any(value != '""' for _, value in blank_env):
        fail("i1650 campaign job environment is not the reviewed empty input set")
    if re.search(r"\b(?:cargo|pnpm)\b|actions/(?:setup-node|setup-python)|rust-toolchain|setup-protoc", job):
        fail("i1650 campaign job includes unrelated runtime setup")
    steps = re.findall(r"(?m)^      - name: ([^\n]+)$", job)
    if steps != ["Checkout exact dispatched tree", "Audit credentialless real integration pack"]:
        fail("i1650 campaign job steps are not the reviewed minimal set")
    uses = re.findall(r"(?m)^        uses: ([^\n]+)$", job)
    if uses != ["actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"]:
        fail("i1650 campaign job has an unexpected action")
    if workflow_run_lines(job) != [
        "set -euo pipefail",
        "python3 -S scripts/verify_real_ignored_harnesses.py",
        "python3 -S scripts/verify_i1650_real_integration_readiness.py",
    ]:
        fail("i1650 campaign job commands are not the reviewed static verifier set")

    shared = code_text(workflow_job(workflow, "campaign"))
    if "inputs.suite != 'i1650-contract'" not in shared:
        fail("shared campaign job can still execute for i1650-contract")


def expect_campaign_rejected(label: str, workflow: str) -> None:
    try:
        assert_campaign_i1650_pack(workflow)
    except AssertionError:
        return
    fail(f"negative campaign-pack mutation was accepted: {label}")


def expect_rejected(label: str, workflow: str, runner: str) -> None:
    try:
        assert_contract(workflow, runner)
    except AssertionError:
        return
    fail(f"negative mutation was accepted: {label}")


def mutation_checks(workflow: str, runner: str, contract_workflow: str) -> None:
    expect_rejected(
        "D1 routed to shared environment",
        workflow.replace("environment: ${{ inputs.profile == 'd1' && 'real-d1-2563' || 'real-integration' }}", "environment: real-integration", 1),
        runner,
    )
    expect_rejected(
        "all profile routed to D1 environment",
        workflow.replace("inputs.profile == 'd1' && 'real-d1-2563'", "inputs.profile == 'all' && 'real-d1-2563'", 1),
        runner,
    )
    expect_rejected(
        "all profile allowed in credentialed job",
        workflow.replace(" && inputs.profile != 'all'", "", 1),
        runner,
    )
    expect_rejected(
        "all profile selectable",
        workflow.replace("          - neon\n", "          - neon\n          - all\n", 1),
        runner,
    )
    expect_rejected(
        "D1 scope probe removed",
        workflow.replace("python3 -S scripts/probe_i2563_d1_token_scope.py", "echo D1-scope-probe-removed", 1),
        runner,
    )
    # Missing trigger: a manually documented lane is not an executor.
    expect_rejected(
        "missing workflow_dispatch",
        workflow.replace("  workflow_dispatch:\n", "  # workflow_dispatch:\n", 1),
        runner,
    )
    expect_rejected(
        "workflow command replaced with inline comment bait",
        workflow.replace(
            '          bash scripts/run-real-ignored-harnesses.sh "$REAL_HARNESS_PROFILE"',
            '          echo "# bash scripts/run-real-ignored-harnesses.sh \\"$REAL_HARNESS_PROFILE\\""',
            1,
        ),
        runner,
    )
    # Automatic PR execution would expose network credentials to untrusted code.
    expect_rejected("pull_request trigger", workflow.replace("  workflow_dispatch:\n", "  pull_request:\n  workflow_dispatch:\n", 1), runner)
    expect_rejected("wrong canonical repository", workflow.replace("HuGR-dev/corelink-server", "HuGR-Labs/corelink-server"), runner)
    expect_rejected("self-hosted real executor", workflow.replace("runs-on: ubuntu-24.04", "runs-on: corelink", 1), runner)
    try:
        assert_hosted_contract_workflow(contract_workflow.replace("runs-on: ubuntu-24.04", "runs-on: corelink", 1))
    except AssertionError:
        pass
    else:
        fail("self-hosted credentialless contract mutation was accepted")
    try:
        assert_hosted_contract_workflow(contract_workflow.replace("permissions:\n  contents: read", "permissions:\n  contents: read\n\nenv:\n  TOKEN: ${{ secrets.TOKEN }}", 1))
    except AssertionError:
        pass
    else:
        fail("credentialed hosted contract mutation was accepted")
    try:
        assert_hosted_contract_workflow(contract_workflow.replace("python3 -S scripts/verify_i1650_real_integration_readiness.py", "echo '# readiness verifier removed'", 1))
    except AssertionError:
        pass
    else:
        fail("missing readiness verifier mutation was accepted")
    for path in CONTRACT_TRIGGER_INPUTS:
        path_entry = f'      - "{path}"\n'
        if path_entry not in contract_workflow:
            fail(f"path-trigger mutation setup is missing input: {path}")
        mutated = contract_workflow.replace(path_entry, "", 1)
        try:
            assert_hosted_contract_workflow(mutated)
        except AssertionError:
            pass
        else:
            fail(f"PR path-filter omission was accepted for verifier input: {path}")
    # Comment bait: a commented-out command is not executable coverage.
    target = REQUIRED_D1[0]
    expect_rejected("commented target", workflow, runner.replace(f"run_cargo d1 {target} --package corelink-server --lib", f"# run_cargo d1 {target} --package corelink-server --lib", 1))
    # Partial executor: dropping any exact real target must be detected.
    expect_rejected("partial D1 executor", workflow, runner.replace(REQUIRED_D1[-1], "d1_target_removed", 1))
    expect_rejected("partial R2 executor", workflow, runner.replace(REQUIRED_R2[-1], "r2_target_removed", 1))
    # Wrong-test substitution must not look like proof of the intended path.
    expect_rejected("wrong test target", workflow, runner.replace("storage_r2_round_trip", "unrelated_unit_test", 1))
    expect_rejected("caller Cargo override", workflow, runner.replace('cargo test --locked "$@" "$expected" -- --ignored --nocapture', '"$CARGO_BIN" test --locked "$@" "$expected" -- --ignored --nocapture', 1))
    expect_rejected("missing R2 source target", workflow, runner.replace("r2_cas_list_durable_audit_failure_precedes_storage", "r2_cas_list_target_removed", 1))
    expect_rejected("R2 wrong source target", workflow, runner.replace("r2_cas_list_durable_audit_failure_precedes_storage", "r2_cas_list_serial_fallback_attributes_the_r2_call_to_ostore", 1))

    source_target = REQUIRED_R2[0]
    source_path = ROOT / REQUIRED_TARGET_SOURCES[source_target]
    source_bytes = source_path.read_bytes()
    source_body = source_bytes.decode("utf-8")
    # Every unique source file gets a byte mutation, proving the manifest is
    # fail-closed independently of which harness file was edited.
    for relative in SOURCE_SHA256:
        original = (ROOT / relative).read_bytes()
        try:
            verify_source_digests(overrides={relative: original + b"\n// B-068 digest mutation\n"})
        except AssertionError:
            pass
        else:
            fail(f"byte mutation was accepted for source digest: {relative}")
    cfg_attr_mutation = source_bytes.replace(b"#[ignore", b"#[cfg_attr(any(), ignore)]\n#[ignore", 1)
    try:
        verify_source_digests(overrides={REQUIRED_TARGET_SOURCES[source_target]: cfg_attr_mutation})
    except AssertionError:
        pass
    else:
        fail("cfg_attr source mutation was accepted by digest")
    for label, mutation in (
        ("raw", source_bytes + b'\nr##"#[cfg(any())]"##\n'),
        ("unicode", source_bytes + "\n// B-068 \u2603\n".encode("utf-8")),
    ):
        try:
            verify_source_digests(overrides={REQUIRED_TARGET_SOURCES[source_target]: mutation})
        except AssertionError:
            pass
        else:
            fail(f"{label} source mutation was accepted by digest")
    declaration = re.search(rf"(?m)^(\s*)(async\s+fn\s+{re.escape(source_target)}\s*\()", source_body)
    # A target may not be remapped to an extra source that lacks a reviewed
    # digest. The closed-set check must catch both missing and extra entries.
    remapped_sources = dict(REQUIRED_TARGET_SOURCES)
    remapped_sources[REQUIRED_D1[0]] = "crates/corelink-container/src/storage/r2_s3_parts/tests_1.rs"
    try:
        verify_source_binding_manifest(remapped_sources)
    except AssertionError:
        pass
    else:
        fail("target remapped to a source without a digest was accepted")
    if declaration is None:
        fail("source mutation setup could not find declaration")
    declaration_line_start = source_body.rfind("\n", 0, declaration.start()) + 1
    ignore_line_start = source_body.rfind("\n", 0, declaration_line_start - 1) + 1
    source_without_ignore = source_body[:ignore_line_start] + "// #[ignore]\n" + source_body[declaration_line_start:]
    if exact_ignored_source(source_without_ignore, source_target):
        fail("source comment bait mutation was accepted")
    source_without_declaration = source_body[:declaration.start()] + "// " + source_body[declaration.start():]
    if exact_ignored_source(source_without_declaration, source_target):
        fail("commented source declaration mutation was accepted")
    valid_attrs = "#[tokio::test]\n#[ignore]\nasync fn target() {}"
    if exact_ignored_source(valid_attrs.replace("#[tokio::test]", "#[ignore]"), "target"):
        fail("missing active test attribute mutation was accepted")
    if exact_ignored_source("#[cfg(any())]\n" + valid_attrs, "target"):
        fail("disabled cfg mutation was accepted")
    if exact_ignored_source("#[cfg(feature = \"never\")]\nmod disabled {\n" + valid_attrs + "\n}", "target"):
        fail("cfg module mutation was accepted")
    for opening, closing in (("{", "}"), ("(", ")"), ("[", "]")):
        if exact_ignored_source(f"macro_rules! unused {opening}\n" + valid_attrs + f"\n{closing}", "target"):
            fail(f"uninvoked macro declaration mutation was accepted: {opening}")
    # Secret exposure: any PAT key-shaped input is forbidden, even if no seed
    # command is present.
    expect_rejected("PAT signing secret", workflow, runner + "\nexport CORELINK_PAT_SIGNING_KEY_HEX=unsafe\n")
    # A direct shell interpolation reintroduces command/injection ambiguity.
    expect_rejected("direct profile interpolation", workflow.replace('bash scripts/run-real-ignored-harnesses.sh "$REAL_HARNESS_PROFILE"', 'bash scripts/run-real-ignored-harnesses.sh "${{ inputs.profile }}"', 1), runner)
    # A D1 dispatch must not receive the sibling profile's credential values.
    expect_rejected(
        "D1 receives R2 secret",
        workflow.replace(
            "R2_S3_SECRET_ACCESS_KEY: ${{ (inputs.profile == 'r2' || inputs.profile == 'all') && secrets.R2_S3_SECRET_ACCESS_KEY || '' }}",
            "R2_S3_SECRET_ACCESS_KEY: ${{ secrets.R2_S3_SECRET_ACCESS_KEY }}",
            1,
        ),
        runner,
    )
    expect_rejected(
        "D1 receives R2 bucket",
        workflow.replace(
            "R2_TEST_BUCKET: ${{ (inputs.profile == 'r2' || inputs.profile == 'all') && vars.R2_TEST_BUCKET || '' }}",
            "R2_TEST_BUCKET: ${{ vars.R2_TEST_BUCKET }}",
            1,
        ),
        runner,
    )
    # The Stripe mode and price are both load-bearing; accepting either missing
    # value would silently exercise another auth/price configuration.
    expect_rejected("missing wallet-broker mode", workflow, runner.replace('[[ "$STRIPE_AUTH_MODE" == wallet-broker ]]', '[[ "$STRIPE_AUTH_MODE" == any-mode ]]', 1))
    expect_rejected("missing Starter price", workflow, runner.replace('[[ "$STRIPE_PRICE_ID_STARTER" == price_* ]]', '[[ "$STRIPE_PRICE_ID_STARTER" == any_* ]]', 1))
    # A preflight that contains a cargo call can mutate the external system
    # before a later profile is checked.
    expect_rejected("cargo in D1 preflight", workflow, runner.replace("  require_env CLOUDFLARE_ACCOUNT_ID CF_API_TOKEN D1_DATABASE_ID\n}\n\npreflight_r2", "  require_env CLOUDFLARE_ACCOUNT_ID CF_API_TOKEN D1_DATABASE_ID\n  run_cargo d1 d1_target --package corelink-server --lib\n}\n\npreflight_r2", 1))
    expect_rejected("late Neon check omitted from all", workflow, runner.replace("    preflight_neon\n    run_d1", "    run_d1", 1))


def campaign_mutation_checks(workflow: str) -> None:
    expect_campaign_rejected(
        "missing dedicated pack job",
        workflow.replace("  i1650-contract:\n", "  i1650-contract-disabled:\n", 1),
    )
    expect_campaign_rejected(
        "protected environment attached",
        workflow.replace("    runs-on: ubuntu-24.04\n    timeout-minutes: 5", "    runs-on: ubuntu-24.04\n    environment: real-integration\n    timeout-minutes: 5", 1),
    )
    expect_campaign_rejected(
        "readiness verifier removed",
        workflow.replace("python3 -S scripts/verify_i1650_real_integration_readiness.py", "echo '# readiness verifier removed'", 1),
    )
    expect_campaign_rejected(
        "shared campaign receives i1650",
        workflow.replace("inputs.suite != 'i1650-contract' && ", "", 1),
    )
    expect_campaign_rejected(
        "extra campaign command",
        workflow.replace(
            "          python3 -S scripts/verify_i1650_real_integration_readiness.py\n",
            "          python3 -S scripts/verify_i1650_real_integration_readiness.py\n          printf unexpected\n",
            1,
        ),
    )
    expect_campaign_rejected(
        "extra campaign step",
        workflow.replace(
            "\n  campaign:\n",
            "\n      - name: Unexpected provider step\n        run: curl https://provider.example.invalid\n\n  campaign:\n",
            1,
        ),
    )
    expect_campaign_rejected(
        "extra campaign environment input",
        workflow.replace(
            '          NEON_TEST_DSN: ""\n',
            '          NEON_TEST_DSN: ""\n          EXTRA_PROVIDER_TOKEN: ""\n',
            1,
        ),
    )


def preflight_runtime_checks() -> None:
    """Prove late missing prerequisites result in zero cargo invocations."""

    baseline = {
        "CLOUDFLARE_ACCOUNT_ID": "account",
        "CF_API_TOKEN": "cf-token",
        "D1_DATABASE_ID": "database",
        "R2_S3_ENDPOINT": "https://r2.example.test",
        "R2_S3_ACCESS_KEY_ID": "access",
        "R2_S3_SECRET_ACCESS_KEY": "secret",
        "R2_TEST_BUCKET": "bucket",
        "HUGR_WALLET_BASE": "https://wallet.example.test",
        "HUGR_WALLET_TOKEN": "hugrw_test",
        "HUGR_STRIPE_REF": "stripe-prod-test",
        "STRIPE_AUTH_MODE": "wallet-broker",
        "STRIPE_PRICE_ID_STARTER": "price_test",
        "NEON_TEST_DSN": "postgresql://user:pass@db.example.test/shadow?sslmode=require",
    }
    with tempfile.TemporaryDirectory(prefix="b068-preflight-") as temp:
        root = Path(temp)
        for missing in ("HUGR_WALLET_TOKEN", "STRIPE_PRICE_ID_STARTER", "NEON_TEST_DSN"):
            marker = root / f"cargo-{missing}"
            fake_cargo = root / "cargo"
            fake_cargo.write_text(
                "#!/bin/sh\n"
                f"printf invoked > {marker}\n"
                "exit 99\n",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o700)
            env = os.environ.copy()
            env.update(baseline)
            env.pop(missing, None)
            env["PATH"] = os.pathsep.join((str(root), env.get("PATH", "")))
            result = subprocess.run(
                ["bash", str(RUNNER_PATH), "all"],
                env=env,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                fail(f"missing {missing} unexpectedly allowed all profile")
            if marker.exists():
                fail(f"missing {missing} invoked cargo before failing preflight")

    for missing in ("CLOUDFLARE_ACCOUNT_ID", "CF_API_TOKEN", "D1_DATABASE_ID"):
        with tempfile.TemporaryDirectory(prefix="b068-d1-missing-") as temp:
            root = Path(temp)
            marker = root / "cargo-invoked"
            fake_cargo = root / "cargo"
            fake_cargo.write_text(
                "#!/bin/sh\n"
                f"printf invoked > {marker}\n"
                "exit 99\n",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o700)
            env = os.environ.copy()
            env.update(baseline)
            env.pop(missing, None)
            env["PATH"] = os.pathsep.join((str(root), env.get("PATH", "")))
            result = subprocess.run(
                ["bash", str(RUNNER_PATH), "d1"],
                env=env,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode == 0 or marker.exists():
                fail(f"missing D1 prerequisite {missing} did not fail before cargo")

    # The D1 profile is independent of the sibling R2 resource. Prove that
    # its own preflight reaches the selected test command with only D1 inputs.
    with tempfile.TemporaryDirectory(prefix="b068-d1-only-") as temp:
        root = Path(temp)
        marker = root / "cargo-invoked"
        fake_cargo = root / "cargo"
        fake_cargo.write_text(
            "#!/bin/sh\n"
            f"printf invoked > {marker}\n"
            "exit 99\n",
            encoding="utf-8",
        )
        fake_cargo.chmod(0o700)
        env = os.environ.copy()
        env.update(
            {
                "CLOUDFLARE_ACCOUNT_ID": "account",
                "CF_API_TOKEN": "cf-token",
                "D1_DATABASE_ID": "database",
                "GITHUB_SHA": "a" * 40,
                "PATH": os.pathsep.join((str(root), os.environ.get("PATH", ""))),
            }
        )
        for name in ("R2_S3_ENDPOINT", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY", "R2_TEST_BUCKET"):
            env.pop(name, None)
        result = subprocess.run(
            ["bash", str(RUNNER_PATH), "d1"],
            env=env,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 99 or not marker.exists():
            fail("D1-only inputs did not pass preflight without R2 credentials")


def failure_receipt_runtime_checks() -> None:
    """Prove fail-fast receipts expose only a sanitized error category."""

    secret = "CF_DIAGNOSTIC_SENTINEL_never_emit"
    dsn = "postgresql://private-user:private-pass@private.example.test/db"
    personal = "private.person@example.test"
    with tempfile.TemporaryDirectory(prefix="b068-failure-receipt-") as temp:
        root = Path(temp)
        cargo_calls = root / "cargo-calls"
        artifact_dir = root / "artifacts" / "real-ignored-harnesses"
        fake_cargo = root / "cargo"
        fake_cargo.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$FAKE_CARGO_CALLS"\n'
            f"printf '%s\\n' \"thread 'd1' panicked at {secret} {dsn} {personal}\" >&2\n"
            "exit 101\n",
            encoding="utf-8",
        )
        fake_cargo.chmod(0o700)
        env = os.environ.copy()
        env.update(
            {
                "CLOUDFLARE_ACCOUNT_ID": "account",
                "CF_API_TOKEN": "cf-token",
                "D1_DATABASE_ID": "database",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_WORKSPACE": str(root),
                "FAKE_CARGO_CALLS": str(cargo_calls),
                "PATH": os.pathsep.join((str(root), env.get("PATH", ""))),
            }
        )
        for name in ("R2_S3_ENDPOINT", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY", "R2_TEST_BUCKET"):
            env.pop(name, None)
        result = subprocess.run(
            ["bash", str(RUNNER_PATH), "d1"],
            env=env,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 101:
            fail("failed Cargo invocation did not preserve its terminal exit code")
        calls = cargo_calls.read_text(encoding="utf-8").splitlines()
        if len(calls) != 1 or "d1_acquire_lock_then_held_then_release" not in calls[0]:
            fail("failed first D1 test did not fail fast before subsequent profile tests")
        receipt = (artifact_dir / "receipt.jsonl").read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in receipt]
        if len(entries) != 3 or [entry["status"] for entry in entries] != ["started", "failed", "failed"]:
            fail("failed first D1 test did not leave complete started/test/profile receipts")
        if any(entry.get("diagnostic_class") != "test_panic" for entry in entries[1:]):
            fail("failed D1 receipts omitted the safe panic classification")
        log_text = (artifact_dir / "d1-d1_acquire_lock_then_held_then_release.log").read_text(encoding="utf-8")
        public_output = result.stdout + result.stderr + log_text + "\n".join(receipt)
        if "diagnostic_class=test_panic" not in log_text:
            fail("redacted test log omitted its diagnostic class")
        if any(marker in public_output for marker in (secret, dsn, personal)):
            fail("runner or artifact exposed private text from raw Cargo output")
        if any(path.name.endswith(".log") and "private" in path.read_text(encoding="utf-8", errors="replace") for path in artifact_dir.iterdir()):
            fail("artifact contains raw private Cargo output")


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--classify-failure":
        raw_output = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
        print(safe_failure_diagnostic(raw_output))
        return 0

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    contract_workflow = CONTRACT_WORKFLOW_PATH.read_text(encoding="utf-8")
    campaign_workflow = CAMPAIGN_WORKFLOW_PATH.read_text(encoding="utf-8")
    runner = RUNNER_PATH.read_text(encoding="utf-8")
    assert_contract(workflow, runner)
    assert_hosted_contract_workflow(contract_workflow)
    assert_campaign_i1650_pack(campaign_workflow)
    mutation_checks(workflow, runner, contract_workflow)
    campaign_mutation_checks(campaign_workflow)
    preflight_runtime_checks()
    failure_diagnostic_negative_controls()
    failure_receipt_runtime_checks()
    print("B-068 executor contract: PASS (full allow-list + negative mutations)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError) as exc:
        print(f"B-068 executor contract: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
