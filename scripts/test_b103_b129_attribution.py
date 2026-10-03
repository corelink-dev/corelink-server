#!/usr/bin/env python3
"""Behavioral and mutation tests for the B-103..B-129 static contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify", ROOT / "scripts/verify_b103_b129_attribution.py")
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
PROBE_SPEC = importlib.util.spec_from_file_location("probe_i1671_b129", ROOT / "scripts/probe_i1671_b129.py")
assert PROBE_SPEC and PROBE_SPEC.loader
b129_probe = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(b129_probe)


def expect_reject(path: str, marker: str) -> None:
    original = (ROOT / path).read_text(encoding="utf-8")
    mutated = original.replace(marker, "MUTATED")
    assert mutated != original, f"mutation marker absent: {path}: {marker}"
    try:
        verify.verify(ROOT, overrides={path: mutated})
    except verify.VerificationError:
        return
    raise AssertionError(f"mutation was accepted: {path}: {marker}")


def expect_wrapper_reject(mutated: str, label: str) -> None:
    path = "crates/corelink-container/src/byte_accounting.rs"
    try:
        verify.verify(ROOT, overrides={path: mutated})
    except verify.VerificationError:
        return
    raise AssertionError(f"mutation was accepted: {path}: {label}")


def expect_b129_reject(path: str, mutated: str, label: str) -> None:
    b129_errors = verify.b129_inline_issues(ROOT, overrides={path: mutated})
    if b129_errors:
        return
    raise AssertionError(f"B-129 mutation was accepted: {path}: {label}")


def main() -> int:
    verify.verify(ROOT)
    if verify.b129_inline_issues(ROOT):
        raise AssertionError("B-129 inline semantic gate rejected the current active symbols")
    expect_reject("crates/corelink-container/src/origin_timing.rs", '"oaccounting"')
    expect_reject("crates/corelink-container/src/adapter_cache.rs", "PhaseScope::with_ledger")
    expect_reject(
        "crates/corelink-container/src/byte_accounting/b126_m2_impl_01_part_02.rs",
        "Phase::Accounting",
    )
    expect_reject(
        "crates/corelink-container/src/routes/ratelimit_layer.rs",
        "crate::origin_timing::Phase::RateLimit",
    )
    expect_reject(
        "crates/corelink-container/src/byte_accounting/b126_m2_impl_01.rs",
        'include!("b126_m2_impl_01_part_02.rs");',
    )
    wrapper = (ROOT / "crates/corelink-container/src/byte_accounting.rs").read_text(encoding="utf-8")
    include = 'include!("byte_accounting/b126_m2_impl_01.rs");'
    assert wrapper.count(include) == 1, "expected one active B126-M2 implementation include"
    accounting = verify._rust_include_closure(
        ROOT,
        "crates/corelink-container/src/byte_accounting.rs",
        {},
    )
    assert accounting.count("Phase::Accounting") >= 1, "nested accounting include was not traversed"
    rate_tokens = verify._rust_tokens(
        (ROOT / "crates/corelink-container/src/routes/ratelimit_layer.rs").read_text(encoding="utf-8")
    )
    assert len(verify._rate_limit_scope_positions(rate_tokens)) == 2, "one-argument rate scopes were not recognized"
    expect_wrapper_reject(wrapper.replace(include, "", 1), "active include removed")
    expect_wrapper_reject(
        wrapper.replace(include, 'include!("byte_accounting/b126_m2_impl_02.rs");', 1),
        "active include path changed",
    )
    expect_wrapper_reject(
        wrapper.replace(include, f"/* {include} */", 1),
        "include moved into comment",
    )
    expect_wrapper_reject(
        wrapper.replace(include, f'const DECOY: &str = r#"{include}"#;', 1),
        "include moved into raw string",
    )
    expect_reject("worker/src/index_observability.ts", "wdbControlPhase")
    expect_reject("worker/tests/server_timing_wdb_residual_phase.test.ts", "unreconciled")
    expect_reject("scripts/probe-cargo-cache-latency.sh", "reconcile_origin_split")
    expect_reject("scripts/probe-cargo-cache-latency.sh", "oaccounting;dur=abc")
    expect_reject("scripts/probe-cargo-cache-latency.sh", "oother;dur=Inf")
    expect_reject(verify.PACKET, "status: **open**")
    diagnostic = (ROOT / ".github/workflows/issue-1671-b129-diagnostic.yml").read_text(encoding="utf-8")
    for marker, label in (
        ("github.repository_id == '", "unrestricted repository dispatch"),
        ("github.ref == 'refs/heads/main' && github.ref_protected", "unprotected dispatch ref"),
        ("environment: production", "unbound production environment"),
        ("CORELINK_PERF_BASE: ${{ vars.CORELINK_PERF_BASE }}", "unbound production origin"),
    ):
        expect_b129_reject(
            ".github/workflows/issue-1671-b129-diagnostic.yml",
            diagnostic.replace(marker, "MUTATED", 1),
            label,
        )

    assert b129_probe.resolve_target_origin(
        "https://CORELINK-API.HUMANGR.COM/", "https://corelink-api.humangr.com"
    ) == "https://corelink-api.humangr.com"
    for requested, configured in (
        ("https://attacker.example", "https://corelink-api.humangr.com"),
        ("http://corelink-api.humangr.com", "https://corelink-api.humangr.com"),
        ("https://user@corelink-api.humangr.com", "https://corelink-api.humangr.com"),
        ("https://corelink-api.humangr.com/path", "https://corelink-api.humangr.com"),
        ("https://corelink-api.humangr.com", ""),
    ):
        try:
            b129_probe.resolve_target_origin(requested, configured)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"unsafe B-129 target accepted: {requested}")

    probe = subprocess.run(
        ["bash", str(ROOT / "scripts/probe-cargo-cache-latency.sh"), "--self-test"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr or probe.stdout
    assert "probe origin reconciliation self-test: PASS" in probe.stdout

    observability = (ROOT / "worker/src/index_observability.ts").read_text(encoding="utf-8")
    expect_b129_reject(
        "worker/src/index_observability.ts",
        observability.replace("export function wdbControlPhase", "// export function wdbControlPhase", 1),
        "comment-only function marker",
    )
    expect_b129_reject(
        "worker/src/index_observability.ts",
        observability.replace(
            "export function wdbControlPhase",
            'const BAIT = "export function wdbControlPhase";\n//',
            1,
        ),
        "string-only stale-path marker",
    )
    no_op = observability.replace(
        'return `qcontrol;dur=${wdbMs};desc="unreconciled"`;',
        'return "qcontrol";',
        1,
    ).replace(
        'return `qcontrol;dur=${wdbMs - sum}`;',
        'return "qcontrol";',
        1,
    )
    expect_b129_reject("worker/src/index_observability.ts", no_op, "no-op qcontrol implementation")
    expect_b129_reject(
        "worker/src/index_observability.ts",
        observability.replace("qcontrol;dur=", "qother;dur="),
        "historical qother emission",
    )
    expect_b129_reject(
        "worker/src/index_observability.ts",
        observability.replace("sum += v;", "sum += v * 2;", 1),
        "scaled phase accumulation",
    )
    finish = (ROOT / "worker/src/index_finish_stage.ts").read_text(encoding="utf-8")
    expect_b129_reject(
        "worker/src/index_finish_stage.ts",
        finish.replace(
            "[stQTierMs, stQDoMs, stQBatchMs, stQResidMs]",
            "[stQTierMs, stQDoMs, stQDoMs, stQBatchMs, stQResidMs]",
            1,
        ),
        "duplicate stQDoMs argument",
    )
    expect_b129_reject(
        "worker/src/index_finish_stage.ts",
        finish.replace('.SERVER_TIMING_WDB_DETAIL === "on"', '.SERVER_TIMING_WDB_DETAIL === "off"', 1),
        "disabled SERVER_TIMING_WDB_DETAIL gate",
    )
    expect_b129_reject(
        "crates/corelink-container/src/origin_timing.rs",
        (ROOT / "crates/corelink-container/src/origin_timing.rs")
        .read_text(encoding="utf-8")
        .replace(
            'parts.push(format!("ohandler;dur={handler_ms}{handler_suffix}"));',
            'parts.push(format!("ohandler;dur={handler_ms}{handler_suffix}"));\n        parts.push(format!("ohandler;dur={handler_ms}{handler_suffix}"));',
            1,
        ),
        "duplicate ohandler emission",
    )
    expect_b129_reject(
        "crates/corelink-container/src/origin_timing.rs",
        (ROOT / "crates/corelink-container/src/origin_timing.rs")
        .read_text(encoding="utf-8")
        .replace('"oother;dur={handler_ms};desc=\\"legacy-alias\\""', '"removed;dur={handler_ms};desc=\\"legacy-alias\\""', 1),
        "legacy alias removed",
    )
    expect_b129_reject(
        "worker/src/index_observability.ts",
        observability.replace(
            'return `qcontrol;dur=${wdbMs};desc="unreconciled"`;',
            'return `qcontrol;dur=${wdbMs - sum}`;',
            1,
        ),
        "no-op return retaining subtraction bait",
    )
    print("B103-B129 attribution verifier mutations: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
