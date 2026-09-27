#!/usr/bin/env python3
"""Fail-closed cache-only composition and single-listener adapter contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
COMPOSITION = ROOT / "crates/corelink-container/src/reapi_composition.rs"
MAIN = ROOT / "crates/corelink-container/src/main.rs"
BUCK2_CONFIG = ROOT / "examples/buck2-starter/.buckconfig"


def effective_buck2_names(buck2_config: str) -> set[tuple[str, str]]:
    """Return normalized noncomment INI section/key names only."""
    names: set[tuple[str, str]] = set()
    for raw_line in buck2_config.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            names.add(("section", re.sub(r"\s+", "", line[1:-1]).lower()))
        elif "=" in line:
            names.add(("key", re.sub(r"\s+", "", line.split("=", 1)[0]).lower()))
    return names


def violations(composition: str, main: str, buck2_config: str) -> list[str]:
    errors: list[str] = []
    required = (
        "pub fn build_unmounted_cache_only_router(ingress: Option<ReapiIngress>) -> Option<Router>",
        "pub fn build_unmounted_cache_only_routes(ingress: Option<ReapiIngress>) -> Option<Routes>",
        "pub fn build_unmounted_cache_only_axum_router(",
        "Some(Server::builder().add_routes(build_unmounted_cache_only_routes(ingress)?))",
        "Some(build_unmounted_cache_only_routes(ingress)?.into_axum_router())",
        "let ingress = ingress?;",
        "CasUnaryService::new(ingress.clone())",
        "ByteStreamServer::new(ReapiByteStreamService::new(ingress.clone()))",
        "ActionCacheServer::new(ReapiActionCacheService::new(ingress.clone()))",
        "CapabilitiesServer::new(",
        "ReapiCacheCapabilitiesService::new(ingress)",
        "REAPI_MAX_DECODING_MESSAGE_BYTES",
        "does not bind a socket",
    )
    for item in required:
        if item not in composition:
            errors.append(f"cache-only composition is missing: {item}")
    if composition.count("Routes::new(") != 1 or composition.count(".add_service(") != 3:
        errors.append("composition must register exactly four cache-only services")
    if composition.count(".max_decoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)") != 4:
        errors.append("every cache-only service must use the bounded decode ceiling")
    if composition.count(".max_encoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)") != 4:
        errors.append("every cache-only service must use the bounded encode ceiling")
    forbidden = (
        "ExecutionServer",
        "ExecutionService",
        "serve(",
        "serve_with_incoming",
        "TcpListener",
        "http://",
        "https://",
        "localhost",
    )
    for item in forbidden:
        if item in composition:
            errors.append(f"composition contains a forbidden mount or cache alternative: {item}")
    if "axum::serve(listener, app)" not in main:
        errors.append("the existing Axum listener serve call is missing")
    if "build_unmounted_cache_only_router" in main:
        errors.append("the legacy standalone composition builder is wired into the public binary")
    if "build_unmounted_cache_only_axum_router(reapi_ingress)" not in main:
        errors.append("the cache-only Axum adapter is not mounted from the factory ingress")
    if "let reapi_ingress = composed.reapi_ingress;" not in main:
        errors.append("the route factory ingress is not retained for fail-closed cache composition")
    starter_template = (
        "# [remote_cache]",
        "# url = https://staging.corelink.humangr.com",
        "# http_headers = Authorization: Bearer ${CORELINK_STAGING_PAT}",
        "# [buck2_re_client]",
        "# action_cache_address = grpcs://staging.corelink.humangr.com",
        "# cas_address = grpcs://staging.corelink.humangr.com",
        "# engine_address = grpcs://staging.corelink.humangr.com",
    )
    for item in starter_template:
        if item not in buck2_config:
            errors.append(f"Buck2 staging activation template is missing: {item}")
    for forbidden_item in (
        "corelink-api.humangr.com",
        "${CORELINK_PAT}",
    ):
        if forbidden_item in buck2_config:
            errors.append(f"Buck2 staging config falls back to production: {forbidden_item}")
    effective_names = effective_buck2_names(buck2_config)
    for forbidden_item in (
        ("section", "remote_cache"),
        ("section", "buck2_re_client"),
        ("key", "url"),
        ("key", "action_cache_address"),
        ("key", "cas_address"),
        ("key", "engine_address"),
        ("key", "http_headers"),
        ("key", "read"),
        ("key", "write"),
    ):
        if forbidden_item in effective_names:
            errors.append(
                "Buck2 remote configuration is active before runtime receipt: "
                f"{forbidden_item[0]} {forbidden_item[1]}"
            )
    return errors


def self_test() -> list[str]:
    composition = COMPOSITION.read_text(encoding="utf-8")
    main = MAIN.read_text(encoding="utf-8")
    buck2_config = BUCK2_CONFIG.read_text(encoding="utf-8")
    errors = violations(composition, main, buck2_config)
    mutations = (
        (composition.replace("ByteStreamServer::new", "RemovedByteServer::new", 1), main, buck2_config, "missing ByteStream"),
        (composition.replace("CapabilitiesServer::new", "RemovedCapabilities::new", 1), main, buck2_config, "missing Capabilities"),
        (composition.replace("let ingress = ingress?;", "let ingress = ingress.unwrap_or_else(|| panic!());", 1), main, buck2_config, "fail-open absent ingress"),
        (composition.replace(".max_decoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)", "", 1), main, buck2_config, "unbounded request decode"),
        (composition.replace(".max_encoding_message_size(REAPI_MAX_DECODING_MESSAGE_BYTES)", "", 1), main, buck2_config, "unbounded response encode"),
        (composition + "\nExecutionServer::new(service);", main, buck2_config, "execution service"),
        (composition + "\nServer::builder().serve(addr);", main, buck2_config, "public listener"),
        (composition, main.replace("axum::serve(listener, app)", "tokio::spawn(serve_reapi(listener, app))", 1), buck2_config, "lost Axum listener"),
        (composition, main.replace("build_unmounted_cache_only_axum_router", "removed_cache_only_axum_router", 1), buck2_config, "missing single-listener adapter"),
        (composition, main + "\nbuild_unmounted_cache_only_router(dependencies);", buck2_config, "legacy public binary wiring"),
        (composition, main, buck2_config + "\n[remote_cache]\nurl = https://staging.corelink.humangr.com\n", "Buck2 endpoint enablement"),
        (composition, main, buck2_config + "\n[buck2_re_client]\nhttp_headers = Authorization: Bearer ${CORELINK_STAGING_PAT}\n", "Buck2 header enablement"),
        (composition, main, buck2_config + "\n[ remote_cache ]\nurl=https://staging.corelink.humangr.com\n", "Buck2 spaced section and no-space endpoint"),
        (composition, main, buck2_config + "\n[ buck2_re_client ]\nhttp_headers=Authorization: Bearer ${CORELINK_STAGING_PAT}\nread=false\nwrite=false\n", "Buck2 no-space header and read/write"),
        (composition, main, buck2_config.replace("CORELINK_STAGING_PAT", "CORELINK_PAT", 1), "Buck2 production PAT"),
        (composition, main, buck2_config.replace("staging.corelink.humangr.com", "corelink-api.humangr.com", 1), "Buck2 production endpoint"),
    )
    for mutated_composition, mutated_main, mutated_buck2_config, label in mutations:
        if not violations(mutated_composition, mutated_main, mutated_buck2_config):
            errors.append(f"mutation was not detected: {label}")
    return errors


def main_cli() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = self_test() if args.self_test else violations(
        COMPOSITION.read_text(encoding="utf-8"),
        MAIN.read_text(encoding="utf-8"),
        BUCK2_CONFIG.read_text(encoding="utf-8"),
    )
    result = {"check": "i2183-reapi-composition", "ok": not errors, "errors": errors}
    print(json.dumps(result, sort_keys=True) if args.json else "\n".join(errors or ["#2183 composition contract: PASS"]))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main_cli())
