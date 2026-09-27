#!/usr/bin/env python3
"""Credentialless static guard for the #1700 provider preflight workflow."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path


WORKFLOW = Path(".github/workflows/staging-provider-preflight.yml")
PROVIDER = Path("scripts/staging_bootstrap_provider.py")
RENDERER = Path("scripts/render_staging_wrangler.py")
# Exact source pins reviewed for the provider-deferred #1700 correction. Any
# provider/renderer source drift must receive explicit preflight safety review
# and updated pins.
CANONICAL_PROVIDER_SOURCE_SHA256 = (
    "4684063fe7acbbc781ea177e029ea6d6ac7b7d4b906a814cf0c41b67eda8abf4"
)
CANONICAL_RENDERER_SOURCE_SHA256 = (
    "4dc4f24bf2e3d62f6ebd386567ec92490d90701f04fcfd4ecb752568f1ec8e9f"
)
# Exact source pin for get() in canonical main@b295292f. This binds request
# construction, all intervening statements, and urlopen send behavior.
CANONICAL_GET_SOURCE_SHA256 = (
    "1a919cdf4974c3d7f2e102dd889c8f59fef5a63447874d690f13531ae55f8a32"
)


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    provider = PROVIDER.read_text(encoding="utf-8")
    source_pins = (
        (PROVIDER, CANONICAL_PROVIDER_SOURCE_SHA256),
        (RENDERER, CANONICAL_RENDERER_SOURCE_SHA256),
    )
    for path, expected in source_pins:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(
                f"{path} changed from the reviewed preflight source; review and update the pin explicitly"
            )
    required_workflow = (
        "github.repository == 'HuGR-dev/corelink-server'",
        "github.ref == 'refs/heads/main' && github.ref_protected",
        'test "$EXPECTED_SHA" = "$GITHUB_SHA"',
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        "persist-credentials: false",
        "timeout-minutes: 10",
        "scripts/staging_bootstrap_provider.py --phase preflight",
        "actions/upload-artifact@",
        "retention-days: 30",
    )
    missing = [item for item in required_workflow if item not in workflow]
    if missing:
        raise SystemExit(f"preflight workflow is missing safety guards: {missing}")
    if "pull_request:" not in workflow or "if: github.event_name == 'pull_request'" not in workflow:
        raise SystemExit("pull request checks must remain credentialless and separate")
    for forbidden in ("wrangler deploy", "secret put", "dns_records", "workers/routes"):
        if forbidden in workflow:
            raise SystemExit(f"provider workflow contains a forbidden mutation surface: {forbidden}")
    tree = ast.parse(provider, filename=str(PROVIDER))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    def dotted_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{dotted_name(node.value)}.{node.attr}"
        return ""

    get_function = next(
        (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "get"),
        None,
    )
    if get_function is None:
        raise SystemExit("provider readback GET helper is absent")
    get_source = ast.get_source_segment(provider, get_function)
    if get_source is None or hashlib.sha256(get_source.encode("utf-8")).hexdigest() != CANONICAL_GET_SOURCE_SHA256:
        raise SystemExit("provider get() request construction/send changed from its reviewed read-only form")
    request_calls = [node for node in calls if dotted_name(node.func) == "urllib.request.Request"]
    urlopen_calls = [node for node in calls if dotted_name(node.func) == "urllib.request.urlopen"]
    function_calls = list(ast.walk(get_function))
    if (
        len(request_calls) != 1
        or len(urlopen_calls) != 1
        or request_calls[0] not in function_calls
        or urlopen_calls[0] not in function_calls
    ):
        raise SystemExit("all Cloudflare provider requests must use the pinned read-only GET helper")
    print("staging provider preflight safety contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
