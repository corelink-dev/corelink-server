#!/usr/bin/env python3
"""Protected-base, source-only admission gate for issue #2176.

The ``pull_request_target`` workflow loads this program from the immutable
pull-request base SHA and supplies a separately checked-out candidate tree.
The candidate is read as UTF-8 data only. No candidate script, workflow,
package hook, build, test, or import is executed.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class ContractError(RuntimeError):
    """The candidate does not meet the protected transport-deny contract."""


INDEX = Path("worker/src/index_fetch.ts")
GATE = Path("worker/src/grpc_transport_gate.ts")
CONTRACT = Path("specs/03_architecture/issue-2176-grpc-transport-contract.md")
WORKFLOW = Path(".github/workflows/issue-2176-grpc-deny-gate.yml")

# These files select the public Worker entrypoint or its deployable source.
# They stay byte-identical to the protected base while native gRPC is denied,
# so an alternate Worker entry cannot evade the first statement in baseHandler.
LOCKED_PERIMETER_PATHS = (
    Path("wrangler.toml"),
    Path("worker/package.json"),
    Path("worker/tsconfig.json"),
    Path("worker/tsconfig.test.json"),
    Path("worker/vitest.config.mts"),
    Path("worker/vitest.miniflare.config.mts"),
    Path("worker/src/index.ts"),
    Path("worker/src/index_common.ts"),
    Path("package.json"),
    Path("pnpm-lock.yaml"),
    Path(".github/workflows/container-build-push-prod.yml"),
)

# The hosted-runner campaign owns these CI-only workflow files in a separate,
# closed-world contract.  Their runner and checkout settings cannot change the
# Worker entrypoint or Container ingress guarded above, so pinning their bytes
# here would block an authorized credentialless migration without adding a
# gRPC safety property.  The runner contract validates them as inert YAML.
MIGRATABLE_CI_PATHS = (
    Path(".github/workflows/corelink-worker.yml"),
    Path(".github/workflows/corelink-reapi.yml"),
)

IMPORT_ANCHOR = 'import { runScheduled } from "./index_schedule.js";\n'
DENY_IMPORT = 'import { rejectUnprovenGrpcTransport } from "./grpc_transport_gate.js";\n'
FETCH_OPENING = "  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {\n"
FIRST_PIPELINE_STEP = "    const requestStart = Date.now();\n"
DENY_INSERTION = (
    "    const grpcTransportGate = rejectUnprovenGrpcTransport(request);\n"
    "    if (grpcTransportGate !== null) return grpcTransportGate;\n"
)

GATE_SOURCE = '''const GRPC_MEDIA_TYPE_PREFIX = "application/grpc";

/**
 * Refuse native-gRPC media types at the public Fetch boundary until a separate
 * protected-environment receipt proves the complete Worker → DO → Container
 * transport. This function reads only the media type and never reflects any
 * request header, including authorization.
 */
export function rejectUnprovenGrpcTransport(request: Request): Response | null {
  const mediaType = request.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (mediaType === undefined || !mediaType.startsWith(GRPC_MEDIA_TYPE_PREFIX)) return null;

  return new Response(JSON.stringify({ error: "GRPC_TRANSPORT_UNAVAILABLE" }), {
    status: 503,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}
'''

CONTRACT_SOURCE = '''# Issue #2176 gRPC transport contract

**BLOCKED — no public gRPC claim.**

`application/grpc` is rejected at the first statement of the public Worker
Fetch handler before routing, Durable Object lookup, Container startup, or a
Container `getTcpPort(50051)` Fetch proxy.

Removing that denial requires a separately reviewed, protected-environment
runtime receipt for the exact deployed SHA and endpoint. It must prove an
external HTTP/2 gRPC request through Worker → Durable Object → Container over a
raw TCP socket, preserving binary framing, authorization metadata, response
metadata, `grpc-status`, trailers, cancellation, unary behavior, and streaming
behavior.

No REST, HTTP/1, gRPC-Web, local proxy, or local cache fallback.
'''

# When this verifier first lands, the protected base may not yet contain the
# workflow. In that bootstrap case only this canonical workflow is accepted.
# Once present on the protected base, its exact bytes become the expected
# workflow for candidates, so later PRs cannot disable or replace the gate.
BOOTSTRAP_WORKFLOW_SOURCE = '''name: issue 2176 trusted gRPC deny gate

# This workflow definition is evaluated from the protected base branch by
# pull_request_target. Candidate files are data only: this workflow never runs
# a candidate workflow, script, package hook, build, or test command.
on:
  pull_request_target:
    branches: [main]
    paths:
      # Current Worker / Durable Object ingress and its deployment boundary.
      - "wrangler.toml"
      - "worker/package.json"
      - "worker/tsconfig.json"
      - "worker/tsconfig.test.json"
      - "worker/vitest.config.mts"
      - "worker/vitest.miniflare.config.mts"
      - "worker/src/index.ts"
      - "worker/src/index_common.ts"
      - "worker/src/index_fetch.ts"
      - "package.json"
      - "pnpm-lock.yaml"
      - ".github/workflows/corelink-worker.yml"
      - ".github/workflows/corelink-reapi.yml"
      - ".github/workflows/container-build-push-prod.yml"
      # Current Container ingress and image/build boundary.
      - "Dockerfile"
      - "Cargo.toml"
      - "Cargo.lock"
      - "crates/corelink-container/**"
      # Future #2176 admission-gate and contract surfaces.
      - "worker/src/grpc_transport_gate.ts"
      - "specs/03_architecture/issue-2176-grpc-transport-contract.md"
      - "scripts/verify_i2176_grpc_deny_gate.py"
      - "tests/test_verify_i2176_grpc_deny_gate.py"
      - ".github/workflows/issue-2176-grpc-deny-gate.yml"

permissions:
  contents: read

concurrency:
  group: issue-2176-trusted-grpc-deny-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  deny-contract:
    name: trusted exact-head gRPC deny contract
    if: ${{ github.repository == 'HuGR-dev/corelink-server' && github.repository_id == '1232040291' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Checkout protected-base verifier
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: trusted-base
          fetch-depth: 1
          persist-credentials: false

      - name: Checkout exact candidate head as inert data
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
          path: candidate
          fetch-depth: 1
          persist-credentials: false

      - name: Validate candidate with the protected-base verifier
        run: >-
          python3 -S trusted-base/scripts/verify_i2176_grpc_deny_gate.py
          --trusted-base trusted-base
          --candidate candidate
          --expected-head ${{ github.event.pull_request.head.sha }}

      - name: Run protected-base adversarial fixtures
        run: python3 -S -m unittest -v trusted-base/tests/test_verify_i2176_grpc_deny_gate.py
'''


def read(root: Path, relative: Path) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ContractError(f"missing required file: {relative}") from error


def require_exact(candidate: Path, trusted_base: Path, relative: Path) -> None:
    if read(candidate, relative) != read(trusted_base, relative):
        raise ContractError(f"{relative}: candidate must equal the protected base")


def expected_index(trusted_base: Path) -> str:
    base_index = read(trusted_base, INDEX)
    canonical_import = IMPORT_ANCHOR + DENY_IMPORT
    canonical_opening = FETCH_OPENING + DENY_INSERTION + FIRST_PIPELINE_STEP

    if DENY_IMPORT in base_index:
        if base_index.count(canonical_import) != 1 or base_index.count(canonical_opening) != 1:
            raise ContractError(f"{INDEX}: protected base has a malformed gRPC deny boundary")
        return base_index

    if base_index.count(IMPORT_ANCHOR) != 1:
        raise ContractError(f"{INDEX}: protected base lacks the known import anchor")
    with_import = base_index.replace(IMPORT_ANCHOR, canonical_import)
    insertion_point = FETCH_OPENING + FIRST_PIPELINE_STEP
    if with_import.count(insertion_point) != 1:
        raise ContractError(f"{INDEX}: protected base lacks the known Fetch entrypoint")
    return with_import.replace(insertion_point, canonical_opening)


def expected_gate(trusted_base: Path) -> str:
    gate_path = trusted_base / GATE
    if gate_path.exists() and read(trusted_base, GATE) != GATE_SOURCE:
        raise ContractError(f"{GATE}: protected base has a malformed gRPC deny helper")
    return GATE_SOURCE


def expected_contract(trusted_base: Path) -> str:
    contract_path = trusted_base / CONTRACT
    if contract_path.exists() and read(trusted_base, CONTRACT) != CONTRACT_SOURCE:
        raise ContractError(f"{CONTRACT}: protected base has a malformed gRPC transport contract")
    return CONTRACT_SOURCE


def expected_workflow(trusted_base: Path) -> str:
    workflow_path = trusted_base / WORKFLOW
    if workflow_path.exists():
        return read(trusted_base, WORKFLOW)
    return BOOTSTRAP_WORKFLOW_SOURCE


def assert_exact_head(candidate: Path, expected_head: str) -> None:
    actual_head = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_head != expected_head:
        raise ContractError(
            f"candidate checkout is {actual_head}, expected pull-request head {expected_head}"
        )


def validate(candidate: Path, trusted_base: Path) -> None:
    # Keep the exception visibly bounded.  A future perimeter path belongs in
    # LOCKED_PERIMETER_PATHS unless its own protected contract proves it is
    # CI-only and credentialless.
    if set(MIGRATABLE_CI_PATHS) & set(LOCKED_PERIMETER_PATHS):
        raise ContractError("migratable CI paths must not bypass the locked perimeter")
    for relative in LOCKED_PERIMETER_PATHS:
        require_exact(candidate, trusted_base, relative)

    base_is_bootstrap = (
        DENY_IMPORT not in read(trusted_base, INDEX)
        and not (trusted_base / GATE).exists()
        and not (trusted_base / CONTRACT).exists()
    )
    candidate_is_unchanged_bootstrap = (
        read(candidate, INDEX) == read(trusted_base, INDEX)
        and not (candidate / GATE).exists()
        and not (candidate / CONTRACT).exists()
    )
    # A runner-only migration cannot add or alter the public gRPC surface.  At
    # the bootstrap base it therefore passes only if that whole surface is
    # byte-identical and absent.  Any #2176 implementation must still supply
    # the exact early denial below; this is not a gRPC enablement exception.
    if not (base_is_bootstrap and candidate_is_unchanged_bootstrap):
        if read(candidate, INDEX) != expected_index(trusted_base):
            raise ContractError(
                f"{INDEX}: candidate must equal the protected base plus the canonical early deny"
            )
        if read(candidate, GATE) != expected_gate(trusted_base):
            raise ContractError(f"{GATE}: candidate must equal the canonical no-inspection deny")
        if read(candidate, CONTRACT) != expected_contract(trusted_base):
            raise ContractError(f"{CONTRACT}: candidate must equal the canonical blocked contract")
    if read(candidate, WORKFLOW) != expected_workflow(trusted_base):
        raise ContractError(
            f"{WORKFLOW}: candidate must equal the protected-base gate workflow"
        )


def write(root: Path, relative: Path, content: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def write_fixture_base(root: Path) -> None:
    write(
        root,
        INDEX,
        'import { runScheduled } from "./index_schedule.js";\n\n'
        "export const baseHandler = {\n"
        + FETCH_OPENING
        + FIRST_PIPELINE_STEP
        + "    return new Response(String(requestStart));\n  },\n};\n",
    )
    for relative in LOCKED_PERIMETER_PATHS:
        write(root, relative, f"protected base fixture: {relative}\n")
    write(root, WORKFLOW, BOOTSTRAP_WORKFLOW_SOURCE)


def write_fixture_candidate(candidate: Path, trusted_base: Path) -> None:
    shutil.copytree(trusted_base, candidate, dirs_exist_ok=True)
    write(candidate, INDEX, expected_index(trusted_base))
    write(candidate, GATE, GATE_SOURCE)
    write(candidate, CONTRACT, CONTRACT_SOURCE)
    write(candidate, WORKFLOW, expected_workflow(trusted_base))


def expect_rejected(candidate: Path, trusted_base: Path, relative: Path, old: str, new: str) -> None:
    original = read(candidate, relative)
    if old not in original:
        raise ContractError(f"self-test fixture lost mutation anchor {old!r}")
    write(candidate, relative, original.replace(old, new, 1))
    try:
        validate(candidate, trusted_base)
    except ContractError:
        pass
    else:
        raise ContractError(f"mutation escaped the deny gate: {relative}: {old!r}")
    write(candidate, relative, original)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        fixture = Path(directory)
        trusted_base = fixture / "trusted-base"
        candidate = fixture / "candidate"
        write_fixture_base(trusted_base)
        write_fixture_candidate(candidate, trusted_base)
        validate(candidate, trusted_base)

        # A CI-only migration does not edit the absent bootstrap gRPC surface.
        unchanged = fixture / "unchanged"
        shutil.copytree(trusted_base, unchanged)
        validate(unchanged, trusted_base)

        mutations = (
            (INDEX, "if (grpcTransportGate !== null) return grpcTransportGate;", ""),
            (INDEX, "    const grpcTransportGate", "    await fetch(\"https://invalid.example\");\n    const grpcTransportGate"),
            (GATE, '"cache-control": "no-store"', '"cache-control": "public, max-age=600"'),
            (GATE, "return new Response", "return null;\n  // return new Response"),
            (GATE, '"application/grpc"', '"application/json"'),
            (CONTRACT, "protected-environment\nruntime receipt", "unverified deployment claim"),
            (WORKFLOW, "pull_request_target:", "pull_request:"),
            (WORKFLOW, '      - "worker/src/index_fetch.ts"\n', ""),
            (Path("worker/src/index.ts"), "protected base", "alternate public handler"),
            (Path("wrangler.toml"), "protected base", "main = \"worker/src/alternate.ts\""),
        )
        for relative, old, new in mutations:
            expect_rejected(candidate, trusted_base, relative, old, new)

        # A candidate may edit its own verifier, but the workflow never imports
        # it; the protected-base verifier above remains authoritative.
        write(candidate, Path("scripts/verify_i2176_grpc_deny_gate.py"), "raise SystemExit(0)\n")
        validate(candidate, trusted_base)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-base", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--expected-head")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            self_test()
        elif (
            arguments.trusted_base is not None
            and arguments.candidate is not None
            and arguments.expected_head is not None
        ):
            assert_exact_head(arguments.candidate, arguments.expected_head)
            validate(arguments.candidate, arguments.trusted_base)
        else:
            raise ContractError(
                "pass --self-test or --trusted-base, --candidate, and --expected-head"
            )
    except (ContractError, subprocess.CalledProcessError) as error:
        print(f"issue-2176 trusted deny gate: FAIL: {error}", file=sys.stderr)
        return 1
    print("issue-2176 trusted deny gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
