#!/usr/bin/env python3
"""Protected-base, source-only admission gate for issue #2176.

The ``pull_request_target`` workflow loads this program from the immutable
pull-request base SHA and supplies a separately checked-out candidate tree.
The candidate is read as UTF-8 data only. No candidate script, workflow,
package hook, build, test, or import is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import stat
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
B141_TEST = Path("tests/test_pull_request_target_spawn_boundary.py")
CANONICAL_SYMLINK = Path(".github/actionlint.yaml")
CANONICAL_SYMLINK_TARGET = "../.actionlint.yaml"


def load_trusted_delivery_policy() -> object:
    """Load only the sibling verifier shipped by this protected BASE tree."""
    path = Path(__file__).with_name("verify_i2574_grpc_diagnostic_policy.py")
    spec = importlib.util.spec_from_file_location("trusted_i2574_policy", path)
    if spec is None or spec.loader is None:
        raise ContractError("trusted delivery policy is unavailable")
    module = importlib.util.module_from_spec(spec)
    original_dont_write_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = original_dont_write_bytecode
    return module


def sha256_file(root: Path, relative: Path) -> str | None:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_regular_mode(root: Path, relative: Path, mode: int = 0o644) -> None:
    path = root / relative
    try:
        actual = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ContractError(f"missing pinned path: {relative}") from error
    if path.is_symlink() or not path.is_file() or actual & 0o777 != mode:
        raise ContractError(f"pinned mode drift: {relative}")


def require_canonical_symlink(base: Path, candidate: Path) -> None:
    for root in (base, candidate):
        path = root / CANONICAL_SYMLINK
        if (
            not path.is_symlink()
            or path.lstat().st_mode & 0o170000 != 0o120000
            or os.readlink(path) != CANONICAL_SYMLINK_TARGET
        ):
            raise ContractError("canonical actionlint symlink missing or changed")


def node_kind(path: Path) -> str:
    """Classify a path from lstat, so links never inherit their target kind."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    return "special"


def is_regular_digest(root: Path, relative: Path, expected: str) -> bool:
    path = root / relative
    return (
        node_kind(path) == "regular"
        and path.lstat().st_mode & 0o777 == 0o644
        and sha256_file(root, relative) == expected
    )


def is_absent(root: Path, relative: Path) -> bool:
    return node_kind(root / relative) == "absent"


def changed_paths(base: Path, candidate: Path) -> set[Path]:
    names = {p.relative_to(base) for p in base.rglob("*")} | {p.relative_to(candidate) for p in candidate.rglob("*")}
    changed: set[Path] = set()
    for name in names:
        if ".git" in name.parts:
            continue
        left, right = base / name, candidate / name
        left_kind, right_kind = node_kind(left), node_kind(right)
        if left_kind == "symlink" or right_kind == "symlink":
            if name != CANONICAL_SYMLINK or not left.is_symlink() or not right.is_symlink() or os.readlink(left) != CANONICAL_SYMLINK_TARGET or os.readlink(right) != CANONICAL_SYMLINK_TARGET:
                raise ContractError(f"noncanonical symlink: {name}")
            continue
        if left_kind == right_kind == "directory":
            continue
        if left_kind == "special" or right_kind == "special":
            raise ContractError(f"non-regular path: {name}")
        if left_kind != right_kind:
            changed.add(name); continue
        if left_kind == "regular" and (sha256_file(base, name) != sha256_file(candidate, name) or left.lstat().st_mode != right.lstat().st_mode):
            changed.add(name)
    require_canonical_symlink(base, candidate)
    return changed


MOUNT = {
    ".github/workflows/issue-2183-reapi-composition.yml": ("e7120a3bf5978cb83c1a5efea8c5388edf4dffa925d53a1b4b83696f8e35bc48", "bb382d6898ce95fb690c62bfc50334e94889dbf371fa7a0871dd7bac5e24b431"),
    "Cargo.toml": ("ea29a8e09c640ee07f33bce567b00d00c35b666e0843cdcd8c9c46317d110695", "6012612bdd15b83e906f9a870049e137a9f2b947af1dd1105ee9aa6a460bfb0a"),
    "crates/corelink-container/build.rs": ("11000cad599f6b9afea46c379c9f1dff73bd56d30a99aba68ddc9bc7ccfc8bd1", "b7d1b11510f0bf00a21f2f83a97a43389b0d288167f6b9c5516da57ffda9ce4d"),
    "crates/corelink-container/proto/staging_transport_probe.proto": (None, "b243732e58ba3ced040e9181befd4f3c2bd995e0b23eb750889c93629245970c"),
    "crates/corelink-container/src/grpc_staging_probe.rs": (None, "bab9a3dd5fea718e4e384e2fabe9145fadf9233bd9b41522c267ea02019d8e3d"),
    "crates/corelink-container/src/lib.rs": ("b47f78891864678310d0d3ff6395f00cf5a3fa074a8733cd656c49f09d07baa9", "01ad3ff6280beabd6dd0dea5e701315e41f7a1aba85a9dd3c7706bde0d3d7ef0"),
    "crates/corelink-container/src/main.rs": ("cd08712cf96d988246665314a29a02f7ecf7072def91b75dddc285513eeb4d16", "f1150ff53657179a26373bea5d009a732d1a9bccea8c820936858c460ae4b46c"),
    "crates/corelink-container/src/reapi_composition.rs": ("a7b0fcbe499f7db437da745e74091675e62c5917675a230d08a4cd35ea5f35c6", "57b3e2c730cf2f326b7f8bdb99df04b9423179524dc830805c3dbb8e62a5f337"),
    "examples/buck2-starter/.buckconfig": ("24ffdf356bff1238e4397392048f7f20702b75ef408ac03307adddca75be2905", "47f6c78d1b20449bf429537b0ba06f1453c2fbc3ec2e0e2b9e828b1f38281899"),
    "scripts/verify_i2183_reapi_composition.py": ("99550ecedb1d700945b5b214323923db2e6bbf9b17067e9f6758491cffe17f6d", "532408187817e4ff508e9b2f5776e1646f7f304235ab697cf2e28fbab49a1b6c"),
}

# Exact known public-deny state, derived from the frozen #2574 old-base
# fixtures.  The three diagnostic implementation paths did not exist there.
DENY = {
    "specs/03_architecture/issue-2176-grpc-transport-contract.md": "cc66f40453ffea97861297db9736d76f2feeea24ecfa39dd422426452b4e92db",
    "worker/src/grpc_transport_gate.ts": "aa4f8cba311c1609c56d54a5f1af2becbc67e136f4bcf49b3472d8e79e00e68e",
    "worker/src/grpc_staging_authorization.ts": None,
    "worker/src/grpc_staging_transport.ts": None,
    "worker/src/index_fetch.ts": "dfc46d5dc6c34078ad38708d03103508f923fead9d8b8149968a658000150b11",
    "worker/src/index_env.ts": "ffdaca609ecb6cbf44375c18e03b10212e00bcbdb1aade4381c3473dc0070ca4",
    "worker/src/index_env_contract.ts": "00600f034876b848b5c0008a982a0a813e1dc63d7daba4a5d75706356aff71cf",
    "worker/src/durable_object.ts": "30159334631b5d3dbe0f4d1569f3fcf9fe87ab1909592cd20b310d57082e1bc2",
    "worker/src/durable_object_probes.ts": "1d7f3c9038322f65ad8ffb7cfc6fe37109bdbad8c86fe97cad25df54d3bc7e60",
    "worker/src/durable_object_start.ts": "7069df729c81016bc46e5c969820d32cf6bea9eb69f82158efdf680c35a5bc47",
    "worker/tests/grpc_staging_transport.test.ts": None,
    "worker/src/lib/internal_auth.ts": "e773fa80db1ffd97ccdd20ae08e60e662482eea7e55bef6f19a3d61644b43acf",
}


def matches_state(root: Path, expected: dict[str, str | None]) -> bool:
    return all(
        is_absent(root, Path(path)) if digest is None else is_regular_digest(root, Path(path), digest)
        for path, digest in expected.items()
    )


def classify_phase(root: Path) -> str:
    policy = load_trusted_delivery_policy()
    if matches_state(root, policy.EXPECTED):
        if all(
            is_absent(root, Path(path)) if preimage is None else is_regular_digest(root, Path(path), preimage)
            for path, (preimage, _candidate) in MOUNT.items()
        ):
            return "pre-mount"
        if all(is_regular_digest(root, Path(path), candidate) for path, (_preimage, candidate) in MOUNT.items()):
            return "mounted"
        raise ContractError("partial or unknown #2578 mount state")
    if matches_state(root, DENY):
        return "deny"
    raise ContractError("unknown or partial delivery base state")

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

# Exact #1700 transition needed to load the already-reviewed ContainerProxy
# export. This exception is available only when the whole protected 23-path
# delivery tree matches its aggregate pin; the package and lockfile must both
# move from these exact preimages to these exact successors.
STAGING_D1_PROXY_PACKAGE_LOCK_PREIMAGES = {
    Path("worker/package.json"): "7b20dc56684526ad90f3b5998aa995f41b750e304397714ab34b6ece2e162348",
    Path("pnpm-lock.yaml"): "b2b79225204fbce1b33e64f03987f0b894b1f7a187daef51078411d6285e0278",
}
STAGING_D1_PROXY_PACKAGE_LOCK_TARGETS = {
    Path("worker/package.json"): "96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34",
    Path("pnpm-lock.yaml"): "7d8509a802bad9c700070722a8e834c98aef18c925768fb9c763a90a5a10c6cc",
}
STAGING_D1_PROXY_DELIVERY_PATHS = frozenset(map(Path, (
    ".github/workflows/staging-quarantine-apply.yml",
    "crates/corelink-container/src/storage.rs",
    "crates/corelink-container/src/storage/d1_http.rs",
    "docs/internal/secrets-checklist.md",
    "infra/staging/README.md",
    "infra/staging/topology.json",
    "pnpm-lock.yaml",
    "scripts/staging_bootstrap_provider.py",
    "scripts/verify_staging_provider_preflight.py",
    "scripts/verify_staging_topology_contract.py",
    "tests/test_staging_bootstrap_provider.py",
    "tests/test_staging_custom_domain.py",
    "tests/test_staging_quarantine_apply_contract.py",
    "worker/package.json",
    "worker/src/durable_object.ts",
    "worker/src/durable_object_start.ts",
    "worker/src/index.ts",
    "worker/src/staging_d1_binding_proxy.ts",
    "worker/src/staging_d1_binding_proxy_entrypoint.ts",
    "worker/tests/cloudflare_workers_node_stub.ts",
    "worker/tests/staging_d1_binding_proxy.test.ts",
    "worker/tests/staging_d1_binding_start_gate.test.ts",
    "worker/vitest.config.mts",
)))
STAGING_D1_PROXY_DELIVERY_TREE_SHA256 = "c3be4d5980841b0a05a339d43ae184d8cd5477afbcc19f7a9f7a1e42dc02284b"

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


def preauthorized_staging_d1_proxy_tree(
    candidate: Path,
    trusted_base: Path,
    changes: set[Path],
) -> bool:
    if len(STAGING_D1_PROXY_DELIVERY_PATHS) != 23 or changes != STAGING_D1_PROXY_DELIVERY_PATHS:
        return False
    if set(STAGING_D1_PROXY_PACKAGE_LOCK_PREIMAGES) != set(STAGING_D1_PROXY_PACKAGE_LOCK_TARGETS):
        return False
    for relative, preimage in STAGING_D1_PROXY_PACKAGE_LOCK_PREIMAGES.items():
        if not is_regular_digest(trusted_base, relative, preimage):
            return False
        target = STAGING_D1_PROXY_PACKAGE_LOCK_TARGETS[relative]
        if not is_regular_digest(candidate, relative, target):
            return False
    rows: list[str] = []
    for relative in sorted(STAGING_D1_PROXY_DELIVERY_PATHS, key=str):
        if node_kind(candidate / relative) != "regular":
            return False
        mode = (candidate / relative).lstat().st_mode & 0o777
        if mode != 0o644:
            return False
        digest = sha256_file(candidate, relative)
        if digest is None:
            return False
        rows.append(f"{relative}\t{mode:04o}\t{digest}\n")
    tree_digest = hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()
    return tree_digest == STAGING_D1_PROXY_DELIVERY_TREE_SHA256


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
    changes = changed_paths(trusted_base, candidate)
    staging_d1_proxy_tree = preauthorized_staging_d1_proxy_tree(
        candidate, trusted_base, changes
    )
    for relative in LOCKED_PERIMETER_PATHS:
        if staging_d1_proxy_tree and relative in STAGING_D1_PROXY_DELIVERY_PATHS:
            continue
        require_exact(candidate, trusted_base, relative)

    # Once #2574's protected predicate exists in BASE, neither its policy
    # surface nor the B141 spawn-boundary sentinel may be changed by any
    # phase, including a deny-base candidate.  The module is loaded only from
    # this verifier's sibling path in trusted BASE.
    policy = None
    if (trusted_base / "scripts/verify_i2574_grpc_diagnostic_policy.py").is_file():
        policy = load_trusted_delivery_policy()
        frozen_policy = {Path(path) for path in policy.POLICY | policy.POLICY_FIXTURES}
        frozen_policy.add(B141_TEST)
        for relative in frozen_policy:
            if staging_d1_proxy_tree and relative in STAGING_D1_PROXY_DELIVERY_PATHS:
                continue
            require_regular_mode(trusted_base, relative)
            require_regular_mode(candidate, relative)
            require_exact(candidate, trusted_base, relative)

    # Inspect the full union before selecting an admission branch.  This is
    # deliberately closed-world: a candidate cannot use a partial delivery or
    # an unrelated Container change to reach a weaker legacy deny check.
    if policy is not None and not staging_d1_proxy_tree:
        phase = classify_phase(trusted_base)
        ci_changes = set(MIGRATABLE_CI_PATHS)
        ci_only = changes <= ci_changes and all(
            node_kind(trusted_base / path) == node_kind(candidate / path) == "regular"
            and (trusted_base / path).lstat().st_mode == (candidate / path).lstat().st_mode
            for path in changes
        )
        if phase == "deny":
            if not changes or ci_only:
                return
            delivery_paths = {Path(path) for path in policy.EXPECTED} - {Path("worker/src/lib/internal_auth.ts")}
            if changes - delivery_paths:
                raise ContractError(f"deny closed-world violation: {sorted(map(str, changes - delivery_paths))}")
            try:
                policy.validate(trusted_base, candidate)
            except policy.ContractError as error:
                raise ContractError(str(error)) from error
            return

        if phase != "deny":
            if not changes or ci_only:
                return
            if phase == "pre-mount" and changes == {Path(path) for path in MOUNT}:
                pass
            else:
                raise ContractError(f"post-delivery closed-world violation: {sorted(map(str, changes))}")
        for path, digest in policy.EXPECTED.items():
            relative = Path(path)
            if sha256_file(trusted_base, relative) != digest or sha256_file(candidate, relative) != digest:
                raise ContractError(f"delivered transport drift: {relative}")
            if (trusted_base / relative).lstat().st_mode & 0o777 != 0o644 or (candidate / relative).lstat().st_mode & 0o777 != 0o644:
                raise ContractError(f"delivered transport mode drift: {relative}")
        for path, (preimage, mounted) in MOUNT.items():
            relative = Path(path)
            base_matches = (
                is_absent(trusted_base, relative)
                if phase == "pre-mount" and preimage is None
                else is_regular_digest(trusted_base, relative, mounted if phase == "mounted" else preimage)
            )
            if not base_matches:
                raise ContractError(f"mount base drift: {relative}")
            if not is_regular_digest(candidate, relative, mounted):
                raise ContractError(f"mount candidate drift: {relative}")
        return

    if staging_d1_proxy_tree:
        # The protected gRPC gate now includes a separately reviewed staging
        # diagnostic forwarder, so its older bootstrap-shape constructor no
        # longer describes current main. The exact #1700 tree may proceed only
        # with the entire current gRPC ingress contract unchanged.
        for relative in (INDEX, GATE, CONTRACT, WORKFLOW):
            require_exact(candidate, trusted_base, relative)
        return

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
    write(root, Path(".actionlint.yaml"), "self-test actionlint fixture\n")
    (root / CANONICAL_SYMLINK).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(CANONICAL_SYMLINK_TARGET, root / CANONICAL_SYMLINK)
    write(root, WORKFLOW, BOOTSTRAP_WORKFLOW_SOURCE)


def write_fixture_candidate(candidate: Path, trusted_base: Path) -> None:
    shutil.copytree(trusted_base, candidate, dirs_exist_ok=True, symlinks=True)
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
        shutil.copytree(trusted_base, unchanged, symlinks=True)
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
