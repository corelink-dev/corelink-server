#!/usr/bin/env python3
"""Protected-base, source-only admission gate for issue #2176.

The ``pull_request_target`` workflow loads this program from the immutable
pull-request base SHA and supplies a separately checked-out candidate tree.
The candidate is read as UTF-8 data only. No candidate script, workflow,
package hook, build, test, or import is executed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zlib
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


# One exact BASE-authorized transition admits the #2575 client/probe delivery.
# The old actionlint configuration is the only preimage; every other path must
# be absent. Once merged, the complete target tree is immutable under this gate.
I2575_PREIMAGES: dict[Path, tuple[int, str] | None] = {
    Path(".actionlint.yaml"): (0o644, "2e1ad216236818322adb7baed2e25dcc836cd7a030493fd799f4d4fc06702576"),
    Path(".github/workflows/issue-2575-staging-grpc-probe.yml"): None,
    Path("docs/internal/issue-2575-postflight-handoff.md"): None,
    Path("scripts/i2575_grpc_probe_client.py"): None,
    Path("scripts/verify_i2575_readiness.py"): None,
    Path("tests/test_i2575_grpc_probe_client.py"): None,
    Path("tests/test_verify_i2575_readiness.py"): None,
}
I2575_TARGETS: dict[Path, tuple[int, str]] = {
    Path(".actionlint.yaml"): (0o644, "fac3a8d8271a9d2b4763ecaa966890f693cf025167f5b3f1f6cd945f706282df"),
    Path(".github/workflows/issue-2575-staging-grpc-probe.yml"): (0o644, "6055fd324f55df7549d47944e239f6e70849548c47026302e85d98b89ebc988c"),
    Path("docs/internal/issue-2575-postflight-handoff.md"): (0o644, "44f912211ef866e9d6d0ec20a1d7ca7f4280aaddd60ffa430aad604b551b2bd9"),
    Path("scripts/i2575_grpc_probe_client.py"): (0o755, "7e2eb08c70a29089afc084ed499fd60176bca96c41f363aca802ec3989461611"),
    Path("scripts/verify_i2575_readiness.py"): (0o644, "931ead0889c3cafc223141b97d933d0b1f571439a16bc57fda41e7440f238239"),
    Path("tests/test_i2575_grpc_probe_client.py"): (0o644, "88041922a3c27e82288daf1c5d379b900338937438eedd312fd880fee0f7b7e8"),
    Path("tests/test_verify_i2575_readiness.py"): (0o644, "77f6d855686a3aced792eeaa166758e19b31e5fb13f6a5e4c4dae1d0703c67cf"),
}
I2575_DELIVERY_PATHS = frozenset(I2575_TARGETS)
I2575_ACTIONLINT_PREIMAGE_ZLIB_B64 = (
    "eNp9V9Fy27YSffdXYOpO03ZCKnYTt6POfaAoWGaskBqSstNO5tIUCUm4hkgWAO1o2v77PQApWUrsvEgksFjsnrPAHp4SP6/qihe5IHmheV0JXmlS1NWSr1qZmxGyrCVGJMPUvaOYfGDSPTk9OSUxWzLJqoINyVrrRg0HgxXX63bhFvVmINdbVQ6evA4Wol4MHs7cX92z80FZF2rQ7eNuSuvuzu1WH6xxt/lG3BGuSE7UdmMiILnguSK6JnqN8SUXzCXXjDXdu6xrDV+s0nJLmtpkk7d6XUuukc0DI6o+yPSVIuxzI3jBYVaVRLKmVlzXcuuUXBU1Ut3CW5PrtSJFXlW1Jgo7Vlps4eavlktGSr60OGgi26pi0hH5ggls3rTCIqg6uKJWYhCbbYd4I8QhyZXnNLwi2IYvQYKFu16Su1YxNbR5swrwF6wki61dRIgqJG+0GthFW6dLxlHr3LiqeLVymy35UbEmB3+M+AFZ4X9IDgzztuTAdiN+cnunR+RvGsE2yAcor3ONnZG6LtZwDRIqnX8mA6LYJq80L8zjmglRrFlxT0qEpN0+u3TNSNEqXW+IRUQR/NSPJAdmGnP9ILZucwE8kbRJ084tBWOWkj6+da00ZkUuVwC4w5n8r16o30lZE0OLZBvQReqKkUeUUd1q0jYlIEXUe4+70G4ZysjEohpWGOgPk5CtMKSqfCGYItygwsiPzF25JPHP35xdkGUuFOsjswWDwlLYmkyuPHL3/d9/k3//BXuV4iUKDhEI5vzV1iYDVqxrorTEoHpt/b29wMreGfAH7mAC5/GxlqWjUJza5oAyUaxoUcfbgeBKO/dsW6xzbPKTS8Z10RrGCMuLde+rz8CigeNzd3pEVDf5H9d17wzjdjHHX8lRLKa4F0Cz92Tgq1HjVWkCMXC4JyeKiaXT0dLzMTwh5JRcWuY6bof7ewOQLSRgbkSrrL9NXkQJWbRclGCyI8dWTEexddWT3rPdnSpzFQic4ZIVsDQFw4oclXNYwQ+4IsA8M6bCegKW90vDt7kuVAeJvS5MuRT7K/Do3nOxsk/jhNiqQcz90/467BPoh9tFW+nW+Xzx1nlrTL6wPjnpNnAecsltdXWQ+aI2pf90YSA7iZIqyVLi8Bi4sEK5P5vLSjKlzJ2CgrCLd5fmLkU1+Nmc7MM70ZQLlgIh3AJkw5Upyf6KFCw3tZtbX5J1dddh1VYlW4Ls8jV5XAM3HEd40TLvl65R3fZi1jkmj7Cz3kAQ3xgUHeLNx0Ga+VdeEOKX+tezKAjT7Jr+kQXjA4v4PBvN/WuaHozdBmlIkyQbRx+w/JmJIw+7wXk8fWZ0Nh9NA9/sm2Tvk6jzNjp780uW0tBDRL2vkedfz2dfhDMKptMgnGTeZBLTiZfSbBrc0KOpmPpR6AfTZ6aSNA5mGKfjCY2z1BtNj+fniTehB+P+ZfZnFNJdRH4UU9hdZ95stk9uP3gZ0+Qq+2Aw/WpuRuPLbOQl9Hg48X0PVGSzYBp1+Y3PsrGHAGCadANpRsOxpcq+03NqHe33MAPjyE+OBoIwSb3pdD92FSUpHWeenwZRmGTejRdM91kG5+8ufstmcXQTjAELksMj7VK+mk/iHWwxvXwau4V7mj7ldH2Thd4Hmsw8v488pB/THdn+lMbX3Qv6LTY29H9t9YRvsA/90CChYRr/kY2T8OupLsbntohG76mfZtPIvzZZjihw8KP5U6U9Y2Ax8KYmZxrT0KcvGHaliRd6GXx8wQbJeyEqOboNafyiTTQfpzFoyegNsrRVgKSAyMtRHizqfr04fMkUBZD5NOjLfIw69eMo+Zb1t8J9P4+DZBzYcnrBBMfzG5MR+NlFixOeUmx4cMx3bMaBb/IHEF6c9tH0c3bJF0TeBuE4uk0Q/5hmSTAJTbb04yzA0cy89GWbIEnmvftn58MI4dFLsHFks5tGhVAcCEPatw06TNHSDzplJ8YJmkrXLydcX7ULqOKyFxToQQ+tQPvNFxxKBHJTMGmEYX3PjGiBRm6Ylc5Lka9U129s/zXNpHSwD2Q4k7bpoKfuuhJDJylY0wneygzAmWnGWra26e/1JUReJ0ONJiZc/25X99Jg5Jy/e2v1LUH4O8HaeVP5xsi4fFXB1ig8zYWADuHC9E7CjLYnNWzlvuW5J1bpm678dVtd5MW9qNG8re42PbbTBRwbSNY9G/xf/bet7qv6sTrIu8fpu+ew/O6T+8r2y9RghzaqIeoOgjKSZ7HVzBF1cf+kkHdAnZ6f/XpBVvHMh2qotl3nhRMJml0SAJMC7BpVid6+anNZwk7wBZOd0OsBWRLGLRYrVtmpsvP0tNZ8F4AhoxPxWbJp9Pa1+ZhKjKj0jahE2Vh9/M7ocWasDuSs+yym+2w7IeU0rVo7jazLb8F7KNXxvSYNCoC5ZYZWW4DdJ9KwD2fI8Q01PHszPPtlSEITmq0Sj/zwAxmRT/98+of4JlrzFcGXDlCoHKg+9snF+CbfGgEKBcQqLIEZgGffvzr5P/cn1EU="
)


def matches_pinned_file(root: Path, relative: Path, pin: tuple[int, str]) -> bool:
    mode, digest = pin
    path = root / relative
    return (
        node_kind(path) == "regular"
        and path.lstat().st_mode & 0o777 == mode
        and sha256_file(root, relative) == digest
    )


def i2575_base_state(root: Path) -> str:
    if set(I2575_PREIMAGES) != I2575_DELIVERY_PATHS or set(I2575_TARGETS) != I2575_DELIVERY_PATHS:
        return "unknown"
    preimage = all(
        is_absent(root, relative) if pin is None else matches_pinned_file(root, relative, pin)
        for relative, pin in I2575_PREIMAGES.items()
    )
    delivered = all(matches_pinned_file(root, relative, pin) for relative, pin in I2575_TARGETS.items())
    if preimage:
        return "preimage"
    if delivered:
        return "delivered"
    return "partial-or-unknown"


def preauthorized_i2575_delivery(candidate: Path, trusted_base: Path, changes: set[Path]) -> bool:
    if len(I2575_DELIVERY_PATHS) != 7 or not I2575_DELIVERY_PATHS <= changes:
        return False
    structural = changes - I2575_DELIVERY_PATHS
    if any(
        node_kind(candidate / path) != "directory"
        or not any(target.is_relative_to(path) for target in I2575_DELIVERY_PATHS)
        for path in structural
    ):
        return False
    if i2575_base_state(trusted_base) != "preimage":
        return False
    return all(matches_pinned_file(candidate, relative, pin) for relative, pin in I2575_TARGETS.items())


def changed_paths(base: Path, candidate: Path) -> set[Path]:
    names = {p.relative_to(base) for p in base.rglob("*")} | {p.relative_to(candidate) for p in candidate.rglob("*")}
    changed: set[Path] = set()
    for name in names:
        if ".git" in name.parts:
            continue
        left, right = base / name, candidate / name
        left_kind, right_kind = node_kind(left), node_kind(right)
        if left_kind == "symlink" or right_kind == "symlink":
            if (
                left_kind != "symlink" or right_kind != "symlink"
                or left.lstat().st_mode != right.lstat().st_mode
                or os.readlink(left) != os.readlink(right)
            ):
                raise ContractError(f"added, retargeted, or replaced symlink: {name}")
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
    Path(".github/workflows/issue-2730-dsr-alert-receiver.yml"),
    Path(".github/workflows/issue-2568-sla-credit-real.yml"),
    Path(".actionlint.yaml"),
    Path(".actionlint.yaml"),
)

# Exact #1700 transition needed to load the reviewed ContainerProxy export and
# its private runtime probe. The exception covers only the frozen 37-path tree.
# Separate exact successors below admit #1648 and B216 after their own bases.
STAGING_D1_PROXY_PACKAGE_LOCK_PREIMAGES = {
    Path('worker/package.json'): '7b20dc56684526ad90f3b5998aa995f41b750e304397714ab34b6ece2e162348',
    Path('pnpm-lock.yaml'): 'b2b79225204fbce1b33e64f03987f0b894b1f7a187daef51078411d6285e0278',
}
STAGING_D1_PROXY_PACKAGE_LOCK_TARGETS = {
    Path('worker/package.json'): '96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34',
    Path('pnpm-lock.yaml'): '7d8509a802bad9c700070722a8e834c98aef18c925768fb9c763a90a5a10c6cc',
}
STAGING_D1_PROXY_DELIVERY_PATHS = frozenset(map(Path, (
    ".github/workflows/issue-1700-container-staging-deploy.yml",
    ".github/workflows/staging-quarantine-apply.yml",
    "crates/corelink-container/src/main.rs",
    "crates/corelink-container/src/routes.rs",
    "crates/corelink-container/src/routes/staging_d1_binding_probe.rs",
    "crates/corelink-container/src/storage.rs",
    "crates/corelink-container/src/storage/d1_http.rs",
    "docs/internal/secrets-checklist.md",
    "infra/staging/README.md",
    "infra/staging/topology.json",
    "pnpm-lock.yaml",
    "scripts/issue_1700_runtime_probe.mjs",
    "scripts/staging_bootstrap_provider.py",
    "scripts/tests/issue_1700_runtime_probe.test.mjs",
    "scripts/verify_staging_provider_preflight.py",
    "scripts/verify_staging_topology_contract.py",
    "tests/test_issue_1700_route_inventory.py",
    "tests/test_staging_bootstrap_provider.py",
    "tests/test_staging_custom_domain.py",
    "tests/test_staging_quarantine_apply_contract.py",
    "worker/package.json",
    "worker/src/durable_object.ts",
    "worker/src/durable_object_start.ts",
    "worker/src/index.ts",
    "worker/src/index_schedule.ts",
    "worker/src/lib/devenv_cleanup_route.ts",
    "worker/src/lib/runner_credential_routes.ts",
    "worker/src/pat_issue_rate_limit.ts",
    "worker/src/staging_d1_binding_proxy.ts",
    "worker/src/staging_d1_binding_proxy_entrypoint.ts",
    "worker/src/staging_runtime_d1_probe.ts",
    "worker/tests/cloudflare_workers_node_stub.ts",
    "worker/tests/durable_object.test.ts",
    "worker/tests/staging_d1_binding_proxy.test.ts",
    "worker/tests/staging_d1_binding_start_gate.test.ts",
    "worker/tests/staging_runtime_d1_probe.test.ts",
    "worker/vitest.config.mts",
)))
STAGING_D1_PROXY_DELIVERY_TREE_SHA256 = "05e9e3c71a7073146ced7fbcf52afaf8acae88ee6ffc621710921a0eb1f6ec0e"
STAGING_D1_PROXY_TARGETS = {
    Path('.github/workflows/issue-1700-container-staging-deploy.yml'): (420, 'c31908be992a6727e124e9b87160708af44fa2f1a042be2bd142b930abf15199'),
    Path('.github/workflows/staging-quarantine-apply.yml'): (420, '24d901a61e2b45af71fc5ec0632455956690725f8f05f9959c0baf213deb1594'),
    Path('crates/corelink-container/src/main.rs'): (420, '44c28a9a8387212b156ce05aa65918b0c34454453d7fcd85e79fd29f9a5518db'),
    Path('crates/corelink-container/src/routes.rs'): (420, '04a84d7be655fd25ee6d05d1b5c598c169be1aae381a255533ffeda0aad1ec2f'),
    Path('crates/corelink-container/src/routes/staging_d1_binding_probe.rs'): (420, '237d0679a4d7b63c7ad1f9634d74fbd029f62e38e8ad3aa8982e014204d032ff'),
    Path('crates/corelink-container/src/storage.rs'): (420, 'ee16e0155fae72ddfe01fedb4b7d29bff087467b2a23c42c830a42f3aeb9b78e'),
    Path('crates/corelink-container/src/storage/d1_http.rs'): (420, '258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5'),
    Path('docs/internal/secrets-checklist.md'): (420, '6157f5653e1a4ebea7be4a11e69e04abd36f59eb5fed6fa23997bb48f18f45b8'),
    Path('infra/staging/README.md'): (420, '5f3daac1edba6320bcfc6663d57bece16a9c63b7977156c0fc3a3b562276a435'),
    Path('infra/staging/topology.json'): (420, 'a55b4e72f63569b74539e9b42a8c0b34bd964f9213a5696b535fb2eb4ca24b14'),
    Path('pnpm-lock.yaml'): (420, '7d8509a802bad9c700070722a8e834c98aef18c925768fb9c763a90a5a10c6cc'),
    Path('scripts/issue_1700_runtime_probe.mjs'): (420, '7045e5d0f1bd8065055396494ea14c8162457f37637bb5e0078223bce0a02186'),
    Path('scripts/staging_bootstrap_provider.py'): (420, '8a77837893f2bd094f1fd834042361e69375e1453ec1d4dde9c20c605d00ccdb'),
    Path('scripts/tests/issue_1700_runtime_probe.test.mjs'): (420, '48e3b316bd716f112e682636a8e9dd3f3f759aedf8809e6d7535c40b966187ab'),
    Path('scripts/verify_staging_provider_preflight.py'): (420, 'ddc9d57aa31cbee273dabc923b23a3ef33fb11b40bbd3b746ad7dcaca0633b62'),
    Path('scripts/verify_staging_topology_contract.py'): (420, '48b69bc6c4852ef8218058d53105fb82c4a60d22af25739b111dc4a0def79bf9'),
    Path('tests/test_issue_1700_route_inventory.py'): (420, 'd9dc1e4012f590ef6b3e76eb1e342ac43d513a14ef16f3ee8db8cffb9ef2b734'),
    Path('tests/test_staging_bootstrap_provider.py'): (420, 'ec4633c038fd4ae1553464e00ba2ce6dfe79e10562f79243e0fb629d1d93e219'),
    Path('tests/test_staging_custom_domain.py'): (420, 'cfc063496302c06c8bc879c380c7f24e13088fdf8f2a5412def3e6e60b115afc'),
    Path('tests/test_staging_quarantine_apply_contract.py'): (420, 'b90d143271b96038ce2f51a23bc62b3be3fee546a231f003b9bcfbfb79a497bf'),
    Path('worker/package.json'): (420, '96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34'),
    Path('worker/src/durable_object.ts'): (420, 'c4046c2008acedecc7d1404bfad2fecbda58131e66927b58c5d56d82ca9febb9'),
    Path('worker/src/durable_object_start.ts'): (420, '7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c'),
    Path('worker/src/index.ts'): (420, '18b960a74833284f953bd28818cd7260798d9570c17bce459502f7b7ca50f3cd'),
    Path('worker/src/index_schedule.ts'): (420, 'fa2385df3e6ec121de862845fac0a66e48edb506912a95f2c7d3a02dae671678'),
    Path('worker/src/lib/devenv_cleanup_route.ts'): (420, 'e279cb99a585388fbf4483313a80c042df3c14bf1ca5ef52c31dc451e329907c'),
    Path('worker/src/lib/runner_credential_routes.ts'): (420, '6cd7af8c032dd8315c619f6830c3ef63df1a459152f197ca6a7faedf847b5731'),
    Path('worker/src/pat_issue_rate_limit.ts'): (420, 'ff4ca0814c40f128fed4650b2041660670bcc985037b975cb6f29b177d3c1afb'),
    Path('worker/src/staging_d1_binding_proxy.ts'): (420, '1e5d940b240a4bef9daba0e360758793ab7b11a165f5b1bc8ccb7eae658a348d'),
    Path('worker/src/staging_d1_binding_proxy_entrypoint.ts'): (420, 'af759d84e63a2016737c899cfba045f52c1fcf20061678a3612ddeec6c18bdab'),
    Path('worker/src/staging_runtime_d1_probe.ts'): (420, '3758098dd2419314fd006fdb8478f5b5043b1b80dd6679a31e2043323355f132'),
    Path('worker/tests/cloudflare_workers_node_stub.ts'): (420, '0237103e747517298fea07261598d250e25edff6f412cd1df33695c1585cfcf7'),
    Path('worker/tests/durable_object.test.ts'): (420, '53f07e0929c957a4e804e2f9063e01359e382fea74b7c0322c2a41f47bbd16a2'),
    Path('worker/tests/staging_d1_binding_proxy.test.ts'): (420, '5710f974898de4c88a1ddca3f9815589d7c805faa4481f44d9005054d10796cc'),
    Path('worker/tests/staging_d1_binding_start_gate.test.ts'): (420, '2377e10e46528888f60f711820a931f8358d214ac53b8c822bfac9c2d9f2da66'),
    Path('worker/tests/staging_runtime_d1_probe.test.ts'): (420, '05bfc2224d8db3ab72946332bcb41b4667e5e628da30a24a237ed57f7163f639'),
    Path('worker/vitest.config.mts'): (420, 'e2c2f0e46d4a45d5e789f920f95b73ffd44e6a14a9450e11817426995feda506'),
}

STAGING_D1_PROXY_PREIMAGES = {
    Path('.github/workflows/issue-1700-container-staging-deploy.yml'): (420, '9970b7ae60d825c8d5f5deaa1e82a84a58f96352312f9f8faa699621ccc38e76'),
    Path('.github/workflows/staging-quarantine-apply.yml'): (420, '11937887c2dc88942e0c35e7b3824c9835c0f484e6ae1f0fdd8de4066a83c9da'),
    Path('crates/corelink-container/src/main.rs'): (420, 'f1150ff53657179a26373bea5d009a732d1a9bccea8c820936858c460ae4b46c'),
    Path('crates/corelink-container/src/routes.rs'): (420, 'd1909aefc3f99b981eebb10d018b8fdb21ce739f05c834257f7412c85d88a7ef'),
    Path('crates/corelink-container/src/routes/staging_d1_binding_probe.rs'): None,
    Path('crates/corelink-container/src/storage.rs'): (420, '89bd546ac229e17454dc27457e306662f8dbc3babab440c889ab2c485e9bf361'),
    Path('crates/corelink-container/src/storage/d1_http.rs'): (420, '57df01654b44a12c57663d4543b1290125c87346e014e3b8210624a2d9cb6dd2'),
    Path('docs/internal/secrets-checklist.md'): (420, '24d0e59ee398a92a1bfd037daf4482d619129118e6236c1bea974b76b4ef3b22'),
    Path('infra/staging/README.md'): (420, '4689c4a43dda1d69ecbb60cdc8a65b4e2f2e5e017f5783f06f567d70ff8ab0ea'),
    Path('infra/staging/topology.json'): (420, '586665e34c11bf91a34fb83247fdbafec9fdfb8e7a336ba4da6f5bda8266dd99'),
    Path('pnpm-lock.yaml'): (420, 'b2b79225204fbce1b33e64f03987f0b894b1f7a187daef51078411d6285e0278'),
    Path('scripts/issue_1700_runtime_probe.mjs'): None,
    Path('scripts/staging_bootstrap_provider.py'): (420, '4684063fe7acbbc781ea177e029ea6d6ac7b7d4b906a814cf0c41b67eda8abf4'),
    Path('scripts/tests/issue_1700_runtime_probe.test.mjs'): None,
    Path('scripts/verify_staging_provider_preflight.py'): (420, '30c5e7fca9151d5a5147cc37b0ea49ced0100bd0dce5392eec4faa9e53afbfe0'),
    Path('scripts/verify_staging_topology_contract.py'): (420, '18a70767b543a5ea8cadda94a216c068de41a8a294182ef255067126a9fa0e27'),
    Path('tests/test_issue_1700_route_inventory.py'): (420, '216a00df6c5b67d78c90d5a9d1c78043a56985c230d7ede72e0270186eb6ef56'),
    Path('tests/test_staging_bootstrap_provider.py'): (420, '189efec0ef4b61b5a5efbea105ad56c210196c4b051fc9c1119645ec3758f5f7'),
    Path('tests/test_staging_custom_domain.py'): (420, 'ebca7d9b0e46763cac025dfc79bda65291d1e77f2132176527f28c9f8238e3a2'),
    Path('tests/test_staging_quarantine_apply_contract.py'): (420, 'ceb689591b8a5e380ce34f91bc598262c8f9051aaa84b7e0d05c088f194dffe6'),
    Path('worker/package.json'): (420, '7b20dc56684526ad90f3b5998aa995f41b750e304397714ab34b6ece2e162348'),
    Path('worker/src/durable_object.ts'): (420, '5be00eb88931adf4b2789c15ff3e715407dcd3e67e176de370c0922b175356a7'),
    Path('worker/src/durable_object_start.ts'): (420, '26d78fadfb89ca7327f698696ec15c53c455823f3f2c1ae3c282af16b4cab244'),
    Path('worker/src/index.ts'): (420, '627c97d894c9d02521e279b1721a9b0a4346ab1050a586706321b94931fbee8c'),
    Path('worker/src/index_schedule.ts'): (420, '1dab69b8d54f53129631f2135a23ade52fa2772c384e785f4e356c035e4888da'),
    Path('worker/src/lib/devenv_cleanup_route.ts'): (420, 'f039ca514d423ef4acdd722e5561482efcb99c4fab99d49ab0e8374e36c6cf71'),
    Path('worker/src/lib/runner_credential_routes.ts'): (420, '0830e3843c4b252efc3c0842e87441fe050ff7e9372ebd99879482eb898a1715'),
    Path('worker/src/pat_issue_rate_limit.ts'): (420, '139d80e9037eba47e5712e6d80110e70fc7360e61f0c5ce2b7529e80146485a4'),
    Path('worker/src/staging_d1_binding_proxy.ts'): None,
    Path('worker/src/staging_d1_binding_proxy_entrypoint.ts'): None,
    Path('worker/src/staging_runtime_d1_probe.ts'): None,
    Path('worker/tests/cloudflare_workers_node_stub.ts'): None,
    Path('worker/tests/durable_object.test.ts'): (420, 'ae533b3614615a5ca908922af6082f8e504986947f4db22d52b6dbe65018a669'),
    Path('worker/tests/staging_d1_binding_proxy.test.ts'): None,
    Path('worker/tests/staging_d1_binding_start_gate.test.ts'): None,
    Path('worker/tests/staging_runtime_d1_probe.test.ts'): None,
    Path('worker/vitest.config.mts'): (420, '0ee4c1a03685a300e6ead7720901ab0ae9103da8ffb359a34c5b10e7d3e46a44'),
}

# Ordered, isolated successor transitions. These are not mixed with the #1700
# tree: #1648 follows the merged #1700 base; B216 follows #1700 and its exact
# checklist preimage. Each transition is exact-path and exact mode/hash only.
I1648_PREIMAGES = {
    Path(".github/workflows/container-build-push-prod.yml"): (0o644, "db7124deb092eb309e3d3421ab304e2b53267dbcbdd5547dd2f86b87273a5b2f"),
    Path("scripts/verify_b063_hosted_build_workflow.py"): None,
    Path("scripts/test_verify_b063_hosted_build_workflow.py"): None,
    Path("wrangler.toml"): (0o644, "d9aeb0fab1790d37fc6511c0760a812921e8405bafc039a046947dd565576ddc"),
    Path("evidence/owner-actions/B-063/production-image-build-receipt.json"): None,
}
I1648_TARGETS = {
    Path(".github/workflows/container-build-push-prod.yml"): (0o644, "8ee0d29eff20ef5d473e4a712279a727fcdc6c881ba2bb46433f7659802f598f"),
    Path("scripts/verify_b063_hosted_build_workflow.py"): (0o644, "09617a685bb467ed749dadd0e6d5155e08e901733393223f825b34e2b2c22157"),
    Path("scripts/test_verify_b063_hosted_build_workflow.py"): (0o644, "3dae07bc590c83f50d03c5194d8db3a71cb15a3c2eabbd68c1ef059ebcedb748"),
    Path("wrangler.toml"): (0o644, "568d0e6994ce1156542e350520a9750924a0f3f416e67af07c7275682e24c7a6"),
    Path("evidence/owner-actions/B-063/production-image-build-receipt.json"): (0o644, "6fdc47bb51354a0e7675b9f19c21864a23e89562751944386525e966e957dd27"),
}
I1648_PATHS = frozenset(I1648_PREIMAGES)
B216_PREIMAGES = {
    Path(".github/workflows/b216-receiver-deploy-nonprod.yml"): (0o644, "1d0e94cd0ba53fccc4b8aaf225a81b180192136f4bee99b8b9d6f69a7b78eeb0"),
    Path("apps/dsr-alert-receiver/scripts/deploy-route.mjs"): (0o644, "c83ac8b06826940a49faca93ef192bf5acdd44adaed3088a29b4f7df97117557"),
    Path("apps/dsr-alert-receiver/tests/deploy-route.test.mjs"): (0o644, "7f0511864d5deced20c2352ed23da7d436761f1d0a422750fb06e94feaac65d8"),
    Path("docs/internal/secrets-checklist.md"): (0o644, "6157f5653e1a4ebea7be4a11e69e04abd36f59eb5fed6fa23997bb48f18f45b8"),
}
B216_TARGETS = {
    Path(".github/workflows/b216-receiver-deploy-nonprod.yml"): (0o644, "1a3c849443f1ded6e0a8791797d906640121b753f8e5a0043b1dec78ac1c941d"),
    Path("apps/dsr-alert-receiver/scripts/deploy-route.mjs"): (0o644, "3245267227c49d3ffaa84136f5f3230d559c63d96df25eb34bf75fe773bc5f5b"),
    Path("apps/dsr-alert-receiver/tests/deploy-route.test.mjs"): (0o644, "a2ec944dbb5e9bf54ff1a7cceeb7e26b55427eda6e24b9d4c83730607e32c755"),
    Path("docs/internal/secrets-checklist.md"): (0o644, "acc1debc7f96d7b38b03743f6c905e882655dc0a370ab4b7c97d7b37b5e00196"),
}
B216_PATHS = frozenset(B216_PREIMAGES)
I2568_PREIMAGES = {
    Path('.actionlint.yaml'): (420, '8e119ec23c53aa981bbfea4d909637d76f79956bee8d7aee30f4d6cfbbc48099'),
    Path('.github/workflows/issue-2568-sla-credit-real.yml'): None,
    Path('scripts/issue_2568_sla_credit_real.py'): None,
    Path('scripts/issue_2568_sla_credit_worker.ts'): None,
    Path('scripts/verify_issue_2568_sla_credit_real.py'): None,
    Path('tests/test_issue_2568_sla_credit_real.py'): None,
    Path('docs/campaigns/remediation/wp150-workflow-ownership.md'): (420, 'd8ea8a8c5b19ca5b5fdae2ea8fd46664d9e860d47a7ddaaf318855e89fb6c210'),
    Path('docs/internal/secrets-checklist.md'): (420, 'acc1debc7f96d7b38b03743f6c905e882655dc0a370ab4b7c97d7b37b5e00196'),
}

I2568_TARGETS = {
    Path('.actionlint.yaml'): (420, '2e1ad216236818322adb7baed2e25dcc836cd7a030493fd799f4d4fc06702576'),
    Path('.github/workflows/issue-2568-sla-credit-real.yml'): (420, '67031ad29cdcbef2efa7d6385c298f3aa240440545db81e53d490b9df58ee195'),
    Path('scripts/issue_2568_sla_credit_real.py'): (420, '3a41577dec203d3fa4f18924de6af92224ca5ae35f5b2231551e25a00b8ca0d2'),
    Path('scripts/issue_2568_sla_credit_worker.ts'): (420, '4cf891a4ba1030e03db9401df4a312c75204a08bf7be774a8f634a1bc89e2d62'),
    Path('scripts/verify_issue_2568_sla_credit_real.py'): (420, 'bca4fc394e00694eb2bf95e2418a5f90005cace3c426133e862eae868d20bab4'),
    Path('tests/test_issue_2568_sla_credit_real.py'): (420, '392514070165cf8442f41c82237000831ae313c20d6a0d92d70c0b5dc0214df5'),
    Path('docs/campaigns/remediation/wp150-workflow-ownership.md'): (420, 'cb9bb10177faf2fd578e1cc23163015f8c2913e360e8f2880dcd2afc71904e15'),
    Path('docs/internal/secrets-checklist.md'): (420, '4d3cbad537f0ec07f00cdc34336f41000822c60febbf178dd9fe16a48ea52af7'),
}
I2568_PATHS = frozenset(I2568_PREIMAGES)



def _tree_matches_pins(root: Path, pins: dict[Path, tuple[int, str]]) -> bool:
    return all(is_regular_digest(root, path, digest) and root.joinpath(path).lstat().st_mode & 0o777 == mode for path, (mode, digest) in pins.items())


def preauthorized_exact_transition(candidate: Path, trusted_base: Path, changes: set[Path], paths: frozenset[Path], preimages: dict[Path, tuple[int, str] | None], targets: dict[Path, tuple[int, str]], required_base: tuple[dict[Path, tuple[int, str]], ...] = ()) -> bool:
    if not paths or changes != paths or set(preimages) != paths or set(targets) != paths:
        return False
    cumulative_base_pins: dict[Path, tuple[int, str]] = {}
    for pins in required_base:
        cumulative_base_pins.update(pins)
    if cumulative_base_pins and not _tree_matches_pins(trusted_base, cumulative_base_pins):
        return False
    for relative in paths:
        old = preimages[relative]
        new = targets[relative]
        if new is None or not is_regular_digest(candidate, relative, new[1]) or (candidate / relative).lstat().st_mode & 0o777 != new[0]:
            return False
        if old is None:
            if not is_absent(trusted_base, relative):
                return False
        elif not is_regular_digest(trusted_base, relative, old[1]) or (trusted_base / relative).lstat().st_mode & 0o777 != old[0]:
            return False
    return True

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


FUTURE_I2568_WORKFLOW = Path(".github/workflows/issue-2568-sla-credit-real.yml")


def require_future_i2568_workflow_exact(candidate: Path, trusted_base: Path) -> None:
    """Keep the future #2568 workflow absent until its complete pinned stage."""
    candidate_path = candidate / FUTURE_I2568_WORKFLOW
    base_path = trusted_base / FUTURE_I2568_WORKFLOW
    candidate_kind = node_kind(candidate_path)
    base_kind = node_kind(base_path)
    if candidate_kind == base_kind == "absent":
        return
    if candidate_kind != "regular" or base_kind != "regular":
        raise ContractError(
            f"{FUTURE_I2568_WORKFLOW}: one-sided presence, symlink, or non-file drift"
        )
    if (
        candidate_path.lstat().st_mode & 0o777 != 0o644
        or base_path.lstat().st_mode & 0o777 != 0o644
        or sha256_file(candidate, FUTURE_I2568_WORKFLOW)
        != sha256_file(trusted_base, FUTURE_I2568_WORKFLOW)
    ):
        raise ContractError(f"{FUTURE_I2568_WORKFLOW}: protected bytes or mode drift")


def require_exact(candidate: Path, trusted_base: Path, relative: Path) -> None:
    if read(candidate, relative) != read(trusted_base, relative):
        raise ContractError(f"{relative}: candidate must equal the protected base")


def preauthorized_staging_d1_proxy_tree(
    candidate: Path,
    trusted_base: Path,
    changes: set[Path],
) -> bool:
    if len(STAGING_D1_PROXY_DELIVERY_PATHS) != 37 or changes != STAGING_D1_PROXY_DELIVERY_PATHS:
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
    if set(STAGING_D1_PROXY_PREIMAGES) != STAGING_D1_PROXY_DELIVERY_PATHS:
        return False
    for relative in sorted(STAGING_D1_PROXY_DELIVERY_PATHS, key=str):
        preimage = STAGING_D1_PROXY_PREIMAGES[relative]
        if preimage is None:
            if not is_absent(trusted_base, relative):
                return False
        elif not is_regular_digest(trusted_base, relative, preimage[1]) or (trusted_base / relative).lstat().st_mode & 0o777 != preimage[0]:
            return False
        if node_kind(candidate / relative) != "regular":
            return False
        mode = (candidate / relative).lstat().st_mode & 0o777
        if mode != 0o644:
            return False
        digest = sha256_file(candidate, relative)
        if digest is None:
            return False
        rows.append(f"{(0o100000 | mode):06o} {digest} {relative}\n")
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


# Frozen four-delivery admission wave. Every path has one d2f1 preimage and
# one reviewed target (None means exact absence); modes and bytes are checked.
WAVE_GROUPS: dict[str, dict[Path, tuple[tuple[int, str] | None, tuple[int, str] | None]]]= {
    "i1652": {
        Path('.github/workflows/issue-1652-b072-evidence.yml'): ((0o0644, "7902fc5211d88c461554981f635dbbd7948ea358420facb722cd1f06c215aa43"), (0o0644, "95f1644aea80a18f5ca4aaffbf1e66c2beecf4326cad465ee55188e4dc6618f1")),
        Path('.github/workflows/synthetic-pager-worker-deploy.yml'): ((0o0644, "3ab28f10f0bdda409be1790b63b18f8c45c2290ac1f5534c872981766af2dace"), (0o0644, "3c011375a5477d05fa4211ee9aace75ab253e8c869380e45b1d724e849962c75")),
        Path('apps/synthetic-pager-worker/src/contract.ts'): ((0o0644, "fb4a25030f5ab409cd6af58e33bc7aac64f812a80b06365118d66f4af3668ee2"), (0o0644, "db25b1a27776180a63f4e52f232bd36d1d20dffc0861732cfef534c98c9439bb")),
        Path('apps/synthetic-pager-worker/src/index.ts'): ((0o0644, "d1951170489f1dc4d7d794cf993371a912c819ba4b068b1b07f494c9c763f173"), (0o0644, "e4bab682267f9409d1546b38c660be6a601a077268c1b4cb0c80f768d98cca97")),
        Path('apps/synthetic-pager-worker/tests/receiver.test.ts'): ((0o0644, "4158b83f17cd34f37357a002c54e73d5a199c86b49f95d110a82d6eeab29df56"), (0o0644, "28964c621797a4d87155c0c365badc6eacedc14abac8f30bf001727848f5d5f3")),
        Path('changelog.d/1652-b072-one-shot.md'): (None, (0o0644, "22f60747b272725bcf9d71a32a7e8899970fda47538bffcd8a8b890ca4d4d2db")),
        Path('docs/internal/b072-scheduled-drills-owner-packet.md'): ((0o0644, "27b8ada7c3c84706c82173b9092c1464952ade6419688700fcc9dd1de75ce2fd"), (0o0644, "54e33cb943bb961324c3babf2c35eed21acb93b839dbf1616dd54260b7faaa45")),
        Path('migrations/d1/0153_b072_one_shot_fence.sql'): (None, (0o0644, "8ac96c331cb5b44a9f0376ae5c257fc23a783e1fb51ec2415842101da57a67a9")),
        Path('scripts/issue_1652_b072_operator.py'): (None, (0o0644, "0fb4752246e6036e7af9fc8e62d2b9bae7764aacfc219be7148699ae0b35062c")),
        Path('scripts/test_issue_1652_b072_operator.py'): (None, (0o0644, "74678eb4b42fef3567cac2963d9462da28904964abbcf22372535ce6c6ad0828")),
        Path('scripts/test_issue_1652_b072_workflow.py'): (None, (0o0644, "40501fd987ad3994e32ab58e7fe7269ad8248a537e41d1080f820d8623bd63dc")),
        Path('worker/src/b072_one_shot.ts'): (None, (0o0644, "0083f893f91aee58f59bb3f290c95e17cba19bc22a3d06c42f0d07f166c56e4c")),
        Path('worker/src/index_schedule.ts'): ((0o0644, "cce9a2f88923fed6f7c6eddb82a6f9145767b9c77617721de2e634961dea3e3d"), (0o0644, "390a6458dbcc7bc825105dc5373b017e3044dd41085c4d775cafe6b02913cfdb")),
        Path('worker/tests/b072_one_shot.test.ts'): (None, (0o0644, "ecd19f939fca175b5b29bbb187e73e0ac05a4b582f74f491b9f14fcb4517598c")),
        Path('worker/tests/scheduled_drills.test.ts'): ((0o0644, "7ff36a7bb7bf65fe58c3013b80b397f5432d8dd8d90c87dd2443db171be1b5a5"), (0o0644, "d325b36d1bdca9f96e691a917a912033818db9b9e29ae7e56a6a1ef35ceebb90")),
        Path('scripts/verify_b072_receiver.py'): ((0o0644, "3bfa5d552f9d588c424c25a2cb7654dd840f77279cd89ff249f594c052674ecc"), (0o0644, "650a2b0ed7d999e7698182f29fa3d2e6f98a252d8e46eac215b80f34b8549d55")),
        Path('scripts/test_b072_receiver_mutations.py'): ((0o0644, "86c3f91858694327126c5db48af9f151fb5b4603d461634c12dc5ccebaf26297"), (0o0644, "761de6a4375d9dbeb74e706b3f2d32c5beb74432178b06f4fe2281d14e8e659a")),
    },
    "i1648": {
        Path('.github/workflows/cf-deploy-prod.yml'): ((0o0644, "dd3606d88be58955fb6c3853e64f355fbc44fd01e9988af1cf3e356f4e20aa64"), (0o0644, "0bd0198cfb7153acace49e9f581d4488956955fa37316b97b60d3c0ff3e92fe3")),
        Path('.github/workflows/issue-1667-b122-production-evidence.yml'): ((0o0644, "a6f95f55fed4badc7c73a44b7aa2ef53704e0e88269178179ad35a2ee0be71ae"), (0o0644, "a1dba7b9f4e65956b38aa0cb4056af13e31d824d94144aade9f106ee821e0a73")),
        Path('scripts/issue_1648_image_only.py'): (None, (0o0644, "7f39d68f7ee65fba5512ac57ab738913e008be53cacff150bfaec9a9eb6c66ca")),
        Path('tests/test_issue_1648_image_only.py'): (None, (0o0644, "9c7869d41e7170c1b503ac46637d3f26ff1070d587adb67f49b6321e97b471cd")),
    },
    "i1700": {
        Path('.github/workflows/campaign-ci.yml'): ((0o0644, "888a1e53fef4f59a883d80f493b14fe56d3ad4149c99c8b2f3bf7e4637534dff"), (0o0644, "13c6801d8e84468cd4efa60fe3ed83de033f5fa08687a5e98c71d1e87caa4a3e")),
        Path('.github/workflows/issue-1700-container-staging-deploy.yml'): ((0o0644, "04f80c37d653628799691af7a8cfc520d98adba07292f65c57f894293c07caae"), (0o0644, "93235218ce8720ce324608616301169b6a4e49bb607da11a350ad8b5f82f63d9")),
        Path('changelog.d/1700-retire-fresh-proof.md'): (None, (0o0644, "a305c6a0b21c6fcb1dca770d665030028467e2bb946acd8ddccc9f135946e437")),
        Path('crates/corelink-container/src/routes/staging_d1_binding_probe.rs'): ((0o0644, "67d8ff7749679f56a7147e49237223d39de2db65bd23523d6a5d5fdef48b6af3"), (0o0644, "a6c95b5c001ebd74a1f10542ab9e91484e4de9182208ea91b0ac36865461b626")),
        Path('crates/corelink-container/src/routes/staging_d1_probe_window.json'): ((0o0644, "a030ec8f3a3b73252ef1d6bfc18f9bc31c3f421d94950f83a71171fb846e6ca5"), (0o0644, "cd34dd5bf32638ab9dba45397494ae38dc87a57594e79dcc5aa5d948a2705824")),
        Path('docs/operator/issue-1700-runtime-recovery.md'): ((0o0644, "6cecbc1a697f997868b7ecfd5224b0c93878e2d8d02b976d5b699a43237eca3f"), (0o0644, "e9115364b59f95f345e0daeabdd7128426da26c8ef41ee3135f2e399c669abe4")),
        Path('scripts/issue_1700_rollback_quiescence.py'): (None, (0o0644, "cae820f601ddb86f048b4eda81d89968eb70d92b5da1bee6ae645cb4101170ad")),
        Path('scripts/issue_1700_runtime_probe.mjs'): ((0o0644, "9438eb081ac786fbdfb26f17a9a6d6d63601bb6893ebf83fff12fbcef0dfae35"), (0o0644, "1ed2681d5f200408eed7daea009ab9c0d341d1b240e430c238b8bf687ebbc8b1")),
        Path('scripts/tests/issue_1700_probe_process.test.mjs'): ((0o0644, "9dd57cbb0494cc76b785d56d65820627f1656eb2ae467cde5feec6b66316094b"), (0o0644, "f39f216574443ba8b1cb2a7f2eccd53c3c71f80bcb706583c156b02cfec1dff0")),
        Path('scripts/tests/issue_1700_runtime_probe.test.mjs'): ((0o0644, "0bd4acaed0860a56c98ae32c5c1d34ef18e2f9436670e8af4cdfb0c9256d5241"), (0o0644, "b93ee9785a7eb323de337f7d70a9f27fdc07f8de10e8c11d030ffccbe6ad7739")),
        Path('tests/test_issue_1700_rollback_quiescence.py'): (None, (0o0644, "27b13b705c37aed64afa5001e07f428738afa1252d15094d2b2a6d7242b4145f")),
        Path('worker/src/durable_object.ts'): ((0o0644, "ae3811c359ad59f4df9e6cb8de4f664cfb019ee141c2d44700e52f8f8cf8c9af"), (0o0644, "10a22f81b4e407c5200d217e43db83ec68620c48b8ba273eaaea41861283d22e")),
        Path('worker/src/staging_d1_probe_retirement.ts'): (None, (0o0644, "79adca4ea6d18e9c6bd9025898f72956d9a187b064b497527533df690f0c9f55")),
        Path('worker/src/staging_runtime_d1_probe.ts'): ((0o0644, "731c86a7dedaae283dd8ed0b186f1d408c85a2fd4609e6be9d29a338994f2278"), (0o0644, "cd9e32bcfee3ec79ae3d1a1ea88923f27be34413a49395f76287d598bb27acee")),
        Path('worker/tests/durable_object.test.ts'): ((0o0644, "9fb7a118318b442dd327e89bff793d67a6c07ead964d04ba97c219c1e1bf8ca5"), (0o0644, "08c2bebe46b885fcdef58cbe08d0fdba76710c21da5d2780ac8d63c49cafc206")),
        Path('worker/tests/staging_d1_probe_retirement.test.ts'): (None, (0o0644, "d2442e3fb955a6a08dd8d8d2643cfb78dfd40eabd16ec6d9d313fae16be653ab")),
        Path('worker/tests/staging_runtime_d1_probe.test.ts'): ((0o0644, "aa53d792193df3cad82fc895332ce728f0d40c77807d66c7d4f07eec04772c8c"), (0o0644, "15b4023d2445f46a18dc264a4605f4f7eda65e07239d2bf41871acd93db7bb83")),
    },
    "i2565": {
        Path('.github/workflows/issue-1650-real-integration-contract.yml'): ((0o0644, "7c474c4926c9342c025d32017ab7808a42659a991237bd8874a5a4df4b1a4be7"), (0o0644, "8787a94eaf42862be6baea6304de64a16c0bd9d13891429f18f68015d716037f")),
        Path('.github/workflows/real-ignored-harnesses.yml'): ((0o0644, "e18baf7d4983b457c398c0d8c74a464390aa6367ad491120c70f0fd3a04a8573"), (0o0644, "7e07edb842d3e0077ceab32035fbc754074bc7b95532045c3a80324428331db9")),
        Path('crates/corelink-stripe-real/src/client.rs'): ((0o0644, "21c3b70a4b6c7dfcbb548dc07dc9f6abc8bdbaf2045bae2b52622a82ebb45fea"), (0o0644, "40059a20c4cde7dcc2c5a4a6d52cd98e802ef24735bd22e060050e85f0cddccc")),
        Path('crates/corelink-stripe-real/tests/live_integration.rs'): ((0o0644, "b7d8b83fb6f736c4675d7cb4d36727464b6d9ddcc97fe3d026a1e0fe182bb587"), (0o0644, "36129c26caf3b54ac5da4fb50adfc98dae0f11cb2994dc124f298a88672259d9")),
        Path('docs/handoff/2026-09-22-i1650-real-integration-readiness.json'): ((0o0644, "d826103bdc29aad73a5345465105ab8aa63200ed0175301421f168827664536c"), (0o0644, "947e49ba07061eac1db56c389924d03928e64ba691fd5a825fca35535de07b1f")),
        Path('scripts/real-ignored-harness-manifest.json'): ((0o0644, "00e3c392584fc56b0533d40df265fb37b8785a65b20031e327481062a785b55f"), (0o0644, "c71ea89468fe06595270142646ee25ef4f853839c0115ea54fd58c4441b1740c")),
        Path('scripts/run-real-ignored-harnesses.sh'): ((0o0755, "9a3bb0d28733b0c9a6f655330a06ca57183a78787c93015f5f9cd1087bdd0287"), (0o0755, "71d05f1557d3603e2f565e4572f544fa1d284eb52f055789afa1f0aeeb387a47")),
        Path('scripts/verify_real_ignored_harnesses.py'): ((0o0644, "d2ec122fea6fcb6f7b7504ebe00dfcad32bf692c6e959141433ce59d7dc1eb6b"), (0o0644, "377bcacb98e7e936bc812babc781a1fc50e68c4da8760c0bf25910f1e16e283a")),
    },
}
WAVE_BASE_CONTROLS: dict[Path, tuple[int, str] | None] = {
    Path('.github/workflows/container-build-push-prod.yml'): (0o0644, "8ee0d29eff20ef5d473e4a712279a727fcdc6c881ba2bb46433f7659802f598f"),
    Path('.github/workflows/issue-2183-reapi-composition.yml'): (0o0644, "bb382d6898ce95fb690c62bfc50334e94889dbf371fa7a0871dd7bac5e24b431"),
    Path('.github/workflows/issue-2568-sla-credit-real.yml'): (0o0644, "1376e1b9eb4136ef1faba62abbe3e051bcf9c9df837351697e0b3048bac55390"),
    Path('.github/workflows/issue-2730-dsr-alert-receiver.yml'): (0o0644, "00ed5dab40391114b3a3a5bc299f98568e78c2dfcd14a05ccf5bac4276a6a235"),
    Path('.github/workflows/staging-quarantine-apply.yml'): (0o0644, "24d901a61e2b45af71fc5ec0632455956690725f8f05f9959c0baf213deb1594"),
    Path('Cargo.lock'): (0o0644, "e161aa27d6994badb497a9c881b99d9ee0255a4c2796b7f345e8a81c1bb9e707"),
    Path('Cargo.toml'): (0o0644, "6012612bdd15b83e906f9a870049e137a9f2b947af1dd1105ee9aa6a460bfb0a"),
    Path('Dockerfile'): (0o0644, "884f577834cfb8ef3c357afee884ac02f27c9c6031a139db04a0523fc07d5472"),
    Path('crates/corelink-container/build.rs'): (0o0644, "b7d1b11510f0bf00a21f2f83a97a43389b0d288167f6b9c5516da57ffda9ce4d"),
    Path('crates/corelink-container/proto/staging_transport_probe.proto'): (0o0644, "b243732e58ba3ced040e9181befd4f3c2bd995e0b23eb750889c93629245970c"),
    Path('crates/corelink-container/src/grpc_staging_probe.rs'): (0o0644, "bab9a3dd5fea718e4e384e2fabe9145fadf9233bd9b41522c267ea02019d8e3d"),
    Path('crates/corelink-container/src/lib.rs'): (0o0644, "01ad3ff6280beabd6dd0dea5e701315e41f7a1aba85a9dd3c7706bde0d3d7ef0"),
    Path('crates/corelink-container/src/main.rs'): (0o0644, "44c28a9a8387212b156ce05aa65918b0c34454453d7fcd85e79fd29f9a5518db"),
    Path('crates/corelink-container/src/reapi_composition.rs'): (0o0644, "57b3e2c730cf2f326b7f8bdb99df04b9423179524dc830805c3dbb8e62a5f337"),
    Path('crates/corelink-container/src/routes.rs'): (0o0644, "04a84d7be655fd25ee6d05d1b5c598c169be1aae381a255533ffeda0aad1ec2f"),
    Path('crates/corelink-container/src/storage.rs'): (0o0644, "ee16e0155fae72ddfe01fedb4b7d29bff087467b2a23c42c830a42f3aeb9b78e"),
    Path('crates/corelink-container/src/storage/d1_http.rs'): (0o0644, "258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5"),
    Path('infra/staging/README.md'): (0o0644, "5f3daac1edba6320bcfc6663d57bece16a9c63b7977156c0fc3a3b562276a435"),
    Path('infra/staging/topology.json'): (0o0644, "a55b4e72f63569b74539e9b42a8c0b34bd964f9213a5696b535fb2eb4ca24b14"),
    Path('scripts/staging_bootstrap_provider.py'): (0o0644, "8a77837893f2bd094f1fd834042361e69375e1453ec1d4dde9c20c605d00ccdb"),
    Path('scripts/verify_i2183_reapi_composition.py'): (0o0644, "532408187817e4ff508e9b2f5776e1646f7f304235ab697cf2e28fbab49a1b6c"),
    Path('scripts/verify_i2574_grpc_diagnostic_policy.py'): (0o0644, "28023901b65dd1046af666fb26c8d862a389b94cafc11e3870a2794d869a6743"),
    Path('scripts/verify_staging_provider_preflight.py'): (0o0644, "ddc9d57aa31cbee273dabc923b23a3ef33fb11b40bbd3b746ad7dcaca0633b62"),
    Path('scripts/verify_staging_topology_contract.py'): (0o0644, "48b69bc6c4852ef8218058d53105fb82c4a60d22af25739b111dc4a0def79bf9"),
    Path('specs/03_architecture/issue-2176-grpc-transport-contract.md'): (0o0644, "351aa666c129c7dbc87db4f69f476f8bcdf522d0ba35223dca7eb507c8a926b3"),
    Path('tests/test_issue_1700_route_inventory.py'): (0o0644, "a371d50bc84eafad075c9ad943cbe9ab5b90a53a4e1501d19a428d38873a5d4a"),
    Path('tests/test_staging_bootstrap_provider.py'): (0o0644, "ec4633c038fd4ae1553464e00ba2ce6dfe79e10562f79243e0fb629d1d93e219"),
    Path('tests/test_staging_custom_domain.py'): (0o0644, "cfc063496302c06c8bc879c380c7f24e13088fdf8f2a5412def3e6e60b115afc"),
    Path('tests/test_staging_quarantine_apply_contract.py'): (0o0644, "b90d143271b96038ce2f51a23bc62b3be3fee546a231f003b9bcfbfb79a497bf"),
    Path('worker/package.json'): (0o0644, "96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34"),
    Path('worker/src/durable_object_probes.ts'): (0o0644, "3b1a67b3c6883d23dfd29bd0a8cf18de9e9c3848b4e79e1d3d04539944081f78"),
    Path('worker/src/durable_object_start.ts'): (0o0644, "7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c"),
    Path('worker/src/grpc_staging_authorization.ts'): (0o0644, "6b8e2f6eb6cc42d0b0d7404950d068bab9da47c4bb1bb4c4fa0a0073c3f48400"),
    Path('worker/src/grpc_staging_transport.ts'): (0o0644, "b3c0b471790ed7fd64138d99c0976b63c4fb620b0ce588f8c9852ea2de900f72"),
    Path('worker/src/grpc_transport_gate.ts'): (0o0644, "68b14c5537100733ff467d8beb80f3cadce07f9b3b5f43339ab323e8ca1cfcfd"),
    Path('worker/src/index.ts'): (0o0644, "18b960a74833284f953bd28818cd7260798d9570c17bce459502f7b7ca50f3cd"),
    Path('worker/src/index_common.ts'): (0o0644, "dadbd05f00c855febed2266eb0ef308e2aaa80a909c4c8e463c400ed2d6bb4de"),
    Path('worker/src/index_env.ts'): (0o0644, "ae733fad5467d839b0983f5b0df306fe8ad4c7bee68822e66e1d5b4f028886cf"),
    Path('worker/src/index_env_contract.ts'): (0o0644, "ec259cf4d4f4c6bab582375b88a449c3d5a3d8d53c7680afdcb8e7728710eb9d"),
    Path('worker/src/index_fetch.ts'): (0o0644, "d8619985ea28485792198c8f0e8607c108d82af66a76c0fbfc5253f2e2c3ab07"),
    Path('worker/src/lib/devenv_cleanup_route.ts'): (0o0644, "e279cb99a585388fbf4483313a80c042df3c14bf1ca5ef52c31dc451e329907c"),
    Path('worker/src/lib/internal_auth.ts'): (0o0644, "e773fa80db1ffd97ccdd20ae08e60e662482eea7e55bef6f19a3d61644b43acf"),
    Path('worker/src/lib/runner_credential_routes.ts'): (0o0644, "6cd7af8c032dd8315c619f6830c3ef63df1a459152f197ca6a7faedf847b5731"),
    Path('worker/src/pat_issue_rate_limit.ts'): (0o0644, "ff4ca0814c40f128fed4650b2041660670bcc985037b975cb6f29b177d3c1afb"),
    Path('worker/src/staging_d1_binding_proxy.ts'): (0o0644, "1e5d940b240a4bef9daba0e360758793ab7b11a165f5b1bc8ccb7eae658a348d"),
    Path('worker/src/staging_d1_binding_proxy_entrypoint.ts'): (0o0644, "af759d84e63a2016737c899cfba045f52c1fcf20061678a3612ddeec6c18bdab"),
    Path('worker/tests/cloudflare_workers_node_stub.ts'): (0o0644, "0237103e747517298fea07261598d250e25edff6f412cd1df33695c1585cfcf7"),
    Path('worker/tests/grpc_staging_transport.test.ts'): (0o0644, "ab3748063dda62d241c4c0cfdd482261514a2b8fd8a6f427d5ef4023c7fe4f96"),
    Path('worker/tests/staging_d1_binding_proxy.test.ts'): (0o0644, "5710f974898de4c88a1ddca3f9815589d7c805faa4481f44d9005054d10796cc"),
    Path('worker/tests/staging_d1_binding_start_gate.test.ts'): (0o0644, "2377e10e46528888f60f711820a931f8358d214ac53b8c822bfac9c2d9f2da66"),
    Path('worker/tsconfig.json'): (0o0644, "98bfdb3e20a22fe1433a82c1cb04bd3522fa74445a61524a4f2a7263f01a93b3"),
    Path('worker/tsconfig.test.json'): (0o0644, "7dded910aa967755433a54655f915ba7cf35e271afce2d9f47dffa32ad6f3f79"),
    Path('worker/vitest.config.mts'): (0o0644, "e2c2f0e46d4a45d5e789f920f95b73ffd44e6a14a9450e11817426995feda506"),
    Path('worker/vitest.miniflare.config.mts'): (0o0644, "da43009c6edc93f9ca3b626e29371b84d5125de0645c10ba7f3b6bbf3751a12a"),
}
WAVE_MATRIX_SHA256 = "323917e9f4cb3c67ace170b59cd548034a7af1d17759f81ab5ccd9e300f9b8aa"
WAVE_CONTROLLED_PATHS = frozenset((
    Path("scripts/verify_i2176_grpc_deny_gate.py"),
    Path("tests/test_verify_i2176_grpc_deny_gate.py"),
    Path(".github/workflows/issue-2176-grpc-deny-gate.yml"),
    Path("docs/internal/secrets-checklist.md"),
))

def _wave_pin_matches(root: Path, relative: Path, pin: tuple[int, str] | None) -> bool:
    if pin is None:
        return is_absent(root, relative)
    return matches_pinned_file(root, relative, pin)

def _wave_state(root: Path) -> dict[str, str]:
    states: dict[str, str] = {}
    for group in WAVE_GROUPS:
        states[group] = _wave_group_state(root, group)
    return states

def _wave_controls_match(root: Path) -> bool:
    if not all(_wave_pin_matches(root, path, pin) for path, pin in WAVE_BASE_CONTROLS.items()):
        return False
    return _wave_pin_matches(root, Path("docs/internal/secrets-checklist.md"), (0o644, WAVE_MATRIX_SHA256))

def _wave_common_controls_equal(candidate: Path, trusted_base: Path) -> None:
    if not _wave_controls_match(trusted_base) or not _wave_controls_match(candidate):
        raise ContractError("actual d2f1 transport controls or P0 secrets matrix drift")
    for relative in WAVE_CONTROLLED_PATHS:
        require_regular_mode(trusted_base, relative)
        require_regular_mode(candidate, relative)
        require_exact(candidate, trusted_base, relative)
    policy = load_trusted_delivery_policy()
    frozen = {Path(path) for path in policy.POLICY | policy.POLICY_FIXTURES}
    frozen.add(B141_TEST)
    for relative in frozen:
        require_regular_mode(trusted_base, relative)
        require_regular_mode(candidate, relative)
        require_exact(candidate, trusted_base, relative)

WALLET_ROUTE_ORDINARY_PATHS = frozenset((
    Path("crates/corelink-stripe-real/src/client.rs"),
    Path("crates/corelink-stripe-real/src/client/tests_part_01.rs"),
    Path("crates/corelink-stripe-real/tests/wallet_broker_proxy.rs"),
))
WALLET_ROUTE_LIVE_PATH = Path("crates/corelink-stripe-real/tests/live_integration.rs")
WALLET_ROUTE_VERIFIER_PATH = Path("scripts/verify_real_ignored_harnesses.py")
WALLET_ROUTE_PATHS = WALLET_ROUTE_ORDINARY_PATHS | {
    WALLET_ROUTE_LIVE_PATH, WALLET_ROUTE_VERIFIER_PATH
}
WALLET_ROUTE_LITERAL = b"/_wallet/proxy"
WALLET_ROUTE_LIVE_MODULE = b"mod cleanup_fault_injection {"
WALLET_ROUTE_LIVE_END = b"\n}\n\nimpl Drop for HarnessCleanup"
WALLET_ROUTE_LIVE_LITERAL_COUNT = 11
WALLET_ROUTE_TRANSFORMED_LIVE_SHA256 = "4667e8354afb20adea5eb18afe33fcadf77bee696e3e91b1f00eefcf7e200b11"
WALLET_ROUTE_TRANSFORMED_VERIFIER_SHA256 = "294ea6c178b6713f75e3b85f4db9e4ee28c79576c20a47aeb071069f175333fa"
WALLET_ROUTE_VERIFIER_KEY = (
    b'"crates/corelink-stripe-real/tests/live_integration.rs": "'
)


def _wallet_route_expected_live(base: Path) -> tuple[bytes, bytes]:
    source = (base / WALLET_ROUTE_LIVE_PATH).read_bytes()
    source_sha = hashlib.sha256(source).hexdigest()
    if source_sha == WALLET_ROUTE_TRANSFORMED_LIVE_SHA256:
        return source, source
    live_pin = WAVE_GROUPS["i2565"][WALLET_ROUTE_LIVE_PATH][1]
    if live_pin is None or source_sha != live_pin[1]:
        raise ContractError("trusted wallet live harness is neither the frozen BASE nor exact route transform")
    if source.count(WALLET_ROUTE_LIVE_MODULE) != 1:
        raise ContractError("trusted wallet live harness module is ambiguous")
    start = source.index(WALLET_ROUTE_LIVE_MODULE)
    end = source.find(WALLET_ROUTE_LIVE_END, start)
    if end < 0:
        raise ContractError("trusted wallet live harness module boundary is missing")
    region_end = end + len(WALLET_ROUTE_LIVE_END) - len(b"\n\nimpl Drop for HarnessCleanup")
    region = source[start:region_end]
    if (
        source.count(WALLET_ROUTE_LITERAL) != WALLET_ROUTE_LIVE_LITERAL_COUNT
        or region.count(WALLET_ROUTE_LITERAL) != WALLET_ROUTE_LIVE_LITERAL_COUNT
    ):
        raise ContractError("trusted wallet live harness route literal count drift")
    transformed = source[:start] + region.replace(WALLET_ROUTE_LITERAL, b"") + source[region_end:]
    if hashlib.sha256(transformed).hexdigest() != WALLET_ROUTE_TRANSFORMED_LIVE_SHA256:
        raise ContractError("trusted wallet live transform no longer matches its frozen digest")
    return source, transformed


def _wallet_route_expected_verifier(base: Path, accepted_live: bytes) -> bytes:
    source = (base / WALLET_ROUTE_VERIFIER_PATH).read_bytes()
    if source.count(WALLET_ROUTE_VERIFIER_KEY) != 1:
        raise ContractError("trusted B068 live source pin is ambiguous")
    start = source.index(WALLET_ROUTE_VERIFIER_KEY) + len(WALLET_ROUTE_VERIFIER_KEY)
    end = start + 64
    if source[end:end + 2] != b'",':
        raise ContractError("trusted B068 live source pin is malformed")
    baseline = hashlib.sha256((base / WALLET_ROUTE_LIVE_PATH).read_bytes()).hexdigest().encode("ascii")
    if source[start:end] != baseline:
        raise ContractError("trusted B068 live source pin does not match trusted BASE")
    accepted = hashlib.sha256(accepted_live).hexdigest().encode("ascii")
    expected = source[:start] + accepted + source[end:]
    expected_sha = hashlib.sha256(expected).hexdigest()
    allowed = (
        WAVE_GROUPS["i2565"][WALLET_ROUTE_VERIFIER_PATH][1][1],
        WALLET_ROUTE_TRANSFORMED_VERIFIER_SHA256,
    )
    if expected_sha not in allowed:
        raise ContractError("trusted B068 verifier is not the frozen BASE or exact route transform")
    return expected


def _wallet_route_base_states(trusted_base: Path) -> dict[str, str]:
    """Recognize consumed #2565 on either side of the exact privileged transform."""
    states = {name: _wave_group_state(trusted_base, name) for name in WAVE_GROUPS if name != "i2565"}
    route_live, transformed_live = _wallet_route_expected_live(trusted_base)
    actual_live = (trusted_base / WALLET_ROUTE_LIVE_PATH).read_bytes()
    expected_live_pin = WAVE_GROUPS["i2565"][WALLET_ROUTE_LIVE_PATH][1]
    if actual_live not in (route_live, transformed_live):
        raise ContractError("trusted wallet live harness is outside the frozen route states")
    if expected_live_pin is not None and hashlib.sha256(actual_live).hexdigest() not in (
        expected_live_pin[1], WALLET_ROUTE_TRANSFORMED_LIVE_SHA256
    ):
        raise ContractError("trusted wallet live harness does not prove consumed #2565")
    verifier = _wallet_route_expected_verifier(trusted_base, actual_live)
    actual_verifier = (trusted_base / WALLET_ROUTE_VERIFIER_PATH).read_bytes()
    if actual_verifier != verifier:
        raise ContractError("trusted B068 verifier is not paired with its wallet live harness")
    for relative, (_old, new) in WAVE_GROUPS["i2565"].items():
        if relative in WALLET_ROUTE_PATHS or relative == Path("crates/corelink-stripe-real/src/client.rs"):
            continue
        if not _wave_pin_matches(trusted_base, relative, new):
            raise ContractError(f"trusted #2565 endpoint drift: {relative}")
    for relative in WALLET_ROUTE_PATHS:
        require_regular_mode(trusted_base, relative)
    states["i2565"] = "new"
    return states


def validate_wallet_route_candidate(
    trusted_base: Path, candidate: Path, changes: set[Path] | None = None
) -> bool:
    """Validate the one protected wallet-route transition from consumed #2565."""
    states = _wallet_route_base_states(trusted_base)
    if states.get("i2565") != "new":
        raise ContractError("wallet route requires the consumed #2565 trusted BASE")
    if changes is None:
        changes = changed_paths(trusted_base, candidate)
    if changes - WALLET_ROUTE_PATHS:
        raise ContractError(f"wallet route includes foreign paths: {sorted(map(str, changes - WALLET_ROUTE_PATHS))}")
    _wave_common_controls_equal(candidate, trusted_base)
    for name, state in states.items():
        if name == "i2565":
            continue
        if _wave_group_state(candidate, name) != state:
            raise ContractError(f"wallet route changes another delivery wave: {name}")
    for relative, (_old, new) in WAVE_GROUPS["i2565"].items():
        if relative not in WALLET_ROUTE_PATHS and not _wave_pin_matches(trusted_base, relative, new):
            raise ContractError(f"trusted #2565 endpoint drift: {relative}")
        if relative not in WALLET_ROUTE_PATHS and not _wave_pin_matches(candidate, relative, new):
            raise ContractError(f"wallet route changes a #2565 control: {relative}")
    for relative in WALLET_ROUTE_PATHS:
        require_regular_mode(trusted_base, relative)
        require_regular_mode(candidate, relative)
    base_live, target_live = _wallet_route_expected_live(trusted_base)
    actual_live = (candidate / WALLET_ROUTE_LIVE_PATH).read_bytes()
    if actual_live not in (base_live, target_live):
        raise ContractError("wallet live harness must be BASE or exact 11-literal route transform")
    if actual_live != base_live and not WALLET_ROUTE_ORDINARY_PATHS <= changes:
        raise ContractError("wallet live route transform requires all three ordinary Stripe source paths")
    expected_verifier = _wallet_route_expected_verifier(trusted_base, actual_live)
    actual_verifier = (candidate / WALLET_ROUTE_VERIFIER_PATH).read_bytes()
    if actual_verifier != expected_verifier:
        raise ContractError("B068 verifier may change only the BASE-derived live source digest")
    return True


def _wave_group_state(root: Path, group: str) -> str:
    pins = WAVE_GROUPS[group]
    old = all(_wave_pin_matches(root, path, old_pin) for path, (old_pin, _new_pin) in pins.items())
    new = all(_wave_pin_matches(root, path, new_pin) for path, (_old_pin, new_pin) in pins.items())
    if old == new:
        raise ContractError(f"unknown or partial trusted BASE delivery state: {group}")
    return "old" if old else "new"

def validate_wave(candidate: Path, trusted_base: Path, changes: set[Path]) -> bool:
    # Accept only the actual d2f1 control surface plus four complete old/new groups.
    if not _wave_controls_match(trusted_base):
        raise ContractError("trusted BASE transport controls do not match actual d2f1 snapshot")
    route_base = None
    has_route_sentinels = (trusted_base / WALLET_ROUTE_LIVE_PATH).is_file() and (
        trusted_base / WALLET_ROUTE_VERIFIER_PATH
    ).is_file()
    try:
        if has_route_sentinels:
            route_base = _wallet_route_base_states(trusted_base)
    except ContractError:
        # An exact pre-#2565 BASE continues through the original finite wave
        # classifier. Partial or drifted post-#2565 states fail closed below.
        try:
            if _wave_group_state(trusted_base, "i2565") != "old":
                raise
        except ContractError:
            raise
        route_base = None
    if route_base is not None and validate_wallet_route_candidate(trusted_base, candidate, changes):
        return True
    base = _wave_state(trusted_base)
    target = _wave_state(candidate)
    _wave_common_controls_equal(candidate, trusted_base)
    changed_groups = [name for name in WAVE_GROUPS if base[name] != target[name]]
    if not changed_groups:
        if changes:
            raise ContractError(f"wave candidate has unrelated changes: {sorted(map(str, changes))}")
        return True
    if len(changed_groups) != 1:
        raise ContractError("wave candidate changes combined delivery groups")
    group = changed_groups[0]
    if base[group] != "old" or target[group] != "new":
        raise ContractError(f"wave candidate downgrades delivery group: {group}")
    if changes != set(WAVE_GROUPS[group]):
        delta = sorted(map(str, changes ^ set(WAVE_GROUPS[group])))
        raise ContractError(f"wave candidate has partial or extra {group} paths: {delta}")
    return True


def validate(candidate: Path, trusted_base: Path) -> None:
    # Production admission is exclusively the frozen, trusted-BASE wave.
    # Legacy fixture validation remains private to self-test/unit-test setup.
    changes = changed_paths(trusted_base, candidate)
    validate_wave(candidate, trusted_base, changes)


def _validate_legacy_fixture(candidate: Path, trusted_base: Path) -> None:
    # Historical synthetic fixtures do not contain the actual trusted policy
    # module or P0 pins. This private constructor path is never used by the CLI.
    # Keep the legacy exception visibly bounded as a regression-test oracle.
    if set(MIGRATABLE_CI_PATHS) & set(LOCKED_PERIMETER_PATHS):
        raise ContractError("migratable CI paths must not bypass the locked perimeter")
    changes = changed_paths(trusted_base, candidate)
    i2575_state = i2575_base_state(trusted_base)
    if i2575_state == "partial-or-unknown":
        raise ContractError("partial or unknown #2575 trusted BASE state")
    if i2575_state == "delivered":
        if not all(matches_pinned_file(candidate, path, pin) for path, pin in I2575_TARGETS.items()):
            raise ContractError("delivered #2575 client tree was downgraded or altered")
    elif changes & I2575_DELIVERY_PATHS:
        if preauthorized_i2575_delivery(candidate, trusted_base, changes):
            # This exact seven-path transition changes no verifier, worker,
            # policy, or other path; BASE admits only the reviewed bytes/modes.
            return
        raise ContractError("partial, altered, or self-authorizing #2575 delivery")

    staging_d1_proxy_tree = preauthorized_staging_d1_proxy_tree(
        candidate, trusted_base, changes
    )
    staging_i1648_tree = preauthorized_exact_transition(candidate, trusted_base, changes, I1648_PATHS, I1648_PREIMAGES, I1648_TARGETS, (STAGING_D1_PROXY_TARGETS,))
    staging_b216_tree = preauthorized_exact_transition(candidate, trusted_base, changes, B216_PATHS, B216_PREIMAGES, B216_TARGETS, (STAGING_D1_PROXY_TARGETS, I1648_TARGETS))
    staging_i2568_tree = preauthorized_exact_transition(candidate, trusted_base, changes, I2568_PATHS, I2568_PREIMAGES, I2568_TARGETS, (STAGING_D1_PROXY_TARGETS, I1648_TARGETS, B216_TARGETS))
    for relative in LOCKED_PERIMETER_PATHS:
        if (staging_d1_proxy_tree and relative in STAGING_D1_PROXY_DELIVERY_PATHS) or (staging_i1648_tree and relative in I1648_PATHS) or (staging_i2568_tree and relative in I2568_PATHS):
            continue
        if relative == FUTURE_I2568_WORKFLOW:
            require_future_i2568_workflow_exact(candidate, trusted_base)
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
            if (staging_d1_proxy_tree and relative in STAGING_D1_PROXY_DELIVERY_PATHS) or (staging_b216_tree and relative == Path("docs/internal/secrets-checklist.md")) or (staging_i2568_tree and relative in I2568_PATHS):
                continue
            require_regular_mode(trusted_base, relative)
            require_regular_mode(candidate, relative)
            require_exact(candidate, trusted_base, relative)

    if staging_i1648_tree or staging_b216_tree or staging_i2568_tree:
        # Only the exact separately reviewed follow-on file set may move. All
        # Worker gRPC surfaces remain covered by the closed changed-path set.
        return

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
    actionlint_bytes = zlib.decompress(base64.b64decode(I2575_ACTIONLINT_PREIMAGE_ZLIB_B64))
    if hashlib.sha256(actionlint_bytes).hexdigest() != I2575_PREIMAGES[Path(".actionlint.yaml")][1]:
        raise ContractError("self-test actionlint baseline no longer matches the trusted pin")
    actionlint_path = root / ".actionlint.yaml"
    actionlint_path.parent.mkdir(parents=True, exist_ok=True)
    actionlint_path.write_bytes(actionlint_bytes)
    actionlint_path.chmod(0o644)
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
        _validate_legacy_fixture(candidate, trusted_base)
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
        _validate_legacy_fixture(candidate, trusted_base)

        # A CI-only migration does not edit the absent bootstrap gRPC surface.
        unchanged = fixture / "unchanged"
        shutil.copytree(trusted_base, unchanged, symlinks=True)
        _validate_legacy_fixture(unchanged, trusted_base)

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
        _validate_legacy_fixture(candidate, trusted_base)


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
