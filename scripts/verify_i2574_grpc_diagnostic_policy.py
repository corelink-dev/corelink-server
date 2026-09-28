#!/usr/bin/env python3
"""Trusted-base, data-only delivery predicate for #2574.

The pull_request_target gate runs this file from protected base.  The candidate
tree is only read, never imported or executed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import tempfile
import subprocess
import re
from pathlib import Path


class ContractError(RuntimeError):
    pass


EXPECTED = {
    "specs/03_architecture/issue-2176-grpc-transport-contract.md": "351aa666c129c7dbc87db4f69f476f8bcdf522d0ba35223dca7eb507c8a926b3",
    "worker/src/grpc_transport_gate.ts": "68b14c5537100733ff467d8beb80f3cadce07f9b3b5f43339ab323e8ca1cfcfd",
    "worker/src/grpc_staging_authorization.ts": "6b8e2f6eb6cc42d0b0d7404950d068bab9da47c4bb1bb4c4fa0a0073c3f48400",
    "worker/src/grpc_staging_transport.ts": "b3c0b471790ed7fd64138d99c0976b63c4fb620b0ce588f8c9852ea2de900f72",
    "worker/src/index_fetch.ts": "d8619985ea28485792198c8f0e8607c108d82af66a76c0fbfc5253f2e2c3ab07",
    "worker/src/index_env.ts": "ae733fad5467d839b0983f5b0df306fe8ad4c7bee68822e66e1d5b4f028886cf",
    "worker/src/index_env_contract.ts": "ec259cf4d4f4c6bab582375b88a449c3d5a3d8d53c7680afdcb8e7728710eb9d",
    "worker/src/durable_object.ts": "5be00eb88931adf4b2789c15ff3e715407dcd3e67e176de370c0922b175356a7",
    "worker/src/durable_object_probes.ts": "3b1a67b3c6883d23dfd29bd0a8cf18de9e9c3848b4e79e1d3d04539944081f78",
    "worker/src/durable_object_start.ts": "26d78fadfb89ca7327f698696ec15c53c455823f3f2c1ae3c282af16b4cab244",
    "worker/tests/grpc_staging_transport.test.ts": "ab3748063dda62d241c4c0cfdd482261514a2b8fd8a6f427d5ef4023c7fe4f96",
    "worker/src/lib/internal_auth.ts": "e773fa80db1ffd97ccdd20ae08e60e662482eea7e55bef6f19a3d61644b43acf",
}
POLICY = {
    "docs/campaigns/remediation/wp150-workflow-ownership.md",
    "docs/internal/secrets-checklist.md",
    "scripts/verify_i2176_grpc_deny_gate.py",
    "tests/test_pull_request_target_spawn_boundary.py",
    "tests/test_verify_i2176_grpc_deny_gate.py",
    "scripts/verify_i2574_grpc_diagnostic_policy.py",
    "tests/test_verify_i2574_grpc_diagnostic_policy.py",
    "tests/test_i2574_p0_transition_fixture.py",
    ".github/workflows/issue-2176-grpc-deny-gate.yml",
    ".github/workflows/issue-2574-staging-grpc-diagnostic.yml",
    ".github/workflows/issue-2730-dsr-alert-receiver.yml",
}
# Exact staging transition from the frozen final #1700 mode/hash manifest.
STAGING_D1_PROXY_PREIMAGES = {
    '.github/workflows/issue-1700-container-staging-deploy.yml': (420, '9970b7ae60d825c8d5f5deaa1e82a84a58f96352312f9f8faa699621ccc38e76'),
    '.github/workflows/staging-quarantine-apply.yml': (420, '11937887c2dc88942e0c35e7b3824c9835c0f484e6ae1f0fdd8de4066a83c9da'),
    'crates/corelink-container/src/main.rs': (420, 'f1150ff53657179a26373bea5d009a732d1a9bccea8c820936858c460ae4b46c'),
    'crates/corelink-container/src/routes.rs': (420, 'd1909aefc3f99b981eebb10d018b8fdb21ce739f05c834257f7412c85d88a7ef'),
    'crates/corelink-container/src/routes/staging_d1_binding_probe.rs': None,
    'crates/corelink-container/src/storage.rs': (420, '89bd546ac229e17454dc27457e306662f8dbc3babab440c889ab2c485e9bf361'),
    'crates/corelink-container/src/storage/d1_http.rs': (420, '57df01654b44a12c57663d4543b1290125c87346e014e3b8210624a2d9cb6dd2'),
    'docs/internal/secrets-checklist.md': (420, '24d0e59ee398a92a1bfd037daf4482d619129118e6236c1bea974b76b4ef3b22'),
    'infra/staging/README.md': (420, '4689c4a43dda1d69ecbb60cdc8a65b4e2f2e5e017f5783f06f567d70ff8ab0ea'),
    'infra/staging/topology.json': (420, '586665e34c11bf91a34fb83247fdbafec9fdfb8e7a336ba4da6f5bda8266dd99'),
    'pnpm-lock.yaml': (420, 'b2b79225204fbce1b33e64f03987f0b894b1f7a187daef51078411d6285e0278'),
    'scripts/issue_1700_runtime_probe.mjs': None,
    'scripts/staging_bootstrap_provider.py': (420, '4684063fe7acbbc781ea177e029ea6d6ac7b7d4b906a814cf0c41b67eda8abf4'),
    'scripts/tests/issue_1700_runtime_probe.test.mjs': None,
    'scripts/verify_staging_provider_preflight.py': (420, '30c5e7fca9151d5a5147cc37b0ea49ced0100bd0dce5392eec4faa9e53afbfe0'),
    'scripts/verify_staging_topology_contract.py': (420, '18a70767b543a5ea8cadda94a216c068de41a8a294182ef255067126a9fa0e27'),
    'tests/test_staging_bootstrap_provider.py': (420, '189efec0ef4b61b5a5efbea105ad56c210196c4b051fc9c1119645ec3758f5f7'),
    'tests/test_staging_custom_domain.py': (420, 'ebca7d9b0e46763cac025dfc79bda65291d1e77f2132176527f28c9f8238e3a2'),
    'tests/test_staging_quarantine_apply_contract.py': (420, 'ceb689591b8a5e380ce34f91bc598262c8f9051aaa84b7e0d05c088f194dffe6'),
    'worker/package.json': (420, '7b20dc56684526ad90f3b5998aa995f41b750e304397714ab34b6ece2e162348'),
    'worker/src/durable_object.ts': (420, '5be00eb88931adf4b2789c15ff3e715407dcd3e67e176de370c0922b175356a7'),
    'worker/src/durable_object_start.ts': (420, '26d78fadfb89ca7327f698696ec15c53c455823f3f2c1ae3c282af16b4cab244'),
    'worker/src/index.ts': (420, '627c97d894c9d02521e279b1721a9b0a4346ab1050a586706321b94931fbee8c'),
    'worker/src/index_schedule.ts': (420, '1dab69b8d54f53129631f2135a23ade52fa2772c384e785f4e356c035e4888da'),
    'worker/src/staging_d1_binding_proxy.ts': None,
    'worker/src/staging_d1_binding_proxy_entrypoint.ts': None,
    'worker/src/staging_runtime_d1_probe.ts': None,
    'worker/tests/cloudflare_workers_node_stub.ts': None,
    'worker/tests/durable_object.test.ts': (420, 'ae533b3614615a5ca908922af6082f8e504986947f4db22d52b6dbe65018a669'),
    'worker/tests/staging_d1_binding_proxy.test.ts': None,
    'worker/tests/staging_d1_binding_start_gate.test.ts': None,
    'worker/tests/staging_runtime_d1_probe.test.ts': None,
    'worker/vitest.config.mts': (420, '0ee4c1a03685a300e6ead7720901ab0ae9103da8ffb359a34c5b10e7d3e46a44'),
}
STAGING_D1_PROXY_TARGETS = {
    '.github/workflows/issue-1700-container-staging-deploy.yml': (420, 'c31908be992a6727e124e9b87160708af44fa2f1a042be2bd142b930abf15199'),
    '.github/workflows/staging-quarantine-apply.yml': (420, '24d901a61e2b45af71fc5ec0632455956690725f8f05f9959c0baf213deb1594'),
    'crates/corelink-container/src/main.rs': (420, '44c28a9a8387212b156ce05aa65918b0c34454453d7fcd85e79fd29f9a5518db'),
    'crates/corelink-container/src/routes.rs': (420, '5d0db886c9e8fc5c087e041f84b0c9f92c0de1a94079fccef84c990d8274a99d'),
    'crates/corelink-container/src/routes/staging_d1_binding_probe.rs': (420, 'efe92ead9f103c8ee2e60a343c17fc828c291bc3f4bbc5130c00b38f4c50adc1'),
    'crates/corelink-container/src/storage.rs': (420, 'ee16e0155fae72ddfe01fedb4b7d29bff087467b2a23c42c830a42f3aeb9b78e'),
    'crates/corelink-container/src/storage/d1_http.rs': (420, '258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5'),
    'docs/internal/secrets-checklist.md': (420, '6157f5653e1a4ebea7be4a11e69e04abd36f59eb5fed6fa23997bb48f18f45b8'),
    'infra/staging/README.md': (420, '5f3daac1edba6320bcfc6663d57bece16a9c63b7977156c0fc3a3b562276a435'),
    'infra/staging/topology.json': (420, 'a55b4e72f63569b74539e9b42a8c0b34bd964f9213a5696b535fb2eb4ca24b14'),
    'pnpm-lock.yaml': (420, '7d8509a802bad9c700070722a8e834c98aef18c925768fb9c763a90a5a10c6cc'),
    'scripts/issue_1700_runtime_probe.mjs': (420, '814381b0a7854d24e65cb1aa9881c1f6753fa57b4e61d1e870f858adedd0fb78'),
    'scripts/staging_bootstrap_provider.py': (420, '8a77837893f2bd094f1fd834042361e69375e1453ec1d4dde9c20c605d00ccdb'),
    'scripts/tests/issue_1700_runtime_probe.test.mjs': (420, '48e3b316bd716f112e682636a8e9dd3f3f759aedf8809e6d7535c40b966187ab'),
    'scripts/verify_staging_provider_preflight.py': (420, 'ddc9d57aa31cbee273dabc923b23a3ef33fb11b40bbd3b746ad7dcaca0633b62'),
    'scripts/verify_staging_topology_contract.py': (420, '48b69bc6c4852ef8218058d53105fb82c4a60d22af25739b111dc4a0def79bf9'),
    'tests/test_staging_bootstrap_provider.py': (420, 'ec4633c038fd4ae1553464e00ba2ce6dfe79e10562f79243e0fb629d1d93e219'),
    'tests/test_staging_custom_domain.py': (420, 'cfc063496302c06c8bc879c380c7f24e13088fdf8f2a5412def3e6e60b115afc'),
    'tests/test_staging_quarantine_apply_contract.py': (420, 'b90d143271b96038ce2f51a23bc62b3be3fee546a231f003b9bcfbfb79a497bf'),
    'worker/package.json': (420, '96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34'),
    'worker/src/durable_object.ts': (420, 'f2185d824862738ed428b92fb914b1a47e79c2b1ee3a0cc679d0d90d14214105'),
    'worker/src/durable_object_start.ts': (420, '7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c'),
    'worker/src/index.ts': (420, '18b960a74833284f953bd28818cd7260798d9570c17bce459502f7b7ca50f3cd'),
    'worker/src/index_schedule.ts': (420, 'ea754a50aaa088694167f45b0b8c53fc43641c250d54ac1de35743ae8f46bdc1'),
    'worker/src/staging_d1_binding_proxy.ts': (420, '01e5ac58773118bae44c9d11ff2b3cdd0ba376579f43317af8b4fd2138b7a92d'),
    'worker/src/staging_d1_binding_proxy_entrypoint.ts': (420, 'af759d84e63a2016737c899cfba045f52c1fcf20061678a3612ddeec6c18bdab'),
    'worker/src/staging_runtime_d1_probe.ts': (420, '3758098dd2419314fd006fdb8478f5b5043b1b80dd6679a31e2043323355f132'),
    'worker/tests/cloudflare_workers_node_stub.ts': (420, '0237103e747517298fea07261598d250e25edff6f412cd1df33695c1585cfcf7'),
    'worker/tests/durable_object.test.ts': (420, '53f07e0929c957a4e804e2f9063e01359e382fea74b7c0322c2a41f47bbd16a2'),
    'worker/tests/staging_d1_binding_proxy.test.ts': (420, '6eb924bbe1aff66f9d223adb9c490c1500a6a9dfa3a3160182ffda45c72f4e78'),
    'worker/tests/staging_d1_binding_start_gate.test.ts': (420, '2377e10e46528888f60f711820a931f8358d214ac53b8c822bfac9c2d9f2da66'),
    'worker/tests/staging_runtime_d1_probe.test.ts': (420, '8277e7d58e32feaa8514c972f155d9dafaafe1788364a10bb5290a9c9ce2241b'),
    'worker/vitest.config.mts': (420, 'e2c2f0e46d4a45d5e789f920f95b73ffd44e6a14a9450e11817426995feda506'),
}
STAGING_D1_PROXY_MANIFEST_SHA256 = "4c29964fb1b46800a4dd281aebd97670d664e5bced4cf68c5ac5e9887cbae43c"


def exact_staging_d1_proxy_transition(base: Path, candidate: Path) -> bool:
    paths = set(STAGING_D1_PROXY_TARGETS)
    if len(paths) != 33 or set(STAGING_D1_PROXY_PREIMAGES) != paths:
        return False
    before, after = files(base), files(candidate)
    differences = {name for name in before | after if not (base / name).exists() or not (candidate / name).exists() or digest(base / name) != digest(candidate / name) or stat.S_IMODE((base / name).lstat().st_mode) != stat.S_IMODE((candidate / name).lstat().st_mode)}
    if differences != paths:
        return False
    manifest_rows = []
    for name in sorted(paths):
        old, target = STAGING_D1_PROXY_PREIMAGES[name], STAGING_D1_PROXY_TARGETS[name]
        old_path, new_path = base / name, candidate / name
        if old is None:
            if old_path.exists(): return False
        elif not old_path.is_file() or stat.S_IMODE(old_path.lstat().st_mode) != old[0] or digest(old_path) != old[1]: return False
        if not new_path.is_file() or stat.S_IMODE(new_path.lstat().st_mode) != target[0] or digest(new_path) != target[1]: return False
        manifest_rows.append(f"{(0o100000 | target[0]):06o} {target[1]} {name}\n")
    return hashlib.sha256("".join(manifest_rows).encode()).hexdigest() == STAGING_D1_PROXY_MANIFEST_SHA256


POLICY_FIXTURES = {
    "tests/fixtures/i2574_old_base_bytes/specs/03_architecture/issue-2176-grpc-transport-contract.md",
    "tests/fixtures/i2574_old_base_bytes/worker/src/grpc_transport_gate.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/index_fetch.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/index_env.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/index_env_contract.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/durable_object.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/durable_object_probes.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/durable_object_start.ts",
    "tests/fixtures/i2574_old_base_bytes/worker/src/lib/internal_auth.ts",
    "tests/fixtures/i2574_old_base_bytes/scripts/verify_i2176_grpc_deny_gate.py",
    "tests/fixtures/i2574_old_base_bytes/.github/workflows/issue-2176-grpc-deny-gate.yml",
    "tests/fixtures/i2574_delivery_bytes/specs/03_architecture/issue-2176-grpc-transport-contract.md",
    "tests/fixtures/i2574_delivery_bytes/worker/src/grpc_transport_gate.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/grpc_staging_authorization.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/grpc_staging_transport.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/index_fetch.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/index_env.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/index_env_contract.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/durable_object.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/durable_object_probes.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/src/durable_object_start.ts",
    "tests/fixtures/i2574_delivery_bytes/worker/tests/grpc_staging_transport.test.ts",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(root: Path) -> set[str]:
    return {
        str(p.relative_to(root)) for p in root.rglob("*")
        if stat.S_ISREG(p.lstat().st_mode) and ".git" not in p.parts
    }


def require_regular_tree(root: Path, trusted_base: Path | None = None) -> None:
    for path in root.rglob("*"):
        if ".git" in path.parts:
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            relative = path.relative_to(root)
            base_path = trusted_base / relative if trusted_base is not None else None
            if base_path is None:
                continue
            if not base_path.is_symlink() or os.readlink(base_path) != os.readlink(path):
                raise ContractError(f"symlink forbidden: {relative}")
            continue
        if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
            raise ContractError(f"non-regular path forbidden: {path.relative_to(root)}")


def require_tree_union(base: Path, candidate: Path) -> None:
    names = {p.relative_to(base) for p in base.rglob("*")} | {p.relative_to(candidate) for p in candidate.rglob("*")}
    for relative in names:
        if ".git" in relative.parts:
            continue
        left, right = base / relative, candidate / relative
        if left.is_symlink() or right.is_symlink():
            if not left.is_symlink() or not right.is_symlink() or os.readlink(left) != os.readlink(right):
                raise ContractError(f"symlink changed: {relative}")
            if str(relative) != ".github/actionlint.yaml" or os.readlink(left) != "../.actionlint.yaml":
                raise ContractError(f"symlink forbidden: {relative}")
        elif left.exists() and right.exists() and stat.S_IMODE(left.lstat().st_mode) != stat.S_IMODE(right.lstat().st_mode):
            raise ContractError(f"mode changed: {relative}")
    canonical = base / ".github/actionlint.yaml"
    candidate_canonical = candidate / ".github/actionlint.yaml"
    if not canonical.is_symlink() or not candidate_canonical.is_symlink() or os.readlink(canonical) != "../.actionlint.yaml" or os.readlink(candidate_canonical) != "../.actionlint.yaml":
        raise ContractError("canonical actionlint symlink missing or changed")


def require_pinned_modes(root: Path, paths: set[str]) -> None:
    for name in paths:
        path = root / name
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError as error:
            raise ContractError(f"missing pinned path: {name}") from error
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o644:
            raise ContractError(f"unexpected pinned mode: {name}")


def changed(base: Path, candidate: Path) -> set[str]:
    names = files(base) | files(candidate)
    return {name for name in names if not (base / name).exists() or not (candidate / name).exists() or digest(base / name) != digest(candidate / name)}


def validate(base: Path, candidate: Path) -> None:
    require_regular_tree(base)
    require_regular_tree(candidate, base)
    require_tree_union(base, candidate)
    require_pinned_modes(base, POLICY | POLICY_FIXTURES)
    require_pinned_modes(candidate, set(EXPECTED) | POLICY | POLICY_FIXTURES)
    differences = changed(base, candidate)
    native_transition = exact_staging_d1_proxy_transition(base, candidate)
    allowed = set(EXPECTED) - {"worker/src/lib/internal_auth.ts"}
    if differences - allowed and not (native_transition and differences == set(STAGING_D1_PROXY_TARGETS)):
        raise ContractError(f"closed-world violation: {sorted(differences - allowed)}")
    for name in POLICY | POLICY_FIXTURES:
        if name == "docs/internal/secrets-checklist.md" and native_transition:
            continue
        if (base / name).read_bytes() != (candidate / name).read_bytes():
            raise ContractError(f"policy self-alteration: {name}")
    for name, expected in EXPECTED.items():
        target = candidate / name
        if native_transition and name in {"worker/src/durable_object.ts", "worker/src/durable_object_start.ts"}:
            expected = STAGING_D1_PROXY_TARGETS[name][1]
        if not target.is_file() or digest(target) != expected:
            raise ContractError(f"unexpected bytes: {name}")


def self_test() -> None:
    global EXPECTED
    with tempfile.TemporaryDirectory() as tmp:
        base, candidate = Path(tmp) / "base", Path(tmp) / "candidate"
        for name, value in EXPECTED.items():
            p = base / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"base")
            p = candidate / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"base")
        for name in POLICY | POLICY_FIXTURES:
            p = base / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("protected")
            p = candidate / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("protected")
        (base / ".github").mkdir(exist_ok=True); (candidate / ".github").mkdir(exist_ok=True)
        os.symlink("../.actionlint.yaml", base / ".github/actionlint.yaml")
        os.symlink("../.actionlint.yaml", candidate / ".github/actionlint.yaml")
        # Install exact expected bytes by replacing the predicate for this fixture.
        original = EXPECTED
        EXPECTED = {name: digest(candidate / name) for name in original}
        validate(base, candidate)
        for name in ("worker/src/grpc_transport_gate.ts", "scripts/verify_i2574_grpc_diagnostic_policy.py", ".github/workflows/issue-2574-staging-grpc-diagnostic.yml"):
            p = candidate / name; p.write_bytes(p.read_bytes() + b"x")
            try: validate(base, candidate)
            except ContractError: pass
            else: raise ContractError(f"mutation escaped: {name}")
            p.write_bytes(p.read_bytes()[:-1])
        unexpected = candidate / "worker/src/alternate.ts"; unexpected.write_text("escape")
        try: validate(base, candidate)
        except ContractError: pass
        else: raise ContractError("added path escaped")
        EXPECTED = original


RECEIVER_ALLOWED = re.compile(r"^(apps/dsr-alert-receiver/|\.github/workflows/(issue-2730-dsr-alert-receiver|b216-receiver-deploy-nonprod)\.yml$|docs/campaigns/remediation/wp150-workflow-ownership\.md$|docs/internal/secrets-checklist\.md$)")
RECEIVER_OWNED = re.compile(r"^(apps/dsr-alert-receiver/|\.github/workflows/b216-receiver-deploy-nonprod\.yml$)")
PRIVACY_MARKERS = re.compile(r"console\.(?:log|error|warn)|DSR_DLQ_ALERT_AUTH_TOKEN|tenant_id|subject_id|raw body", re.IGNORECASE)


def validate_receiver_path_boundary(changed_paths: set[str], repository: Path) -> None:
    if any(RECEIVER_OWNED.search(path) for path in changed_paths):
        foreign = sorted(path for path in changed_paths if not RECEIVER_ALLOWED.search(path))
        if foreign:
            raise ContractError(f"receiver change includes foreign paths: {foreign}")
    source = repository / "apps/dsr-alert-receiver/src"
    for path in source.rglob("*") if source.exists() else ():
        if path.is_file() and PRIVACY_MARKERS.search(path.read_text(encoding="utf-8")):
            raise ContractError("receiver source contains a forbidden privacy/debug marker")


def check_receiver_path_boundary(repository: Path, base_sha: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(repository), "diff", "--name-only", f"{base_sha}...HEAD"],
        check=True, capture_output=True, text=True,
    )
    validate_receiver_path_boundary(set(result.stdout.splitlines()), repository)


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--trusted-base", type=Path); parser.add_argument("--candidate", type=Path); parser.add_argument("--self-test", action="store_true"); parser.add_argument("--check-receiver-path-boundary", action="store_true"); parser.add_argument("--base-sha")
    args = parser.parse_args()
    try:
        if args.self_test: self_test()
        elif args.check_receiver_path_boundary and args.base_sha: check_receiver_path_boundary(Path.cwd(), args.base_sha)
        elif args.trusted_base and args.candidate: validate(args.trusted_base, args.candidate)
        else: raise ContractError("pass --self-test, --check-receiver-path-boundary with --base-sha, or both trees")
    except ContractError as exc:
        print(f"issue-2574 trusted policy: FAIL: {exc}"); return 1
    print("issue-2574 trusted policy: PASS"); return 0


if __name__ == "__main__": raise SystemExit(main())
