"""Behavioral fixtures for the B-112 release inventory and Rekor gates."""

from __future__ import annotations

import base64
import hashlib
import json
import pytest
import re
import subprocess
import sys
from pathlib import Path

from scripts.cli_release_manifest import FINAL_INVENTORY


ROOT = Path(__file__).resolve().parents[1]
REKOR = ROOT / "scripts/verify_cli_rekor_bundle.py"
INVENTORY = ROOT / "scripts/verify_cli_release_inventory.py"
B112_ROOT_CAUSE = ROOT / "scripts/verify_b112_release_root_cause.py"
BACKLOG_VERIFY = ROOT / ".github/workflows/backlog-verify.yml"
PYTHON_TESTS = ROOT / ".github/workflows/python-tests.yml"
RUSTFMT = ROOT / ".github/workflows/rustfmt.yml"
TAG = "cli-v1.2.3"
SOURCE = "0123456789abcdef0123456789abcdef01234567"
REPOSITORY = "HuGR-Labs/corelink-server"


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [sys.executable, str(script), *args], cwd=ROOT,
            text=True, capture_output=True, check=False, timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            [sys.executable, str(script), *args], 124,
            stdout=exc.stdout or "", stderr=exc.stderr or "timeout",
        )


def _b112_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Copy only the B-112 verifier population into an isolated fixture."""
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    release = workflows / "release-cli.yml"
    cosign = workflows / "cosign-sign.yml"
    backlog = tmp_path / "BACKLOG.md"
    release.write_text((ROOT / ".github/workflows/release-cli.yml").read_text(encoding="utf-8"), encoding="utf-8")
    helper = tmp_path / "scripts/cli_release_api.py"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text((ROOT / "scripts/cli_release_api.py").read_text(encoding="utf-8"), encoding="utf-8")
    # B-118 retired the former OCI lane.  Keep the path as an unwritten
    # mutation target so the B-112 verifier proves reintroduction is red.
    backlog.write_text((ROOT / "BACKLOG.md").read_text(encoding="utf-8"), encoding="utf-8")
    return release, cosign, backlog


def _run_b112_fixture(root: Path) -> subprocess.CompletedProcess[str]:
    return _run(B112_ROOT_CAUSE, "--root", str(root))


def _inject_release_run(text: str, command: str) -> str:
    """Insert a mutation into a real semantic run block, never YAML bait."""
    needle = "          cargo-zigbuild --help >/dev/null\n"
    assert needle in text
    return text.replace(needle, needle + f"          {command}\n", 1)


def test_b112_root_cause_guard_baseline_is_green():
    result = _run(B112_ROOT_CAUSE, "--root", str(ROOT))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("replacement", ["open", "done"])
def test_b112_root_cause_guard_requires_parked_status(tmp_path: Path, replacement: str):
    _release, _cosign, backlog = _b112_fixture(tmp_path)
    old = "id: B-112\nrepo: corelink-server\nowner: tl\nstatus: parked"
    new = old.replace("status: parked", f"status: {replacement}")
    assert backlog.read_text(encoding="utf-8").count(old) == 1
    backlog.write_text(backlog.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0


def test_b112_root_cause_guard_rejects_fake_done_claim_in_parked_means(tmp_path: Path):
    _release, _cosign, backlog = _b112_fixture(tmp_path)
    text = backlog.read_text(encoding="utf-8")
    match = re.search(r"(id: B-112\n.*?)(?=\n```)", text, flags=re.DOTALL)
    assert match is not None
    block = match.group(1)
    assert "verify-means: |\n  parked —" in block
    mutated = block.replace("verify-means: |\n  parked —", "verify-means: |\n  done —", 1)
    backlog.write_text(text[: match.start(1)] + mutated + text[match.end(1) :], encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("cache export", lambda text: text.replace("CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}", "CARGO_ZIGBUILD_CACHE_MUTATED=${ZIGBUILD_CACHE}", 1)),
        ("prebuilt installer", lambda text: text.replace("taiki-e/install-action@07b4745e0c39a41822af610387492e3e53aa222b", "actions/checkout@deadbeef", 1)),
        ("manual trigger", lambda text: text.replace("  workflow_dispatch:", "  # dispatch removed", 1)),
        ("draft retry classification", lambda text: text.replace(
            "--expected-state draft --allow-absent --create-or-reuse-empty-draft",
            "--expected-state draft --create-or-reuse-empty-draft",
            1,
        )),
        ("legacy create path", lambda text: text.replace("--create-or-reuse-empty-draft", "--format id", 1)),
    ],
)
def test_b112_root_cause_guard_rejects_release_mutations(tmp_path: Path, label: str, mutate):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    source = release.read_text(encoding="utf-8")
    mutated = mutate(source)
    assert mutated != source, f"{label} mutation must take effect"
    release.write_text(mutated, encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0, label


def test_b112_root_cause_guard_rejects_reintroduced_darwin_matrix_target(tmp_path: Path):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    text = release.read_text(encoding="utf-8")
    anchor = "            runner: windows-2022\n"
    assert text.count(anchor) == 1
    release.write_text(text.replace(
        anchor,
        anchor + (
            "          - triple: x86_64-apple-darwin\n"
            "            name: corelink-darwin-x86_64\n"
            "            signer_name: corelink-darwin-x86_64\n"
            "            ext: \"\"\n"
            "            runner: ubuntu-24.04\n"
        ), 1,
    ), encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0


def test_b112_root_cause_guard_rejects_cosign_and_evidence_mutations(tmp_path: Path):
    release, cosign, backlog = _b112_fixture(tmp_path)
    cosign.write_text("name: stale retired lane\n", encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0

    _release, _cosign, backlog = _b112_fixture(tmp_path / "evidence")
    backlog.write_text(backlog.read_text(encoding="utf-8").replace(
        "could not execute process rustc", "compiler invocation", 1
    ), encoding="utf-8")
    result = _run_b112_fixture(tmp_path / "evidence")
    assert result.returncode != 0


def test_b112_root_cause_guard_rejects_shared_cargo_state_mutations(tmp_path: Path):
    mutations = (
        ("cargo-home", lambda text: text.replace(
            'CARGO_HOME="${RUNNER_TEMP}/corelink-cargo/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"',
            'CARGO_HOME="$HOME/.cargo"',
            1,
        )),
        ("target-dir", lambda text: text.replace(
            'CARGO_TARGET_DIR="${RUNNER_TEMP}/corelink-target/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"',
            'CARGO_TARGET_DIR="$HOME/target"',
            1,
        )),
        ("cargo-home-echo-bait", lambda text: text.replace(
            'CARGO_HOME="${RUNNER_TEMP}/corelink-cargo/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"',
            'echo \'CARGO_HOME="$HOME/.cargo"\'',
            1,
        )),
        ("cargo-home-comment-bait", lambda text: text.replace(
            'CARGO_HOME="${RUNNER_TEMP}/corelink-cargo/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"',
            '# CARGO_HOME="$HOME/.cargo"',
            1,
        )),
        ("cargo-target-echo-bait", lambda text: text.replace(
            'CARGO_TARGET_DIR="${RUNNER_TEMP}/corelink-target/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"',
            'echo \'CARGO_TARGET_DIR="$HOME/target"\'',
            1,
        )),
        ("cargo-target-comment-bait", lambda text: text.replace(
            'CARGO_TARGET_DIR="${RUNNER_TEMP}/corelink-target/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"',
            '# CARGO_TARGET_DIR="$HOME/target"',
            1,
        )),
        ("registry-delete", lambda text: _inject_release_run(text, 'rm -rf "$HOME/.cargo"')),
        ("manual-fetch", lambda text: _inject_release_run(text, 'cargo fetch --target "${TARGET_TRIPLE}"')),
        ("artifact-path", lambda text: text.replace(
            'SRC="${CARGO_TARGET_DIR}/${TARGET_TRIPLE}/release/corelink"',
            'SRC="target/${TARGET_TRIPLE}/release/corelink"',
            1,
        )),
    )
    for index, (label, mutate) in enumerate(mutations):
        case_root = tmp_path / f"case-{index}-{label}"
        release, _cosign, _backlog = _b112_fixture(case_root)
        release.write_text(mutate(release.read_text(encoding="utf-8")), encoding="utf-8")
        result = _run_b112_fixture(case_root)
        assert result.returncode != 0, label


def test_b112_root_cause_guard_ignores_shell_comment_and_string_bait(tmp_path: Path):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    release.write_text(
        release.read_text(encoding="utf-8")
        + '\n          echo \'CARGO_HOME="$HOME/.cargo" rm -rf "$HOME/.cargo"\'\n'
        + '          # CARGO_TARGET_DIR="$HOME/target"; cargo fetch\n',
        encoding="utf-8",
    )
    result = _run_b112_fixture(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("label", "command"),
    [
        ("sudo fetch", 'sudo -n cargo fetch --target "${TARGET_TRIPLE}"'),
        ("env install", "env CARGO_NET_OFFLINE=false cargo install cargo-zigbuild"),
        ("env separator fetch", "env -- CARGO_NET_OFFLINE=false cargo fetch --locked"),
        ("nested shell fetch", "bash -lc 'cargo fetch --locked'"),
        ("dynamic shell fetch", 'bash -c "$COMMAND"'),
        ("combined rm flags", 'sudo rm -Rf -- "$HOME//./.cargo/registry"'),
    ],
)
def test_b112_root_cause_guard_rejects_wrapped_and_normalized_mutations(
    tmp_path: Path, label: str, command: str,
):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    release.write_text(_inject_release_run(release.read_text(encoding="utf-8"), command), encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0, label


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("cache order", lambda text: text.replace(
            "          cargo-zigbuild --help >/dev/null\n"
            '          ZIGBUILD_CACHE="${RUNNER_TEMP}/cargo-zigbuild/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"\n'
            '          mkdir -p "$ZIGBUILD_CACHE"\n'
            '          echo "CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}" >> "$GITHUB_ENV"\n',
            "          cargo-zigbuild --help >/dev/null\n"
            '          mkdir -p "$ZIGBUILD_CACHE"\n'
            '          echo "CARGO_ZIGBUILD_CACHE_DIR=${ZIGBUILD_CACHE}" >> "$GITHUB_ENV"\n'
            '          ZIGBUILD_CACHE="${RUNNER_TEMP}/cargo-zigbuild/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}/${TARGET_TRIPLE}"\n', 1)),
        ("Cargo export order", lambda text: text.replace(
            '          echo "CARGO_HOME=${CARGO_HOME}" >> "$GITHUB_ENV"\n',
            '', 1)),
        ("SRC consumer order", lambda text: _inject_release_run(text, 'cp "$SRC" /tmp/early-artifact')),
    ],
)
def test_b112_root_cause_guard_rejects_order_mutations(tmp_path: Path, label: str, mutate):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    release.write_text(mutate(release.read_text(encoding="utf-8")), encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0, label


def test_b112_root_cause_guard_fails_closed_on_invalid_yaml_and_unbounded_shell_input(tmp_path: Path):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    release.write_text("jobs: [", encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0

    release, _cosign, _backlog = _b112_fixture(tmp_path / "oversized")
    release.write_text("x" * 2_000_001, encoding="utf-8")
    result = _run_b112_fixture(tmp_path / "oversized")
    assert result.returncode != 0

    release, _cosign, _backlog = _b112_fixture(tmp_path / "bad-shell")
    release.write_text(
        release.read_text(encoding="utf-8").replace(
            "          set -euo pipefail\n", "          echo \"unterminated\n", 1
        ), encoding="utf-8",
    )
    result = _run_b112_fixture(tmp_path / "bad-shell")
    assert result.returncode != 0


def test_b112_root_cause_guard_rejects_unclosed_heredoc(tmp_path: Path):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    release.write_text(
        _inject_release_run(release.read_text(encoding="utf-8"), "cat <<'B112_EOF'"),
        encoding="utf-8",
    )
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("hosted runner bait", lambda text: text.replace(
            "runner: windows-2022", "runner: self-hosted", 1
        )),
        ("missing release target", lambda text: text.replace(
            '          rustup target add "${TARGET_TRIPLE}"\n', "", 1
        )),
        ("missing Windows long paths", lambda text: text.replace(
            "        run: git config --global core.longpaths true\n", "", 1
        )),
        ("invalid cargo-zigbuild version probe", lambda text: text.replace(
            "          cargo-zigbuild --help >/dev/null\n",
            "          cargo-zigbuild --version\n", 1
        )),
        ("pinned target installation order", lambda text: text.replace(
            '          bash scripts/ci-assert-pinned-toolchain.sh\n'
            '          rustup target add "${TARGET_TRIPLE}"\n'
            '          bash scripts/ci-assert-pinned-toolchain.sh "${TARGET_TRIPLE}"\n',
            '          rustup target add "${TARGET_TRIPLE}"\n'
            '          bash scripts/ci-assert-pinned-toolchain.sh\n'
            '          bash scripts/ci-assert-pinned-toolchain.sh "${TARGET_TRIPLE}"\n', 1
        )),
        ("toolchain echo bait", lambda text: text.replace(
            '          bash scripts/ci-assert-pinned-toolchain.sh\n',
            "          echo 'bash scripts/ci-assert-pinned-toolchain.sh'\n", 1
        )),
        ("zig pin echo bait", lambda text: text.replace(
            "          EXPECTED_ZIG_VERSION=0.16.0\n",
            "          echo 'EXPECTED_ZIG_VERSION=0.16.0'\n", 1
        )),
        ("tool echo bait", lambda text: text.replace(
            "          tool: cargo-zigbuild@0.19.8\n", "          tool: cargo-zigbuild@0.19.7\n", 1
        ).replace(
            "          cargo-zigbuild --help >/dev/null\n",
            "          echo 'tool: cargo-zigbuild@0.19.8'\n"
            "          cargo-zigbuild --help >/dev/null\n", 1
        )),
    ],
)
def test_b112_root_cause_guard_rejects_semantic_required_value_bait(
    tmp_path: Path, label: str, mutate,
):
    release, _cosign, _backlog = _b112_fixture(tmp_path)
    release.write_text(mutate(release.read_text(encoding="utf-8")), encoding="utf-8")
    result = _run_b112_fixture(tmp_path)
    assert result.returncode != 0, label


def _rekor_fixture(tmp_path: Path, *, root: str | None = None,
                   entries: list[dict] | None = None) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    payload = tmp_path / "provenance.intoto.jsonl"
    payload.write_bytes(b'{"statement":"fixture"}\n')
    expected = hashlib.sha256(payload.read_bytes()).hexdigest()
    body = json.dumps(
        {"spec": {"data": {"hash": {"algorithm": "sha256", "value": expected}}}},
        separators=(",", ":"),
    ).encode()
    leaf = hashlib.sha256(b"\x00" + body).hexdigest()
    proof = {
        "logIndex": 0,
        "treeSize": 1,
        "rootHash": root or leaf,
        "hashes": [],
    }
    entry = {
        "logIndex": 0,
        "logId": {"keyId": "fixture-log"},
        "integratedTime": 0,
        "canonicalizedBody": base64.b64encode(body).decode(),
        "inclusionProof": proof,
    }
    bundle = tmp_path / "provenance.intoto.jsonl.bundle"
    bundle.write_text(json.dumps({"verificationMaterial": {"tlogEntries":
                         entries if entries is not None else [entry]}}), encoding="utf-8")
    return payload, bundle


def _rekor_non_power_of_two_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """A valid RFC 6962 proof for the right edge of a three-leaf tree."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    payload = tmp_path / "provenance.intoto.jsonl"
    payload.write_bytes(b'{"statement":"fixture"}\n')
    expected = hashlib.sha256(payload.read_bytes()).hexdigest()
    body = json.dumps(
        {"spec": {"data": {"hash": {"algorithm": "sha256", "value": expected}}}},
        separators=(",", ":"),
    ).encode()

    def leaf(value: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + value).digest()

    def node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    left_subtree = node(leaf(b"left-0"), leaf(b"left-1"))
    target_leaf = leaf(body)
    root = node(left_subtree, target_leaf)
    entry = {
        "logIndex": 2,
        "logId": {"keyId": "fixture-log"},
        "integratedTime": 0,
        "canonicalizedBody": base64.b64encode(body).decode(),
        "inclusionProof": {
            "logIndex": 2,
            "treeSize": 3,
            # Exercise both accepted hash encodings in one real proof.
            "rootHash": base64.b64encode(root).decode(),
            "hashes": [left_subtree.hex()],
        },
    }
    bundle = tmp_path / "provenance.intoto.jsonl.bundle"
    bundle.write_text(json.dumps({"verificationMaterial": {"tlogEntries": [entry]}}),
                      encoding="utf-8")
    return payload, bundle


def test_rekor_verifier_accepts_zero_fields_and_valid_merkle_proof(tmp_path: Path):
    payload, bundle = _rekor_fixture(tmp_path)
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode == 0, result.stdout + result.stderr


def test_rekor_verifier_accepts_rfc6962_right_edge_and_rejects_bad_paths(tmp_path: Path):
    payload, bundle = _rekor_non_power_of_two_fixture(tmp_path)
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode == 0, result.stdout + result.stderr

    value = json.loads(bundle.read_text(encoding="utf-8"))
    proof = value["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    proof["hashes"] = []
    bundle.write_text(json.dumps(value), encoding="utf-8")
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode != 0

    payload, bundle = _rekor_non_power_of_two_fixture(tmp_path / "fake")
    value = json.loads(bundle.read_text(encoding="utf-8"))
    value["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] = "00" * 32
    bundle.write_text(json.dumps(value), encoding="utf-8")
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode != 0


def test_rekor_verifier_rejects_empty_and_fake_proofs(tmp_path: Path):
    payload, bundle = _rekor_fixture(tmp_path, entries=[])
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode != 0

    payload, bundle = _rekor_fixture(tmp_path, root="00" * 32)
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode != 0

    payload, bundle = _rekor_fixture(tmp_path)
    value = json.loads(bundle.read_text(encoding="utf-8"))
    value["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["treeSize"] = 2
    bundle.write_text(json.dumps(value), encoding="utf-8")
    result = _run(REKOR, "--payload", str(payload), "--bundle", str(bundle))
    assert result.returncode != 0


def _inventory_fixture(tmp_path: Path, *, replacement: bool = False,
                       duplicate_subject: bool = False) -> tuple[Path, Path, Path, Path, str]:
    directory = tmp_path / "assets"
    directory.mkdir()
    payload_names = FINAL_INVENTORY - {name for name in FINAL_INVENTORY if name.endswith(".sha256")} - {"checksums.txt"}
    for name in payload_names:
        (directory / name).write_bytes(name.encode())
    for name in sorted(payload_names):
        content_digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        sidecar_name = f"{name}.sha256"
        (directory / sidecar_name).write_text(f"{content_digest}  {name}\n", encoding="utf-8")
    checksum_lines = [
        (directory / sidecar).read_text(encoding="utf-8").rstrip("\n")
        for sidecar in sorted(f"{name}.sha256" for name in payload_names)
    ]
    checksums = directory / "checksums.txt"
    checksums.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    manifest = directory / "release-manifest.json"
    artifact_digests = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in FINAL_INVENTORY}
    manifest.write_text(json.dumps({"version": 2, "tag": TAG, "source_sha": SOURCE,
                                    "staging_manifest_sha256": "a" * 64,
                                    "allowed_transformations": ["replace-platform-signed-artifact", "add-linux-detached-signature-asc"],
                                    "artifacts": [{"name": name, "sha256": artifact_digests[name]} for name in sorted(FINAL_INVENTORY)]}), encoding="utf-8")
    if replacement:
        (directory / "corelink-linux-x86_64").write_bytes(b"replacement")
    actual_manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    statement = {
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": name, "digest": {"sha256": hashlib.sha256((directory / name).read_bytes()).hexdigest()}}
                    for name in sorted(FINAL_INVENTORY)],
        "predicate": {"buildDefinition": {"runDetails": {"builder": {
            "id": f"https://github.com/{REPOSITORY}/.github/workflows/release-slsa3.yml@refs/tags/{TAG}"
        }}}},
    }
    if duplicate_subject:
        duplicate = statement["subject"][0]
        statement["subject"].append({"name": duplicate["name"], "digest": dict(duplicate["digest"])})
    provenance = directory / "provenance.intoto.jsonl"
    provenance.write_text(json.dumps(statement) + "\n", encoding="utf-8")
    bundle = {
        "dsseEnvelope": {
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        },
    }
    (directory / "provenance.intoto.jsonl.bundle").write_text(
        json.dumps(bundle), encoding="utf-8"
    )
    api = tmp_path / "api.json"
    api.write_text(json.dumps({"assets": [{"name": name} for name in (
        *sorted(FINAL_INVENTORY), "release-manifest.json", "provenance.intoto.jsonl",
        "provenance.intoto.jsonl.bundle")]}), encoding="utf-8")
    return api, directory, manifest, provenance, actual_manifest_sha


def _run_inventory(tmp_path: Path, **kwargs: bool) -> subprocess.CompletedProcess[str]:
    api, directory, manifest, provenance, manifest_sha = _inventory_fixture(tmp_path, **kwargs)
    bundle = directory / "provenance.intoto.jsonl.bundle"
    return _run(
        INVENTORY, "--api-json", str(api), "--directory", str(directory),
        "--manifest", str(manifest), "--provenance", str(provenance),
        "--bundle", str(bundle),
        "--tag", TAG, "--source-sha", SOURCE, "--manifest-sha256", manifest_sha,
    )


def test_inventory_verifier_rejects_duplicate_subjects(tmp_path: Path):
    result = _run_inventory(tmp_path, duplicate_subject=True)
    assert result.returncode != 0
    assert "duplicate" in result.stdout.lower()


def test_inventory_verifier_rejects_replaced_bytes(tmp_path: Path):
    result = _run_inventory(tmp_path, replacement=True)
    assert result.returncode != 0
    assert "digest" in result.stdout.lower()


def test_inventory_verifier_rejects_false_checksum_file(tmp_path: Path):
    api, directory, manifest, provenance, manifest_sha = _inventory_fixture(tmp_path)
    (directory / "checksums.txt").write_text(
        "0" * 64 + "  corelink-linux-x86_64\n", encoding="utf-8"
    )
    result = _run(
        INVENTORY, "--api-json", str(api), "--directory", str(directory),
        "--manifest", str(manifest), "--provenance", str(provenance),
        "--bundle", str(directory / "provenance.intoto.jsonl.bundle"),
        "--tag", TAG, "--source-sha", SOURCE, "--manifest-sha256", manifest_sha,
    )
    assert result.returncode != 0
    assert "checksum" in (result.stdout + result.stderr).lower()


def test_release_chain_inputs_are_in_complete_ci_trigger_populations():
    """Every changed B-112 input selects an appropriate focused CI gate."""
    python_tests = PYTHON_TESTS.read_text(encoding="utf-8")
    backlog_verify = BACKLOG_VERIFY.read_text(encoding="utf-8")
    rustfmt = RUSTFMT.read_text(encoding="utf-8")

    # The top-level Python lane uses these intentionally broad globs for both
    # pull_request and push.  Keep the assertion tied to the source classes so
    # a future narrowing to a stale allowlist cannot silently orphan a helper or
    # its adversarial regression.
    assert python_tests.count("- 'scripts/**'") == 2
    assert python_tests.count("- 'tests/*.py'") == 2
    assert python_tests.count("- 'BACKLOG.md'") == 2
    assert python_tests.count("- '.github/workflows/release-cli.yml'") == 2
    assert python_tests.count("- '.github/workflows/cosign-sign.yml'") == 0
    for source in (
        "scripts/cli_release_manifest.py",
        "scripts/verify_cli_rekor_bundle.py",
        "scripts/verify_cli_release_inventory.py",
        "tests/test_cli_release_b112_behavior.py",
    ):
        trigger = "- 'scripts/**'" if source.startswith("scripts/") else "- 'tests/*.py'"
        assert trigger in python_tests, f"{source} is outside the Python gate"

    # The trusted backlog gate consumes every path, so release workflow
    # mutations remain covered on both PR and main push paths.
    assert backlog_verify.count('paths: ["**"]') == 2

    # The Rust structural contract is selected by the cheap formatting lane's
    # root-inclusive Rust glob (on both PR and main push paths); universal
    # Cargo test/build lanes remain intentionally out of this focused change.
    assert rustfmt.count("- '**.rs'") == 2
    assert "- '**.rs'" in rustfmt, "the Rust release contract is outside the static gate"
