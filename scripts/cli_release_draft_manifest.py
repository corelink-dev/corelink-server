#!/usr/bin/env python3
"""Create and verify the typed #2572 draft-only CLI release inventory.

This schema is intentionally separate from the production signed-release
manifest. It binds exact final bytes while declaring Windows Authenticode as
unsigned/deferred; the production inventory verifier rejects this version.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from .cli_release_manifest import (
        BASE_PAYLOADS,
        FINAL_INVENTORY,
        LINUX_PAYLOADS,
        SHA,
        SHA256,
        STAGING_INVENTORY,
        TAG,
        WINDOWS_PAYLOADS,
        digest,
        load as load_staging,
        safe_name,
    )
except ImportError:  # script execution from `python3 scripts/...`
    from cli_release_manifest import (
        BASE_PAYLOADS,
        FINAL_INVENTORY,
        LINUX_PAYLOADS,
        SHA,
        SHA256,
        STAGING_INVENTORY,
        TAG,
        WINDOWS_PAYLOADS,
        digest,
        load as load_staging,
        safe_name,
    )

DRAFT_VERSION = 3
DRAFT_MODE = "draft-only"
WINDOWS_STATUS = "unsigned-deferred"
SIGNATURE_POLICY = ["linux-gpg-detached", "windows-unsigned-deferred"]
METADATA_ASSETS = {"release-manifest.json", "provenance.intoto.jsonl", "provenance.intoto.jsonl.bundle"}
EXPECTED_GPG_FINGERPRINT = "795253CEBD6D54C862CFC4A3EC0AD89A75EC6756"
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")


def _canonical_checksum_map(directory: Path, artifacts: dict[str, str]) -> None:
    checksummed = sorted(
        name for name in artifacts
        if name in LINUX_PAYLOADS | WINDOWS_PAYLOADS
        or name in {f"{payload}.asc" for payload in LINUX_PAYLOADS}
    )
    sidecars = {f"{name}.sha256" for name in checksummed}
    actual_sidecars = {name for name in artifacts if name.endswith(".sha256") and name != "checksums.txt"}
    if sidecars != actual_sidecars:
        raise ValueError("draft inventory has a non-canonical sidecar set")
    expected_lines: list[str] = []
    for name in checksummed:
        sidecar = f"{name}.sha256"
        text = (directory / sidecar).read_text(encoding="utf-8")
        lines = text.splitlines()
        match = CHECKSUM_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
        if match is None or match.group(2) != name or match.group(1) != artifacts[name]:
            raise ValueError(f"draft checksum sidecar does not bind final bytes: {sidecar}")
        expected_lines.append(f"{match.group(1)}  {name}")
    checksum_text = (directory / "checksums.txt").read_text(encoding="utf-8")
    if checksum_text != "\n".join(expected_lines) + "\n":
        raise ValueError("draft checksums.txt is not the canonical closed-world index")


def write_checksums(directory: Path) -> None:
    """Write asset-name order; fully hash-check local subjects.

    Signer jobs carry only their two local packages while preserving other
    architecture sidecars, so absent remote payload bytes are checked later by
    the complete downloaded final-inventory verifier.
    """
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("checksum directory is missing, non-directory, or a symlink")
    signatures = {f"{name}.asc" for name in LINUX_PAYLOADS}
    allowed_payloads = BASE_PAYLOADS | signatures
    sidecars = [path for path in directory.glob("*.sha256")]
    if not sidecars:
        raise ValueError("checksum directory has no sidecars")
    rows: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    for sidecar in sidecars:
        if sidecar.is_symlink() or not sidecar.is_file():
            raise ValueError(f"checksum sidecar is not a regular file: {sidecar.name}")
        name = sidecar.name[:-len(".sha256")]
        if name not in allowed_payloads or name in seen_names:
            raise ValueError(f"checksum sidecar has an unexpected or duplicate subject: {sidecar.name}")
        payload = directory / name
        if payload.is_symlink() or (payload.exists() and not payload.is_file()):
            raise ValueError(f"checksum subject is not a regular file: {name}")
        lines = sidecar.read_text(encoding="utf-8").splitlines()
        match = CHECKSUM_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
        if match is None or match.group(2) != name:
            raise ValueError(f"checksum sidecar does not name its exact subject: {sidecar.name}")
        if payload.is_file() and match.group(1) != digest(payload):
            raise ValueError(f"checksum sidecar does not bind local payload bytes: {sidecar.name}")
        seen_names.add(name)
        rows.append((name, lines[0]))
    if not BASE_PAYLOADS.issubset(seen_names):
        raise ValueError("checksum index is missing one or more base release payloads")
    actual_signatures = {path.name for path in directory.iterdir() if path.name in signatures}
    if not actual_signatures.issubset(seen_names):
        raise ValueError("checksum directory has an unindexed local Linux signature")
    checksum_path = directory / "checksums.txt"
    if checksum_path.is_symlink():
        raise ValueError("checksums.txt must not be a symlink")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", dir=directory, prefix=".checksums-", delete=False
        ) as temporary:
            temporary.write("\n".join(line for _, line in sorted(rows)) + "\n")
            temporary_path = Path(temporary.name)
        temporary_path.replace(checksum_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def create(directory: Path, output: Path, tag: str, source_sha: str, staging_manifest: Path) -> None:
    if not TAG.fullmatch(tag) or not SHA.fullmatch(source_sha):
        raise ValueError("tag/source SHA are not canonical")
    staged = {item["name"]: item["sha256"] for item in load_staging(staging_manifest, tag, source_sha)}
    if set(staged) != STAGING_INVENTORY:
        raise ValueError("draft parent is not the complete staged Linux + Windows inventory")
    parent_sha = digest(staging_manifest)
    ignored = {output.name, staging_manifest.name}
    files = []
    for path in sorted(directory.iterdir()):
        if path.name in ignored:
            continue
        if path.is_symlink() or not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            raise ValueError(f"draft inventory contains a non-regular or symlink entry: {path.name!r}")
        files.append(path)
    artifacts = {safe_name(path.name): digest(path) for path in files}
    if set(artifacts) != FINAL_INVENTORY:
        raise ValueError("draft final inventory is not the complete Linux + Windows set")
    # Windows stays byte-for-byte identical to the staged unsigned payloads.
    # Linux signer output may replace only the four Linux payload bytes, add
    # their four detached signatures and sidecars, and refresh checksums.
    for name in WINDOWS_PAYLOADS | {f"{name}.sha256" for name in WINDOWS_PAYLOADS}:
        if artifacts.get(name) != staged.get(name):
            raise ValueError(f"draft changed a Windows artifact outside Authenticode scope: {name}")
    allowed_changes = LINUX_PAYLOADS | {f"{name}.sha256" for name in LINUX_PAYLOADS} | {
        f"{name}.asc" for name in LINUX_PAYLOADS
    } | {f"{name}.asc.sha256" for name in LINUX_PAYLOADS} | {"checksums.txt"}
    for name, old_digest in staged.items():
        if artifacts.get(name) != old_digest and name not in allowed_changes:
            raise ValueError(f"draft changed staged bytes outside the Linux signature allowlist: {name}")
    _canonical_checksum_map(directory, artifacts)
    value = {
        "version": DRAFT_VERSION,
        "mode": DRAFT_MODE,
        "tag": tag,
        "source_sha": source_sha,
        "staging_manifest_sha256": parent_sha,
        "allowed_transformations": ["replace-linux-signed-artifact", "add-linux-detached-signature-asc"],
        "windows_signature_status": WINDOWS_STATUS,
        "artifacts": [{"name": name, "sha256": artifacts[name]} for name in sorted(artifacts)],
    }
    output.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def load_manifest(path: Path, tag: str, source_sha: str) -> dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid draft manifest: {error}") from error
    expected = {
        "version", "mode", "tag", "source_sha", "staging_manifest_sha256",
        "allowed_transformations", "windows_signature_status", "artifacts",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("draft manifest schema is not canonical")
    if (value["version"] != DRAFT_VERSION or value["mode"] != DRAFT_MODE
            or value["tag"] != tag or value["source_sha"] != source_sha):
        raise ValueError("draft manifest identity/mode does not match typed caller inputs")
    if (not isinstance(value["staging_manifest_sha256"], str)
            or not SHA256.fullmatch(value["staging_manifest_sha256"])
            or value["allowed_transformations"] != ["replace-linux-signed-artifact", "add-linux-detached-signature-asc"]
            or value["windows_signature_status"] != WINDOWS_STATUS):
        raise ValueError("draft transformation or Windows signature policy is invalid")
    entries = value["artifacts"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("draft manifest artifact list is invalid")
    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "sha256"}:
            raise ValueError("draft manifest artifact shape is invalid")
        name = safe_name(entry["name"])
        sha256 = entry["sha256"]
        if name in result or not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            raise ValueError("draft manifest contains a duplicate name or invalid digest")
        result[name] = sha256
    if set(result) != FINAL_INVENTORY:
        raise ValueError("draft manifest inventory is not the complete Linux + Windows set")
    return result


def _gpg_verify(directory: Path, artifacts: dict[str, str], public_key: Path,
                expected_fingerprint: str = EXPECTED_GPG_FINGERPRINT) -> None:
    if public_key.is_symlink() or not public_key.is_file():
        raise ValueError("release public key is missing or not a regular file")
    with tempfile.TemporaryDirectory(prefix="corelink-draft-gpg-") as temp:
        home = Path(temp) / "gnupg"
        home.mkdir(mode=0o700)
        imported = subprocess.run(
            ["gpg", "--batch", "--homedir", str(home), "--import", str(public_key)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if imported.returncode:
            raise ValueError("release public key import failed")
        for name in sorted(LINUX_PAYLOADS):
            signature = directory / f"{name}.asc"
            payload = directory / name
            if artifacts.get(name) != digest(payload) or artifacts.get(signature.name) != digest(signature):
                raise ValueError(f"draft Linux signature subject is not in the final inventory: {name}")
            checked = subprocess.run(
                ["gpg", "--batch", "--homedir", str(home), "--status-fd", "1", "--verify", str(signature), str(payload)],
                capture_output=True, text=True, check=False, timeout=30,
            )
            valid = re.findall(r"(?m)^\[GNUPG:\] VALIDSIG ([0-9A-F]{40,64})(?:\s|$)", checked.stdout)
            if checked.returncode or len(valid) != 1 or valid[0] != expected_fingerprint:
                raise ValueError(f"draft Linux signature is invalid or has the wrong fingerprint: {name}")


def _slsa_subjects(provenance: Path, bundle_path: Path) -> dict[str, str]:
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        payload = base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True)
        statement = json.loads(payload)
        published = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("draft provenance is not a DSSE bundle and statement") from error
    if statement != published or not isinstance(statement, dict):
        raise ValueError("draft provenance differs from the signed DSSE payload")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ValueError("draft provenance is not SLSA v1")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("draft provenance subjects are invalid")
    result: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, dict) or set(subject) != {"name", "digest"}:
            raise ValueError("draft provenance subject schema is invalid")
        name = safe_name(subject["name"])
        digest_value = subject["digest"]
        if (name in result or not isinstance(digest_value, dict) or set(digest_value) != {"sha256"}
                or not isinstance(digest_value["sha256"], str) or not SHA256.fullmatch(digest_value["sha256"])):
            raise ValueError("draft provenance has a duplicate subject or invalid digest")
        result[name] = digest_value["sha256"]
    return result


def verify_manifest(directory: Path, manifest: Path, public_key: Path, tag: str,
                    source_sha: str, manifest_sha256: str, *, include_provenance: bool = False,
                    expected_gpg_fingerprint: str = EXPECTED_GPG_FINGERPRINT) -> dict[str, str]:
    if not TAG.fullmatch(tag) or not SHA.fullmatch(source_sha) or not SHA256.fullmatch(manifest_sha256):
        raise ValueError("draft tag/source/manifest digest are not canonical")
    expected = load_manifest(manifest, tag, source_sha)
    if digest(manifest) != manifest_sha256:
        raise ValueError("draft manifest differs from final-manifest output digest")
    actual = {name: digest(directory / name) for name in expected}
    if actual != expected:
        raise ValueError("draft bytes differ from the typed final manifest")
    expected_names = set(expected) | {manifest.name}
    if include_provenance:
        expected_names |= {"provenance.intoto.jsonl", "provenance.intoto.jsonl.bundle"}
    if {path.name for path in directory.iterdir()} != expected_names:
        raise ValueError("draft directory inventory is not closed-world")
    _canonical_checksum_map(directory, expected)
    _gpg_verify(directory, expected, public_key, expected_gpg_fingerprint)
    return expected


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    checksums_parser = commands.add_parser("write-checksums")
    checksums_parser.add_argument("--directory", type=Path, required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--directory", type=Path, required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    create_parser.add_argument("--tag", required=True)
    create_parser.add_argument("--source-sha", required=True)
    create_parser.add_argument("--staging-manifest", type=Path, required=True)
    manifest_parser = commands.add_parser("verify-manifest")
    for flag in ("directory", "manifest", "public-key"):
        manifest_parser.add_argument(f"--{flag}", type=Path, required=True)
    manifest_parser.add_argument("--tag", required=True)
    manifest_parser.add_argument("--source-sha", required=True)
    manifest_parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "write-checksums":
            write_checksums(args.directory)
        elif args.command == "create":
            create(args.directory, args.output, args.tag, args.source_sha, args.staging_manifest)
        elif args.command == "verify-manifest":
            verify_manifest(args.directory, args.manifest, args.public_key, args.tag,
                            args.source_sha, args.manifest_sha256)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"cli-release-draft: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
