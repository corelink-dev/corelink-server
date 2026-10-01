#!/usr/bin/env python3
"""Run the explicitly bounded, one-shot protected GPG access audit.

The only private-key operation is a detached signature over a fixed synthetic
probe, sent to /dev/null. It proves that the protected passphrase unlocks the
imported key without signing release bytes or retaining a signature. GnuPG
output is captured and discarded. The temporary keyring is always removed;
the hosted runner itself is ephemeral as a second cleanup boundary.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


EXPECTED_FINGERPRINT = "795253CEBD6D54C862CFC4A3EC0AD89A75EC6756"
EXPECTED_PRIMARY_UID = "CoreLink Release Signing (corelink-cli release signing key) <releases@humangr.com>"
EXPECTED_REPOSITORY = "HuGR-dev/corelink-server"
EXPECTED_SECRET_NAMES = [
    "GPG_PRIVATE_KEY",
    "GPG_PRIVATE_KEY_PASS",
    "GPG_KEY_ID",
    "GPG_KEY_FINGERPRINT",
]
PROBE_BYTES = b"CoreLink protected GPG access audit probe v1\n"
PRIMARY_UID_EXPORT_FILTER = "keep-uid=primary -t"
WRONG_PASSPHRASE = "corelink-intentionally-wrong-audit-passphrase-v1"
HEX_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
HEX_KEY_ID = re.compile(r"^[0-9A-F]{16}$")


class AuditError(Exception):
    """Safe-to-report audit error category; never contains input data."""


def fail(category: str) -> None:
    raise AuditError(category)


def normalize_fingerprint(value: str) -> str:
    normalized = value.replace(":", "").replace(" ", "").replace("\t", "").upper()
    if not HEX_FINGERPRINT.fullmatch(normalized):
        fail("configured-fingerprint-invalid")
    return normalized


def normalize_key_id(value: str) -> str:
    normalized = value
    if normalized.startswith(("0x", "0X")):
        normalized = normalized[2:]
    normalized = normalized.upper()
    if not HEX_KEY_ID.fullmatch(normalized):
        fail("configured-key-id-invalid")
    return normalized


def validate_configured_binding(fingerprint_value: str, key_id_value: str) -> tuple[str, str]:
    fingerprint = normalize_fingerprint(fingerprint_value)
    key_id = normalize_key_id(key_id_value)
    if fingerprint != EXPECTED_FINGERPRINT:
        fail("configured-fingerprint-mismatch")
    if key_id != EXPECTED_FINGERPRINT[-16:]:
        fail("configured-key-id-mismatch")
    return fingerprint, key_id


def decode_colon_uid(value: str) -> str:
    """Decode GnuPG's C-style quoted UID field, rejecting unknown escapes."""
    output: list[str] = []
    index = 0
    escapes = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue
        if index + 1 >= len(value):
            fail("uid-encoding-invalid")
        marker = value[index + 1]
        if marker == "x" and index + 3 < len(value):
            try:
                output.append(chr(int(value[index + 2 : index + 4], 16)))
            except ValueError:
                fail("uid-encoding-invalid")
            index += 4
            continue
        if marker not in escapes:
            fail("uid-encoding-invalid")
        output.append(escapes[marker])
        index += 2
    return "".join(output)


def parse_identity(listing: str, *, now_epoch: int) -> dict[str, str]:
    """Check synthetic-or-real GnuPG colon output against the pinned identity."""
    records = [line.split(":") for line in listing.splitlines() if line]
    public_records = [row for row in records if row[0] == "pub"]
    if len(public_records) != 1:
        fail("public-key-cardinality")
    public = public_records[0]
    if len(public) <= 11 or public[1][:1] in {"r", "e", "d", "i", "n"} or "D" in public[11]:
        fail("public-key-unusable")

    primary_fingerprints: list[str] = []
    after_primary = False
    primary_uids: list[list[str]] = []
    for row in records:
        if row[0] == "pub":
            after_primary = True
            continue
        if not after_primary:
            continue
        if row[0] in {"sub", "fpr"} and row[0] == "sub":
            after_primary = False
        if row[0] == "fpr" and not primary_fingerprints:
            if len(row) <= 9:
                fail("public-fingerprint-missing")
            primary_fingerprints.append(row[9].upper())
        elif row[0] == "uid" and after_primary:
            primary_uids.append(row)

    if len(primary_fingerprints) != 1 or primary_fingerprints[0] != EXPECTED_FINGERPRINT:
        fail("public-fingerprint-mismatch")
    if len(public) <= 6 or not public[6].isdigit() or int(public[6]) <= now_epoch:
        fail("public-key-expired-or-no-expiry")
    key_id = public[4].upper() if len(public) > 4 else ""
    if key_id != EXPECTED_FINGERPRINT[-16:]:
        fail("public-key-id-mismatch")
    if not primary_uids or len(primary_uids[0]) <= 9:
        fail("primary-uid-missing")
    primary_uid = primary_uids[0]
    if primary_uid[1][:1] in {"r", "e", "d", "i", "n"}:
        fail("primary-uid-unusable")
    if primary_uid[6] and primary_uid[6].isdigit() and int(primary_uid[6]) <= now_epoch:
        fail("primary-uid-expired")
    uid = decode_colon_uid(primary_uid[9])
    if uid != EXPECTED_PRIMARY_UID:
        fail("primary-uid-mismatch")
    return {
        "fingerprint": primary_fingerprints[0],
        "key_id": key_id,
        "primary_uid": uid,
        "expires_at": dt.datetime.fromtimestamp(int(public[6]), tz=dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def check_secret_listing(listing: str) -> None:
    records = [line.split(":") for line in listing.splitlines() if line]
    secret_keys = [row for row in records if row[0] == "sec"]
    fingerprints = [row[9].upper() for row in records if row[0] == "fpr" and len(row) > 9]
    if len(secret_keys) != 1 or len(secret_keys[0]) <= 4:
        fail("protected-private-key-unavailable")
    if secret_keys[0][1][:1] in {"r", "e", "d", "i", "n"}:
        fail("protected-private-key-unusable")
    if secret_keys[0][4].upper() != EXPECTED_FINGERPRINT[-16:]:
        fail("protected-private-key-id-mismatch")
    if EXPECTED_FINGERPRINT not in fingerprints:
        fail("protected-private-key-fingerprint-mismatch")


def run_gpg(args: list[str], *, gnupghome: Path, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            ["gpg", "--batch", "--no-tty", *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "GNUPGHOME": str(gnupghome), "LC_ALL": "C"},
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("gpg-command-failed")
    if completed.returncode != 0:
        fail("gpg-command-failed")
    return completed


def validate_probe_result(returncode: int, *, passphrase_expected_to_work: bool) -> None:
    if passphrase_expected_to_work and returncode != 0:
        fail("protected-passphrase-access-failed")
    if not passphrase_expected_to_work and returncode == 0:
        fail("protected-passphrase-not-required-or-agent-cached")


def run_passphrase_probe(*, gnupghome: Path, key_id: str, passphrase: str, passphrase_expected_to_work: bool) -> None:
    if not passphrase or "\n" in passphrase or "\r" in passphrase:
        fail("protected-passphrase-unavailable")
    read_fd, write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        command = [
            "gpg",
            "--batch",
            "--yes",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            str(read_fd),
            "--local-user",
            key_id,
            "--detach-sign",
            "--output",
            os.devnull,
            "--",
            "-",
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "GNUPGHOME": str(gnupghome), "LC_ALL": "C"},
            close_fds=True,
            pass_fds=(read_fd,),
        )
        os.close(read_fd)
        read_fd = -1
        os.write(write_fd, passphrase.encode("utf-8") + b"\n")
        os.close(write_fd)
        write_fd = -1
        try:
            _, _ = process.communicate(input=PROBE_BYTES, timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            fail("protected-passphrase-access-failed")
        validate_probe_result(process.returncode, passphrase_expected_to_work=passphrase_expected_to_work)
    except BaseException as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        if isinstance(error, OSError):
            fail("protected-passphrase-access-failed")
        raise
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def terminate_ephemeral_agent(gnupghome: Path) -> None:
    try:
        result = subprocess.run(
            ["gpgconf", "--kill", "gpg-agent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "GNUPGHOME": str(gnupghome), "LC_ALL": "C"},
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("ephemeral-agent-cleanup-failed")
    if result.returncode != 0:
        fail("ephemeral-agent-cleanup-failed")


def receipt(identity: dict[str, str], env: dict[str, str]) -> dict[str, object]:
    sha = env.get("GITHUB_SHA", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not run_id.isdigit() or not attempt.isdigit():
        fail("workflow-run-metadata-invalid")
    return {
        "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor_role": "environment-approved operator",
        "repository": EXPECTED_REPOSITORY,
        "workflow": "i1664 GPG release identity audit",
        "run_url": f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{run_id}",
        "run_attempt": int(attempt),
        "sha": sha,
        "primary_uid": identity["primary_uid"],
        "fingerprint": identity["fingerprint"],
        "expires_at": identity["expires_at"],
        "revoked": False,
        "protected_secret_names": EXPECTED_SECRET_NAMES,
        "access_result": "passphrase-unlocked by transient synthetic probe; signature discarded to /dev/null",
    }


def run_audit(env: dict[str, str], *, now_epoch: int | None = None, command_runner: Callable[..., subprocess.CompletedProcess[bytes]] = run_gpg) -> dict[str, object]:
    if env.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        fail("repository-mismatch")
    for name in EXPECTED_SECRET_NAMES:
        if not env.get(name):
            fail("protected-secret-unavailable")

    validate_configured_binding(env["GPG_KEY_FINGERPRINT"], env["GPG_KEY_ID"])

    runner_temp = env.get("RUNNER_TEMP")
    if not runner_temp:
        fail("ephemeral-runner-temp-unavailable")
    temp_root: Path | None = None
    gnupghome: Path | None = None
    try:
        temp_root = Path(tempfile.mkdtemp(prefix="i2587-gpg-audit-", dir=runner_temp))
        os.chmod(temp_root, 0o700)
        gnupghome = temp_root / "gnupg"
        gnupghome.mkdir(mode=0o700)
        imported = command_runner(["--import"], gnupghome=gnupghome, input_bytes=env["GPG_PRIVATE_KEY"].encode("utf-8"))
        del imported
        primary_public_key = command_runner(
            ["--export-filter", PRIMARY_UID_EXPORT_FILTER, "--export", EXPECTED_FINGERPRINT],
            gnupghome=gnupghome,
        )
        if not primary_public_key.stdout:
            fail("primary-public-identity-unavailable")
        listing = command_runner(
            ["--with-colons", "--fixed-list-mode", "--with-fingerprint", "--show-keys"],
            gnupghome=gnupghome,
            input_bytes=primary_public_key.stdout,
        )
        del primary_public_key
        identity = parse_identity(listing.stdout.decode("utf-8", errors="strict"), now_epoch=now_epoch or int(dt.datetime.now(dt.timezone.utc).timestamp()))
        secret_listing = command_runner(
            ["--with-colons", "--fixed-list-mode", "--with-fingerprint", "--list-secret-keys", EXPECTED_FINGERPRINT],
            gnupghome=gnupghome,
        )
        check_secret_listing(secret_listing.stdout.decode("utf-8", errors="strict"))
        terminate_ephemeral_agent(gnupghome)
        run_passphrase_probe(
            gnupghome=gnupghome,
            key_id=EXPECTED_FINGERPRINT,
            passphrase=WRONG_PASSPHRASE,
            passphrase_expected_to_work=False,
        )
        terminate_ephemeral_agent(gnupghome)
        run_passphrase_probe(
            gnupghome=gnupghome,
            key_id=EXPECTED_FINGERPRINT,
            passphrase=env["GPG_PRIVATE_KEY_PASS"],
            passphrase_expected_to_work=True,
        )
    except AuditError:
        raise
    except (UnicodeError, OSError):
        fail("audit-input-or-keyring-invalid")
    finally:
        try:
            if gnupghome is not None and gnupghome.exists():
                terminate_ephemeral_agent(gnupghome)
        finally:
            if temp_root is not None:
                try:
                    shutil.rmtree(temp_root)
                except OSError:
                    fail("ephemeral-keyring-cleanup-failed")

    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        fail("redacted-receipt-destination-unavailable")
    report = receipt(identity, env)
    Path(summary_path).write_text(
        "# Redacted GPG protected access audit receipt\n\n```json\n"
        + json.dumps(report, sort_keys=True, indent=2)
        + "\n```\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    def stop_on_signal(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop_on_signal)
    signal.signal(signal.SIGINT, stop_on_signal)
    try:
        run_audit(dict(os.environ))
    except AuditError as error:
        print(f"::error::protected GPG access audit failed closed ({error})", file=sys.stderr)
        return 1
    except OSError:
        print("::error::protected GPG access audit failed closed (receipt-write-failed)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
