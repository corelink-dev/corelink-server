#!/usr/bin/env python3
"""Verify that PATH resolves to the repository-pinned GitHub CLI executable."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

from install_pinned_gh import InstallError, VERSION, verify_binary


class VerificationError(ValueError):
    pass


def verify(binary_arg: str) -> tuple[Path, str]:
    binary = Path(binary_arg)
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        raise VerificationError("pinned gh path must be an absolute regular file")
    try:
        verify_binary(binary)
    except InstallError as error:
        raise VerificationError(str(error)) from error

    resolved = shutil.which("gh")
    if resolved is None or Path(resolved).resolve(strict=True) != binary.resolve(strict=True):
        raise VerificationError("PATH does not resolve gh to the checksum-pinned executable")

    with tempfile.TemporaryDirectory(prefix="corelink-gh-version-check-") as temporary:
        config_dir = Path(temporary) / "config"
        config_dir.mkdir()
        environment = {
            "PATH": os.defpath,
            "HOME": temporary,
            "GH_CONFIG_DIR": str(config_dir),
            "LC_ALL": "C",
        }
        result = subprocess.run(
            [str(binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=15,
        )
    if result.returncode != 0:
        raise VerificationError("checksum-pinned gh --version failed")
    lines = result.stdout.splitlines()
    match = re.fullmatch(rf"gh version {re.escape(VERSION)} \((\d{{4}}-\d{{2}}-\d{{2}})\)", lines[0] if lines else "")
    if match is None:
        raise VerificationError("checksum-pinned gh version output does not match the pinned semver")
    try:
        date.fromisoformat(match.group(1))
    except ValueError as error:
        raise VerificationError("checksum-pinned gh version date is invalid") from error
    if len(lines) < 2 or lines[1] != f"https://github.com/cli/cli/releases/tag/v{VERSION}":
        raise VerificationError("checksum-pinned gh release URL does not match the pinned version")
    return binary, lines[0]


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "--binary":
        raise SystemExit("usage: verify_pinned_gh.py --binary ABSOLUTE_PATH")
    try:
        binary, version = verify(sys.argv[2])
    except (OSError, VerificationError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"pinned gh verification failed: {error}") from error
    print(f"verified pinned gh path: {binary}")
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
