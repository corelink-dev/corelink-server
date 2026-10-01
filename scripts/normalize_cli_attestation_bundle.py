#!/usr/bin/env python3
"""Copy a GitHub attestation bundle to a GH CLI-supported JSON filename.

The uploaded `.bundle` asset is intentionally left unchanged.  GitHub CLI
2.79.0 selects its bundle decoder from the filename suffix and accepts `.json`
or `.jsonl`, so workflow callers make this private, byte-identical copy before
verification.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path


CHUNK_SIZE = 1024 * 1024
SUPPORTED_SUFFIXES = {".json", ".jsonl"}


class BundleCopyError(ValueError):
    """Raised when the source or destination is unsafe or cannot be bound."""


def normalize(source: Path, destination: Path) -> str:
    if destination.suffix not in SUPPORTED_SUFFIXES:
        raise BundleCopyError("destination must use a GitHub CLI-supported .json or .jsonl suffix")
    if source == destination:
        raise BundleCopyError("source and destination must be different files")
    try:
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise BundleCopyError("bundle source is unavailable or is a symlink") from error

    created = False
    destination_fd: int | None = None
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise BundleCopyError("bundle source must be a regular file")
        try:
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            created = True
        except OSError as error:
            raise BundleCopyError("bundle destination must be absent and must not be a symlink") from error
        os.fchmod(destination_fd, 0o600)

        source_hash = hashlib.sha256()
        with os.fdopen(source_fd, "rb", closefd=False) as source_stream:
            while chunk := source_stream.read(CHUNK_SIZE):
                source_hash.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise BundleCopyError("short write while copying the bundle")
                    view = view[written:]
        os.fsync(destination_fd)
        os.close(destination_fd)
        destination_fd = None

        destination_hash = hashlib.sha256()
        with destination.open("rb") as copied:
            if not stat.S_ISREG(os.fstat(copied.fileno()).st_mode):
                raise BundleCopyError("normalized bundle is not a regular file")
            if stat.S_IMODE(destination.stat(follow_symlinks=False).st_mode) != 0o600:
                raise BundleCopyError("normalized bundle permissions are not private")
            for chunk in iter(lambda: copied.read(CHUNK_SIZE), b""):
                destination_hash.update(chunk)
        if source_hash.digest() != destination_hash.digest():
            raise BundleCopyError("normalized bundle bytes differ from the original")
        return source_hash.hexdigest()
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        print(f"sha256={normalize(args.source, args.destination)}")
    except (OSError, BundleCopyError) as error:
        print(f"normalize-cli-attestation-bundle: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
