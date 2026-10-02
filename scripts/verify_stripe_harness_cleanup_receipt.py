#!/usr/bin/env python3
"""Validate the public, ID-redacted cleanup receipt for one Stripe harness run."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# Each checkout test also owns one disposable TEST-mode Starter product and
# price (direct-test profile, #2565); Stripe cannot delete either, so both are
# archived (`active=false`) and read back.
EXPECTED = {
    "live_create_customer": {"customer": 1},
    "live_create_checkout_session_starter": {"checkout": 1, "customer": 1, "price": 1, "product": 1},
    "live_idempotent_checkout_returns_same_session": {"checkout": 1, "customer": 1, "price": 1, "product": 1},
    "live_billing_portal_session": {"customer": 1},
}
STATUS = {
    "customer": "deleted_readback_pass",
    "checkout": "expired_readback_pass",
    "price": "archived_readback_pass",
    "product": "archived_readback_pass",
}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def validate(lines: list[str], run_id: str) -> bool:
    seen: set[tuple[str, str, str]] = set()
    counts = {test: {kind: 0 for kind in kinds} for test, kinds in EXPECTED.items()}
    try:
        for line in lines:
            row = json.loads(line)
            if set(row) != {"run_id", "test", "kind", "id_sha256", "status"}:
                return False
            test, kind = row["test"], row["kind"]
            if row["run_id"] != run_id or test not in EXPECTED or kind not in EXPECTED[test]:
                return False
            if row["status"] != STATUS[kind] or not isinstance(row["id_sha256"], str):
                return False
            if not HEX_SHA256.fullmatch(row["id_sha256"]):
                return False
            key = (test, kind, row["id_sha256"])
            if key in seen:
                return False
            seen.add(key)
            counts[test][kind] += 1
        return bool(lines) and counts == EXPECTED
    except (TypeError, ValueError, KeyError):
        return False


def main() -> int:
    if len(sys.argv) != 3:
        print("cleanup receipt validation failed", file=sys.stderr)
        return 2
    try:
        lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    except OSError:
        print("cleanup receipt validation failed", file=sys.stderr)
        return 2
    if not validate(lines, sys.argv[2]):
        print("cleanup receipt validation failed", file=sys.stderr)
        return 1
    print("stripe cleanup receipt: PASS (run-owned object counts and redacted hashes verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
