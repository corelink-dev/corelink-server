#!/usr/bin/env python3
"""Fail-closed policy for the B-114 corelink-runners build receipt."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

EXPECTED = {
    "repository": "HuGR-Labs/corelink-runners",
    "runners_commit": "70045e8d322d46888066481b702ddf4d3103df06",
    "publication_run": "36223081235",
    "publication_artifact": "10900170202",
    "artifact_digest": "sha256:7bfc278457c6570e66d4f0f360888e237f54ef63baa89c6c27cc020b95c57a2d",
    "build_only_run": "36223176826",
}
FORBIDDEN_CLAIMS = re.compile(r"\b(?:deploy(?:ed|ment)?|pin(?:ned|ning)?|provider mutation|image pull)\b", re.I)


class ContractError(RuntimeError):
    pass


def fields(text: str) -> dict[str, str]:
    return dict(re.findall(r"(?m)^([a-z_]+):\s*(\S.*)$", text))


def check(text: str) -> None:
    value = fields(text)
    for key, expected in EXPECTED.items():
        if value.get(key) != expected:
            raise ContractError(f"B-114 receipt {key} is not exact")
    if value.get("claim_scope") != "build-publication receipt only; no deployment, pin, provider, or image claim":
        raise ContractError("B-114 receipt claim scope is not exact")
    if FORBIDDEN_CLAIMS.search(text.replace(value["claim_scope"], "")):
        raise ContractError("B-114 receipt makes a forbidden operational claim")


def self_test() -> None:
    valid = "\n".join(f"{key}: {value}" for key, value in EXPECTED.items()) + "\n" + (
        "claim_scope: build-publication receipt only; no deployment, pin, provider, or image claim\n"
    )
    check(valid)
    for old, new in ((EXPECTED["runners_commit"], "0" * 40), ("build-publication", "deployment")):
        try:
            check(valid.replace(old, new, 1))
        except ContractError:
            continue
        raise ContractError("B-114 mutation was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--receipt", action="store_true")
    args = parser.parse_args()
    if args.self_test or not args.receipt:
        try:
            self_test()
        except ContractError as error:
            print(f"B-114 policy FAILED: {error}")
            return 1
        print("B-114 policy mutation checks passed")
        return 0
    receipt = Path("docs/campaigns/remediation/B-114-corelink-runners-receipt.md")
    try:
        check(receipt.read_text(encoding="utf-8"))
    except (OSError, ContractError) as error:
        print(f"B-114 contract FAILED: {error}")
        return 1
    print("B-114 contract OK: exact cross-repository build/publication receipt only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
