#!/usr/bin/env python3
"""Fail-closed inventory, shard receipt, and aggregate checks for #2457.

The workflow is deliberately a thin transport.  This module owns the data
contract so a later Actions retry cannot turn an incomplete mutation campaign
into a green aggregate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping


SHARD_COUNT = 27
SHARDING = "round-robin"
INVENTORY_SHARD = "0/1"
TOOL_VERSION = "27.0.0"
IDENTITY_SCHEMA = "cargo-mutants-v27.full-list-record.sha256.multiset.v1"
INVENTORY_SCHEMA = "corelink.hosted-mutants-inventory.v5"
BASELINE_SCHEMA = "corelink.hosted-mutants-baseline-receipt.v6"
SHARD_SCHEMA = "corelink.hosted-mutants-shard-receipt.v6"
AGGREGATE_SCHEMA = "corelink.hosted-mutants-aggregate-receipt.v6"
EVIDENCE_SCHEMA = "corelink.hosted-mutants-shard-evidence.v2"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
CANONICAL_ARGUMENTS = (
    "--workspace",
    "--no-config",
    "--no-shuffle",
    "--minimum-test-timeout=600",
    "--jobs=8",
    "--build-timeout=60",
    "--timeout=60",
    "--sharding=round-robin",
)
CARGO_MUTANTS_LIST_FIELDS = frozenset(
    {"name", "package", "file", "function", "span", "replacement", "genre", "diff"}
)
OUTCOME_SUMMARIES = {
    "CaughtMutant": "caught",
    "MissedMutant": "missed",
    "Timeout": "timeout",
    "Unviable": "unviable",
    "Success": "success",
}
OUTCOME_COUNT_FIELDS = tuple(sorted(set(OUTCOME_SUMMARIES.values())))


class VerificationError(ValueError):
    """A condition that must make the campaign red."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def config_digest() -> str:
    return digest(
        {
            "cargo_mutants_version": TOOL_VERSION,
            "arguments": CANONICAL_ARGUMENTS,
            "identity_schema": IDENTITY_SCHEMA,
            "shard_count": SHARD_COUNT,
            "sharding": SHARDING,
        }
    )


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{field} must be a non-empty string")
    return value


def require_sha(value: Any, field: str) -> str:
    value = require_string(value, field)
    if not SHA_RE.fullmatch(value):
        raise VerificationError(f"{field} must be a 40-character lowercase SHA")
    return value


def require_digest(value: Any, field: str) -> str:
    value = require_string(value, field)
    if not DIGEST_RE.fullmatch(value):
        raise VerificationError(f"{field} must be a sha256 digest")
    return value


def require_attempt(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VerificationError(f"{field} must be a positive integer")
    return value


def _position(value: Any, field: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise VerificationError(f"{field} must be an object")
    line = value.get("line")
    column = value.get("column")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise VerificationError(f"{field}.line must be a positive integer")
    if isinstance(column, bool) or not isinstance(column, int) or column < 1:
        raise VerificationError(f"{field}.column must be a positive integer")
    return {"line": line, "column": column}


def _span(value: Any, field: str) -> dict[str, dict[str, int]]:
    if not isinstance(value, Mapping):
        raise VerificationError(f"{field} must be an object")
    start = _position(value.get("start"), f"{field}.start")
    end = _position(value.get("end"), f"{field}.end")
    if (end["line"], end["column"]) <= (start["line"], start["column"]):
        raise VerificationError(f"{field} must have an end after its start")
    return {"start": start, "end": end}


def _function(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise VerificationError(f"{field} must be an object or null")
    if set(value) != {"function_name", "return_type", "span"}:
        raise VerificationError(f"{field} fields are not the pinned cargo-mutants v27 shape")
    function_name = require_string(value.get("function_name"), f"{field}.function_name")
    return_type = value.get("return_type")
    if not isinstance(return_type, str):
        raise VerificationError(f"{field}.return_type must be a string")
    return {
        "function_name": function_name,
        "return_type": return_type,
        "span": _span(value.get("span"), f"{field}.span"),
    }


def mutant_identity(item: Mapping[str, Any], index: int) -> str:
    """Return the redacted identity of the complete pinned cargo-mutants v27 record."""
    if set(item) != CARGO_MUTANTS_LIST_FIELDS:
        raise VerificationError(f"mutant[{index}] fields are not the pinned cargo-mutants v27 list shape")
    name = require_string(item.get("name"), f"mutant[{index}].name")
    package = require_string(item.get("package"), f"mutant[{index}].package")
    source_file = require_string(item.get("file"), f"mutant[{index}].file")
    replacement = item.get("replacement")
    if not isinstance(replacement, str):
        raise VerificationError(f"mutant[{index}].replacement must be a string")
    genre = require_string(item.get("genre"), f"mutant[{index}].genre")
    diff = require_string(item.get("diff"), f"mutant[{index}].diff")
    identity = {
        "identity_schema": IDENTITY_SCHEMA,
        "name": name,
        "package": package,
        "file": source_file,
        "function": _function(item.get("function"), f"mutant[{index}].function"),
        "span": _span(item.get("span"), f"mutant[{index}].span"),
        "replacement": replacement,
        "genre": genre,
        "diff": diff,
    }
    return "sha256:" + digest(identity)


def mutant_ids(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        raise VerificationError("cargo-mutants list must be a JSON array")
    ids: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise VerificationError(f"mutant[{index}] must be an object")
        ids.append(mutant_identity(item, index))
    if not ids:
        raise VerificationError("full workspace mutant inventory must not be empty")
    return ids


def mutant_counts(ids: list[str]) -> list[dict[str, Any]]:
    """Return the canonical multiplicity of every redacted full-record hash."""
    return [
        {"identity": identity, "count": count}
        for identity, count in sorted(Counter(ids).items())
    ]


def outcome_counts(records: list[dict[str, str]]) -> dict[str, int]:
    counts = Counter(record["outcome"] for record in records)
    return {field: counts[field] for field in OUTCOME_COUNT_FIELDS}


def terminal_outcome_records(raw: Any, expected_raw: Any, expected_ids: list[str]) -> list[dict[str, str]]:
    """Redact a terminal cargo-mutants outcome set to exact inventory identities."""
    expected = mutant_ids(expected_raw)
    if expected != expected_ids:
        raise VerificationError("cargo-mutants shard list disagrees with frozen inventory")
    if not isinstance(raw, Mapping) or not isinstance(raw.get("end_time"), str):
        raise VerificationError("cargo-mutants outcomes are not terminal")
    if raw.get("cargo_mutants_version") != TOOL_VERSION:
        raise VerificationError("cargo-mutants outcomes do not use the pinned tool version")
    outcomes = raw.get("outcomes")
    if not isinstance(outcomes, list):
        raise VerificationError("cargo-mutants outcomes must be a JSON array")
    if raw.get("total_mutants") != len(expected_ids):
        raise VerificationError("cargo-mutants terminal outcome total does not equal the frozen shard")
    ids_by_name: dict[str, list[str]] = defaultdict(list)
    for item, identity in zip(expected_raw, expected_ids, strict=True):
        ids_by_name[item["name"]].append(identity)
    if any(len(set(identities)) > 1 for identities in ids_by_name.values()):
        raise VerificationError("cargo-mutants outcome names cannot uniquely bind frozen identities")
    records: list[dict[str, str]] = []
    for index, outcome in enumerate(outcomes):
        if not isinstance(outcome, Mapping):
            raise VerificationError(f"outcome[{index}] must be an object")
        scenario = outcome.get("scenario")
        if not isinstance(scenario, Mapping) or set(scenario) != {"Mutant"}:
            raise VerificationError("terminal outcome includes a non-mutant scenario")
        mutant = scenario["Mutant"]
        if not isinstance(mutant, Mapping):
            raise VerificationError("terminal outcome mutant is invalid")
        name = mutant.get("name")
        summary = outcome.get("summary")
        if not isinstance(name, str) or summary not in OUTCOME_SUMMARIES or not ids_by_name.get(name):
            raise VerificationError("terminal outcome does not bind a frozen mutant identity")
        records.append({"identity": ids_by_name[name].pop(), "outcome": OUTCOME_SUMMARIES[summary]})
    if sorted(record["identity"] for record in records) != sorted(expected_ids):
        raise VerificationError("terminal outcomes do not cover the frozen shard exactly once")
    if sum(outcome_counts(records).values()) != len(expected_ids):
        raise VerificationError("terminal outcome summary does not equal the frozen shard")
    return sorted(records, key=lambda record: (record["identity"], record["outcome"]))


def inventory_mutant_ids(value: Any) -> list[str]:
    """Validate the ordered, occurrence-preserving redacted identity list."""
    if not isinstance(value, list):
        raise VerificationError("inventory mutant_ids must be a JSON array")
    if not value or any(not isinstance(name, str) or not name for name in value):
        raise VerificationError("inventory mutant_ids must contain non-empty string identities")
    return value


def inventory_mutant_counts(value: Any, ids: list[str], field: str = "inventory mutant_counts") -> list[dict[str, Any]]:
    """Validate the canonical count projection that binds duplicate occurrences."""
    if not isinstance(value, list):
        raise VerificationError(f"{field} must be a JSON array")
    expected = mutant_counts(ids)
    if value != expected:
        raise VerificationError(f"{field} does not exactly bind identity multiplicity")
    return expected


def membership(ids: list[str], shard: int) -> list[str]:
    if shard < 0 or shard >= SHARD_COUNT:
        raise VerificationError("shard index is outside the frozen denominator")
    return [name for index, name in enumerate(ids) if index % SHARD_COUNT == shard]


def make_inventory(raw: Any, sha: str, run_id: str, attempt: int) -> dict[str, Any]:
    ids = mutant_ids(raw)
    counts = mutant_counts(ids)
    return {
        "schema": INVENTORY_SCHEMA,
        "run_id": require_string(run_id, "run_id"),
        "run_attempt": require_attempt(attempt, "run_attempt"),
        "sha": require_sha(sha, "sha"),
        "tool_version": TOOL_VERSION,
        "config_digest": config_digest(),
        "shard_count": SHARD_COUNT,
        "sharding": SHARDING,
        "inventory_shard": INVENTORY_SHARD,
        "mutant_ids": ids,
        "mutant_counts": counts,
        "inventory_digest": digest({"mutant_ids": ids, "mutant_counts": counts}),
    }


def validate_inventory(document: Mapping[str, Any]) -> list[str]:
    if document.get("schema") != INVENTORY_SCHEMA:
        raise VerificationError("unsupported inventory schema")
    require_string(document.get("run_id"), "inventory.run_id")
    require_attempt(document.get("run_attempt"), "inventory.run_attempt")
    require_sha(document.get("sha"), "inventory.sha")
    if document.get("tool_version") != TOOL_VERSION:
        raise VerificationError("inventory tool version is not pinned cargo-mutants 27.0.0")
    if document.get("config_digest") != config_digest():
        raise VerificationError("inventory configuration digest is not canonical")
    if document.get("shard_count") != SHARD_COUNT or document.get("sharding") != SHARDING:
        raise VerificationError("inventory shard definition drifted")
    if document.get("inventory_shard") != INVENTORY_SHARD:
        raise VerificationError("inventory must use the complete denominator-one shard 0/1")
    ids = inventory_mutant_ids(document.get("mutant_ids"))
    counts = inventory_mutant_counts(document.get("mutant_counts"), ids)
    if document.get("inventory_digest") != digest({"mutant_ids": ids, "mutant_counts": counts}):
        raise VerificationError("inventory digest does not bind its identities")
    return ids


def validate_baseline(receipt: Mapping[str, Any], inventory: Mapping[str, Any]) -> None:
    if receipt.get("schema") != BASELINE_SCHEMA:
        raise VerificationError("unsupported baseline receipt schema")
    for field in ("run_id", "sha", "tool_version", "config_digest", "inventory_digest"):
        if receipt.get(field) != inventory.get(field):
            raise VerificationError(f"baseline {field} does not bind the inventory")
    require_attempt(receipt.get("run_attempt"), "baseline.run_attempt")
    require_digest(receipt.get("baseline_digest"), "baseline.baseline_digest")
    require_digest(receipt.get("plan_digest"), "baseline.plan_digest")
    if receipt.get("shard_count") != SHARD_COUNT:
        raise VerificationError("baseline does not bind all 27 test shards")
    covered_entries = receipt.get("covered_entries")
    if isinstance(covered_entries, bool) or not isinstance(covered_entries, int) or covered_entries <= 0:
        raise VerificationError("baseline does not prove a nonempty complete test mapping")
    if receipt.get("status") != "success" or receipt.get("exit_code") != 0:
        raise VerificationError("unmutated baseline did not succeed")


def validate_shard_receipt(receipt: Mapping[str, Any], inventory: Mapping[str, Any]) -> int:
    if receipt.get("schema") != SHARD_SCHEMA:
        raise VerificationError("unsupported shard receipt schema")
    for field in ("run_id", "sha", "tool_version", "config_digest", "inventory_digest"):
        if receipt.get(field) != inventory.get(field):
            raise VerificationError(f"shard {field} does not bind the inventory")
    attempt = require_attempt(receipt.get("run_attempt"), "shard.run_attempt")
    shard = receipt.get("shard")
    if not isinstance(shard, dict):
        raise VerificationError("shard identity is missing")
    index = shard.get("index")
    total = shard.get("total")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= SHARD_COUNT:
        raise VerificationError("shard index is invalid")
    if total != SHARD_COUNT or shard.get("sharding") != SHARDING:
        raise VerificationError("shard denominator or algorithm drifted")
    ids = validate_inventory(inventory)
    expected = membership(ids, index)
    observed = receipt.get("mutant_ids")
    if observed != expected:
        raise VerificationError(f"shard {index} identities are not the expected deterministic membership")
    inventory_mutant_counts(receipt.get("mutant_counts"), expected, f"shard {index} mutant_counts")
    if receipt.get("membership_digest") != digest(expected):
        raise VerificationError(f"shard {index} membership digest is invalid")
    require_digest(receipt.get("baseline_digest"), "shard.baseline_digest")
    require_digest(receipt.get("evidence_digest"), "shard.evidence_digest")
    require_digest(receipt.get("artifact_digest"), "shard.artifact_digest")
    if receipt.get("evidence_present") is not True:
        raise VerificationError(f"shard {index} evidence artifact is missing")
    counts = receipt.get("outcome_counts")
    outcomes_complete = receipt.get("outcomes_complete")
    if outcomes_complete is False:
        if receipt.get("status") != "incomplete" or counts is not None:
            raise VerificationError(f"shard {index} incomplete status does not bind absent terminal outcomes")
        require_string(receipt.get("incomplete_reason"), f"shard {index} incomplete_reason")
        return index
    if outcomes_complete is not True:
        raise VerificationError(f"shard {index} does not prove complete outcomes")
    if not isinstance(counts, Mapping) or set(counts) != set(OUTCOME_COUNT_FIELDS):
        raise VerificationError(f"shard {index} outcome summary is invalid")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts.values()):
        raise VerificationError(f"shard {index} outcome summary is invalid")
    if sum(counts.values()) != len(expected):
        raise VerificationError(f"shard {index} outcome summary does not cover its frozen membership")
    status = receipt.get("status")
    exit_code = receipt.get("cargo_exit_code")
    if status not in {"success", "failure"} or isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise VerificationError(f"shard {index} terminal status is invalid")
    if status == "success" and (exit_code != 0 or counts["missed"] != 0 or counts["timeout"] != 0):
        raise VerificationError(f"shard {index} successful status disagrees with terminal outcomes")
    if status == "failure" and exit_code == 0:
        raise VerificationError(f"shard {index} failed status has a zero cargo exit")
    return index


def _latest_by_attempt(receipts: Iterable[Mapping[str, Any]], label: str) -> Mapping[str, Any]:
    candidates = list(receipts)
    if not candidates:
        raise VerificationError(f"missing {label} receipt")
    attempts: dict[int, Mapping[str, Any]] = {}
    for receipt in candidates:
        attempt = require_attempt(receipt.get("run_attempt"), f"{label}.run_attempt")
        if attempt in attempts:
            raise VerificationError(f"duplicate {label} receipt for attempt {attempt}")
        attempts[attempt] = receipt
    return attempts[max(attempts)]


def aggregate_receipts(
    inventory_receipts: Iterable[Mapping[str, Any]],
    baseline_receipts: Iterable[Mapping[str, Any]],
    shard_receipts: Iterable[Mapping[str, Any]],
    expected_sha: str,
    current_run_id: str,
    current_attempt: int,
    downloaded_shard_digests: Mapping[tuple[int, int], Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Select latest same-run terminal evidence and prove a complete 27-way union."""
    expected_sha = require_sha(expected_sha, "expected_sha")
    current_run_id = require_string(current_run_id, "current_run_id")
    current_attempt = require_attempt(current_attempt, "current_attempt")
    inventory = _latest_by_attempt(inventory_receipts, "inventory")
    ids = validate_inventory(inventory)
    if inventory.get("sha") != expected_sha or inventory.get("run_id") != current_run_id:
        raise VerificationError("inventory is not from the exact current campaign")
    if inventory["run_attempt"] > current_attempt:
        raise VerificationError("inventory is from a future attempt")
    baseline = _latest_by_attempt(baseline_receipts, "baseline")
    validate_baseline(baseline, inventory)
    if baseline["run_attempt"] > current_attempt:
        raise VerificationError("baseline is from a future attempt")

    by_shard: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for receipt in shard_receipts:
        shard = receipt.get("shard")
        if not isinstance(shard, dict) or not isinstance(shard.get("index"), int):
            raise VerificationError("shard receipt lacks a usable shard index")
        by_shard[shard["index"]].append(receipt)
    if set(by_shard) != set(range(SHARD_COUNT)):
        missing = sorted(set(range(SHARD_COUNT)) - set(by_shard))
        unexpected = sorted(set(by_shard) - set(range(SHARD_COUNT)))
        raise VerificationError(f"expected all 27 shard receipts; missing={missing}, unexpected={unexpected}")

    selected: list[Mapping[str, Any]] = []
    aggregate_artifacts: list[dict[str, Any]] = []
    for index in range(SHARD_COUNT):
        receipt = _latest_by_attempt(by_shard[index], f"shard {index}")
        if receipt.get("run_attempt", 0) > current_attempt:
            raise VerificationError(f"shard {index} is from a future attempt")
        if receipt.get("baseline_digest") != baseline.get("baseline_digest"):
            raise VerificationError(f"shard {index} is bound to another baseline")
        if validate_shard_receipt(receipt, inventory) != index:
            raise VerificationError(f"shard {index} identity drifted")
        if receipt.get("status") == "incomplete":
            raise VerificationError(f"shard {index} has incomplete terminal outcomes: {receipt['incomplete_reason']}")
        if downloaded_shard_digests is not None:
            key = (index, receipt["run_attempt"])
            downloaded = downloaded_shard_digests.get(key)
            if downloaded is None:
                raise VerificationError(f"downloaded evidence is missing for shard {index} attempt {receipt['run_attempt']}")
            if downloaded.get("evidence_digest") != receipt["evidence_digest"]:
                raise VerificationError(f"downloaded evidence bytes do not match shard {index} receipt digest")
            if downloaded.get("artifact_digest") != receipt["artifact_digest"]:
                raise VerificationError(f"downloaded artifact bytes do not match shard {index} receipt digest")
            aggregate_artifacts.append(
                {
                    "index": index,
                    "run_attempt": receipt["run_attempt"],
                    "evidence_digest": downloaded["evidence_digest"],
                    "artifact_digest": downloaded["artifact_digest"],
                }
            )
        selected.append(receipt)

    union = [mutant for receipt in selected for mutant in receipt["mutant_ids"]]
    inventory_counts = inventory_mutant_counts(inventory.get("mutant_counts"), ids)
    union_counts = mutant_counts(union)
    shard_counts = [
        {
            "index": receipt["shard"]["index"],
            "occurrences": len(receipt["mutant_ids"]),
            "multiset_digest": digest(receipt["mutant_counts"]),
        }
        for receipt in selected
    ]
    if sum(item["occurrences"] for item in shard_counts) != len(ids) or union_counts != inventory_counts:
        raise VerificationError("shard occurrence counts are not the complete unsharded inventory")
    aggregate_outcomes = {
        field: sum(receipt["outcome_counts"][field] for receipt in selected)
        for field in OUTCOME_COUNT_FIELDS
    }
    if sum(aggregate_outcomes.values()) != len(ids):
        raise VerificationError("terminal mutation outcome summary does not cover the complete inventory")
    lineage = sorted({inventory["run_attempt"], baseline["run_attempt"], *(item["run_attempt"] for item in selected)})
    return {
        "schema": AGGREGATE_SCHEMA,
        "run_id": current_run_id,
        "run_attempt": current_attempt,
        "sha": expected_sha,
        "tool_version": TOOL_VERSION,
        "config_digest": config_digest(),
        "inventory_digest": inventory["inventory_digest"],
        "baseline_digest": baseline["baseline_digest"],
        "shard_count": SHARD_COUNT,
        "sharding": SHARDING,
        "covered_mutants": len(union),
        "inventory_mutant_counts": inventory_counts,
        "covered_mutant_counts": union_counts,
        "per_shard_occurrence_counts": shard_counts,
        "coverage_digest": digest({"mutant_counts": union_counts, "per_shard_occurrence_counts": shard_counts}),
        "outcome_counts": aggregate_outcomes,
        "outcome_digest": digest(aggregate_outcomes),
        "shard_artifact_digests": aggregate_artifacts,
        "attempt_lineage": lineage,
        "status": "success" if all(receipt["status"] == "success" for receipt in selected) else "failure",
    }


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def directory_digest(root: Path) -> str:
    if not root.is_dir():
        raise VerificationError(f"evidence directory is missing: {root}")
    records: list[dict[str, str]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        records.append({"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if not records:
        raise VerificationError("evidence directory is empty")
    return digest(records)


def shard_artifact_digest(evidence: Path) -> str:
    """Digest retained redacted evidence, excluding the self-referential receipt."""
    records: list[dict[str, str]] = []
    if evidence.is_dir():
        for path in sorted(item for item in evidence.rglob("*") if item.is_file()):
            records.append(
                {
                    "path": f"redacted-evidence/{path.relative_to(evidence).as_posix()}",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    return digest(records)


def validate_redacted_evidence(evidence: Path, receipt: Mapping[str, Any]) -> None:
    """Require retained redacted terminal outcome evidence to bind exact membership."""
    manifest = read_json(evidence / "shard-evidence-manifest.json")
    if not isinstance(manifest, Mapping):
        raise VerificationError("redacted shard evidence manifest must be an object")
    if manifest.get("schema") != EVIDENCE_SCHEMA:
        raise VerificationError("redacted shard evidence has an unsupported schema")
    expected_ids = receipt.get("mutant_ids")
    expected_counts = receipt.get("mutant_counts")
    if manifest.get("expected_mutant_ids") != expected_ids or manifest.get("expected_mutant_counts") != expected_counts:
        raise VerificationError("redacted shard evidence expected list does not bind the receipt")
    if receipt.get("outcomes_complete") is False:
        observed_ids = manifest.get("observed_mutant_ids")
        observed_counts = manifest.get("observed_mutant_counts")
        if observed_ids is not None and observed_ids != expected_ids:
            raise VerificationError("redacted incomplete shard evidence observed list differs from expected membership")
        if observed_counts is not None and observed_counts != expected_counts:
            raise VerificationError("redacted incomplete shard evidence observed counts differ from expected membership")
        if receipt.get("status") != "incomplete" or manifest.get("terminal_outcomes") is not None or manifest.get("outcome_counts") is not None:
            raise VerificationError("redacted shard evidence incomplete state is invalid")
        return
    if manifest.get("observed_mutant_ids") != expected_ids or manifest.get("observed_mutant_counts") != expected_counts:
        raise VerificationError("redacted shard evidence observed list does not equal expected multiplicity")
    records = manifest.get("terminal_outcomes")
    if not isinstance(records, list) or manifest.get("outcome_counts") != receipt.get("outcome_counts"):
        raise VerificationError("redacted shard evidence does not bind terminal outcomes")
    if outcome_counts(records) != receipt.get("outcome_counts"):
        raise VerificationError("redacted shard evidence terminal summary drifted")
    if sorted(record.get("identity") for record in records if isinstance(record, Mapping)) != sorted(expected_ids):
        raise VerificationError("redacted shard evidence terminal identities are incomplete")


def command_build_inventory(args: argparse.Namespace) -> None:
    raw = read_json(args.raw)
    receipt = make_inventory(raw, args.sha, args.run_id, args.run_attempt)
    write_json(args.out, receipt)


def command_write_baseline(args: argparse.Namespace) -> None:
    raise VerificationError("#2478 requires the complete mapped baseline aggregate; direct baseline receipts are forbidden")


def command_write_shard(args: argparse.Namespace) -> None:
    inventory = read_json(args.inventory)
    baseline = read_json(args.baseline)
    ids = validate_inventory(inventory)
    validate_baseline(baseline, inventory)
    expected_ids = membership(ids, args.shard)
    expected_counts = mutant_counts(expected_ids)
    observed: list[str] | None = None
    terminal_records: list[dict[str, str]] | None = None
    terminal_counts: dict[str, int] | None = None
    incomplete_reason: str | None = None
    try:
        if not args.expected.is_file() or not args.observed.is_file() or not args.outcomes.is_file():
            raise VerificationError("shard lacks a terminal list, output inventory, or outcome set")
        expected_raw = read_json(args.expected)
        expected = mutant_ids(expected_raw)
        observed = mutant_ids(read_json(args.observed))
        if expected != expected_ids or observed != expected_ids or mutant_counts(expected) != expected_counts or mutant_counts(observed) != expected_counts:
            raise VerificationError("cargo-mutants shard list/output disagrees with frozen inventory")
        terminal_records = terminal_outcome_records(read_json(args.outcomes), expected_raw, expected_ids)
        terminal_counts = outcome_counts(terminal_records)
    except (OSError, json.JSONDecodeError, VerificationError) as error:
        incomplete_reason = str(error)
    redacted_evidence = Path(args.redacted_evidence)
    redacted_evidence.mkdir(parents=True, exist_ok=True)
    write_json(
        redacted_evidence / "shard-evidence-manifest.json",
        {
            "schema": EVIDENCE_SCHEMA,
            "expected_mutant_ids": expected_ids,
            "expected_mutant_counts": expected_counts,
            "observed_mutant_ids": observed,
            "observed_mutant_counts": mutant_counts(observed) if observed is not None else None,
            "terminal_outcomes": terminal_records,
            "outcome_counts": terminal_counts,
            "incomplete_reason": incomplete_reason,
        },
    )
    evidence_present = True
    evidence_digest = directory_digest(redacted_evidence)
    receipt = {
        "schema": SHARD_SCHEMA,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "sha": args.sha,
        "tool_version": TOOL_VERSION,
        "config_digest": config_digest(),
        "inventory_digest": inventory["inventory_digest"],
        "baseline_digest": baseline["baseline_digest"],
        "shard": {"index": args.shard, "total": SHARD_COUNT, "sharding": SHARDING},
        "mutant_ids": expected_ids,
        "mutant_counts": expected_counts,
        "membership_digest": digest(expected_ids),
        "evidence_digest": evidence_digest,
        "artifact_digest": shard_artifact_digest(redacted_evidence),
        "evidence_present": evidence_present,
        "status": "success" if terminal_records is not None and args.exit_code == 0 else "failure" if terminal_records is not None else "incomplete",
        "cargo_exit_code": args.exit_code,
        "outcomes_complete": terminal_records is not None,
        "outcome_counts": terminal_counts,
        "incomplete_reason": incomplete_reason,
    }
    write_json(args.out, receipt)


def command_aggregate(args: argparse.Namespace) -> None:
    root = args.artifacts
    inventories: list[Any] = []
    baselines: list[Any] = []
    shard_paths: list[Path] = []
    shards: list[Any] = []
    downloaded: dict[tuple[int, int], dict[str, str]] = {}
    failure_reason: str | None = None
    try:
        inventories = [read_json(path) for path in sorted(root.rglob("inventory-manifest.json"))]
        baselines = [read_json(path) for path in sorted(root.rglob("baseline-receipt.json"))]
        shard_paths = sorted(root.rglob("shard-receipt.json"))
        shards = [read_json(path) for path in shard_paths]
        for receipt_path, shard in zip(shard_paths, shards, strict=True):
            shard_identity = shard.get("shard") if isinstance(shard, Mapping) else None
            if not isinstance(shard_identity, dict):
                raise VerificationError("downloaded shard receipt lacks shard identity")
            index = shard_identity.get("index")
            if isinstance(index, bool) or not isinstance(index, int):
                raise VerificationError("downloaded shard receipt has invalid shard index")
            attempt = require_attempt(shard.get("run_attempt"), "downloaded shard.run_attempt")
            key = (index, attempt)
            if key in downloaded:
                raise VerificationError(f"duplicate downloaded shard artifact for shard {index} attempt {attempt}")
            evidence = receipt_path.parent / "redacted-evidence"
            if not (evidence / "shard-evidence-manifest.json").is_file():
                raise VerificationError(f"downloaded evidence bytes are missing for shard {index} attempt {attempt}")
            downloaded[key] = {
                "evidence_digest": directory_digest(evidence),
                "artifact_digest": shard_artifact_digest(evidence),
            }
            validate_redacted_evidence(evidence, shard)
        receipt = aggregate_receipts(
            inventories,
            baselines,
            shards,
            args.sha,
            args.run_id,
            args.run_attempt,
            downloaded,
        )
    except (OSError, ValueError, TypeError, AttributeError) as error:
        failure_reason = str(error)
        received = sorted({shard.get("shard", {}).get("index") for shard in shards if isinstance(shard, Mapping) and isinstance(shard.get("shard"), Mapping) and isinstance(shard["shard"].get("index"), int) and not isinstance(shard["shard"].get("index"), bool)})
        inventory = next((item for item in inventories if isinstance(item, Mapping)), {})
        baseline = next((item for item in baselines if isinstance(item, Mapping)), {})
        observed_coverage: list[dict[str, Any]] = []
        outcome_totals = Counter()
        terminal_shards = 0
        terminal_mutants = 0
        for shard in shards:
            if not isinstance(shard, Mapping) or not isinstance(shard.get("shard"), Mapping):
                continue
            index = shard["shard"].get("index")
            if isinstance(index, bool) or not isinstance(index, int):
                continue
            ids = shard.get("mutant_ids")
            ids = ids if isinstance(ids, list) and all(isinstance(identity, str) for identity in ids) else []
            counts = shard.get("outcome_counts")
            valid_counts = (
                isinstance(counts, Mapping)
                and set(counts) == set(OUTCOME_COUNT_FIELDS)
                and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in counts.values())
                and sum(counts.values()) == len(ids)
            )
            complete = shard.get("outcomes_complete") is True and valid_counts
            if complete:
                terminal_shards += 1
                terminal_mutants += len(ids)
                for field in OUTCOME_COUNT_FIELDS:
                    outcome_totals[field] += counts[field]
            observed_coverage.append({"index": index, "mutants": len(ids), "outcomes_complete": complete})
        artifact_digests = [
            {"index": index, "run_attempt": attempt, **values}
            for (index, attempt), values in sorted(downloaded.items())
        ]
        inventory_ids = inventory.get("mutant_ids")
        expected_coverage = [
            {"index": index, "mutants": len(membership(inventory_ids, index)) if isinstance(inventory_ids, list) else None}
            for index in range(SHARD_COUNT)
        ]
        partial_outcomes = dict(sorted(outcome_totals.items())) if terminal_shards else None
        receipt = {
            "schema": AGGREGATE_SCHEMA,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "sha": args.sha,
            "tool_version": TOOL_VERSION,
            "config_digest": config_digest(),
            "shard_count": SHARD_COUNT,
            "expected_shards": list(range(SHARD_COUNT)),
            "received_shards": received,
            "missing_shards": sorted(set(range(SHARD_COUNT)) - set(received)),
            "inventory_digest": inventory.get("inventory_digest"),
            "baseline_digest": baseline.get("baseline_digest"),
            "expected_mutants": len(inventory_ids) if isinstance(inventory_ids, list) else None,
            "expected_shard_coverage": expected_coverage,
            "observed_shard_coverage": sorted(observed_coverage, key=lambda item: item["index"]),
            "expected_coverage_digest": digest(expected_coverage),
            "observed_mutants_with_terminal_outcomes": terminal_mutants,
            "observed_coverage_digest": digest(sorted(observed_coverage, key=lambda item: item["index"])),
            "terminal_shards": terminal_shards,
            "outcomes_complete": False,
            "outcome_counts": partial_outcomes,
            "outcome_digest": digest(partial_outcomes) if partial_outcomes is not None else None,
            "shard_artifact_digests": artifact_digests,
            "status": "failure",
            "failure_reason": str(error),
        }
    if failure_reason is None and receipt.get("status") != "success":
        failure_reason = "one or more shards failed or terminal mutation outcomes include survivors or timeouts"
        receipt["failure_reason"] = failure_reason
    write_json(args.out, receipt)
    if failure_reason is not None:
        raise VerificationError(failure_reason)


def command_select_latest(args: argparse.Namespace) -> None:
    receipts = [read_json(path) for path in args.artifacts.rglob(args.filename)]
    receipt = _latest_by_attempt(receipts, args.filename)
    write_json(args.out, receipt)


def command_verify_workflow(args: argparse.Namespace) -> None:
    text = args.workflow.read_text(encoding="utf-8")
    required = (
        "workflow_dispatch:",
        "contents: read",
        "actions: read",
        "github.repository_id == vars.CORELINK_SERVER_REPO_ID",
        "github.ref == 'refs/heads/main'",
        "github.ref_protected",
        "SHARD_COUNT: 27",
        "TOTAL_RUNNER_MINUTE_CAP: 8200",
        "HISTORICAL_RECONCILED_INVENTORY_OCCURRENCES: 24469",
        'test "$TOTAL_RUNNER_MINUTE_CAP" = 8200',
        'test "$HISTORICAL_RECONCILED_INVENTORY_OCCURRENCES" = 24469',
        'test "$TOTAL_RUNNER_MINUTE_CAP" -ge "$((10 + 35 + SHARD_COUNT * 45 + 10 + SHARD_COUNT * 255 + 10))"',
        "max-parallel: 9",
        "timeout-minutes: 45",
        "timeout-minutes: 255",
        "timeout-minutes: 240",
        "cargo mutants --workspace --no-config --no-shuffle --minimum-test-timeout=600 --sharding=round-robin --shard 0/1 --list --json",
        "cargo mutants --workspace --no-config --no-shuffle --minimum-test-timeout=600 --sharding=round-robin --shard ${{ matrix.shard }}/27 --list --json",
        "cargo mutants --workspace --no-config --no-shuffle --minimum-test-timeout=600 --jobs=8 --build-timeout=60 --timeout=60 --sharding=round-robin --shard ${{ matrix.shard }}/27 --baseline=skip --output \"$output\"",
        "--outcomes \"${RUNNER_TEMP}/mutants-shard-${{ matrix.shard }}/mutants.out/outcomes.json\"",
        "--redacted-evidence \"${RUNNER_TEMP}/redacted-evidence\"",
        "${{ runner.temp }}/redacted-evidence/",
        "cargo test --workspace --locked",
        "cargo test --workspace --locked --no-run --message-format=json",
        "cargo test --workspace --locked --no-run",
        "freeze complete unmutated workspace test mapping",
        "unmutated workspace baseline shard ${{ matrix.shard }}/27",
        "aggregate complete unmutated workspace baseline",
        "verify_i2478_mutants_baseline.py build-plan",
        "verify_i2478_mutants_baseline.py run-shard",
        "verify_i2478_mutants_baseline.py aggregate",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "verify_i2457_mutants_shards.py aggregate",
        "id: upload-aggregate-receipt",
        "steps.upload-aggregate-receipt.outputs.artifact-digest",
        "Record retained aggregate artifact digest",
        "re.fullmatch(r\"[0-9a-f]{64}\", digest)",
        "retention-days: 30",
        "cancel-in-progress: false",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise VerificationError("workflow is missing required #2457 controls: " + ", ".join(missing))
    if text.count("retention-days: 30") != 6 or text.count("retention-days:") != 6:
        raise VerificationError("workflow must retain each of the six bounded evidence artifacts for exactly 30 days")
    matrices = re.findall(r"(?ms)^      matrix:\n        shard: \[([^]]+)\]", text)
    expected_matrix = ", ".join(map(str, range(SHARD_COUNT)))
    if len(matrices) != 2 or any(matrix != expected_matrix for matrix in matrices):
        raise VerificationError("baseline and mutation matrices must each contain every deterministic shard exactly once")
    if text.count("max-parallel: 9") != 2:
        raise VerificationError("workflow must retain the reviewed nine-runner baseline and mutation concurrency")
    if text.count("timeout-minutes: 45") != 1 or text.count("timeout-minutes: 255") != 1 or text.count("timeout-minutes: 240") != 1:
        raise VerificationError("workflow must retain the 45-minute baseline, 240-minute command, and 255-minute shard caps")
    if text.count("--no-config") != 3:
        raise VerificationError("all three cargo-mutants inventory and shard commands must disable repository config")
    forbidden = (
        "self-hosted",
        "runs-on: corelink",
        "git push",
        "gh issue",
        "deploy",
        "publish",
        "schedule:",
        "pull_request:",
        "push:",
        "--baseline=run",
        "--sharding=slice",
        "${{ runner.temp }}/expected-shard.json",
        "${{ runner.temp }}/mutants-shard-",
    )
    found = [token for token in forbidden if token in text.lower()]
    if found:
        raise VerificationError("workflow contains forbidden execution or mutation controls: " + ", ".join(found))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("build-inventory")
    inventory.add_argument("--raw", type=Path, required=True)
    inventory.add_argument("--sha", required=True)
    inventory.add_argument("--run-id", required=True)
    inventory.add_argument("--run-attempt", type=int, required=True)
    inventory.add_argument("--out", type=Path, required=True)
    inventory.set_defaults(func=command_build_inventory)
    baseline = commands.add_parser("write-baseline")
    baseline.add_argument("--inventory", type=Path, required=True)
    baseline.add_argument("--sha", required=True)
    baseline.add_argument("--run-id", required=True)
    baseline.add_argument("--run-attempt", type=int, required=True)
    baseline.add_argument("--exit-code", type=int, required=True)
    baseline.add_argument("--out", type=Path, required=True)
    baseline.set_defaults(func=command_write_baseline)
    shard = commands.add_parser("write-shard")
    shard.add_argument("--inventory", type=Path, required=True)
    shard.add_argument("--baseline", type=Path, required=True)
    shard.add_argument("--expected", type=Path, required=True)
    shard.add_argument("--observed", type=Path, required=True)
    shard.add_argument("--outcomes", type=Path, required=True)
    shard.add_argument("--evidence", type=Path, required=True)
    shard.add_argument("--redacted-evidence", type=Path, required=True)
    shard.add_argument("--sha", required=True)
    shard.add_argument("--run-id", required=True)
    shard.add_argument("--run-attempt", type=int, required=True)
    shard.add_argument("--shard", type=int, required=True)
    shard.add_argument("--exit-code", type=int, required=True)
    shard.add_argument("--out", type=Path, required=True)
    shard.set_defaults(func=command_write_shard)
    aggregate = commands.add_parser("aggregate")
    aggregate.add_argument("--artifacts", type=Path, required=True)
    aggregate.add_argument("--sha", required=True)
    aggregate.add_argument("--run-id", required=True)
    aggregate.add_argument("--run-attempt", type=int, required=True)
    aggregate.add_argument("--out", type=Path, required=True)
    aggregate.set_defaults(func=command_aggregate)
    select = commands.add_parser("select-latest")
    select.add_argument("--artifacts", type=Path, required=True)
    select.add_argument("--filename", required=True)
    select.add_argument("--out", type=Path, required=True)
    select.set_defaults(func=command_select_latest)
    workflow = commands.add_parser("verify-workflow")
    workflow.add_argument("--workflow", type=Path, required=True)
    workflow.set_defaults(func=command_verify_workflow)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.func(args)
    except (OSError, json.JSONDecodeError, VerificationError) as error:
        print(f"#2457 mutants shards rejected: {error}", file=sys.stderr)
        return 1
    print("#2457 mutants shards: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
