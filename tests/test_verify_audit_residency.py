"""Behavior and mutation controls for scripts/verify_audit_residency.py."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "verify_audit_residency",
    Path(__file__).parents[1] / "scripts" / "verify_audit_residency.py",
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)

# Independently frozen from the producer slugs below, not derived from the
# verifier's allowlist (otherwise removing an event from both SQL and the test
# parameter population would silently pass).
EXPECTED_PUBLIC_EVENTS = (
    "corelink.cas.read.attempted",
    "corelink.cas.read.served",
    "corelink.cas.write.attempted",
    "corelink.cas.write.committed",
    "public.revoke",
    "corelink.signup.pilot_reserved.v1",
    "corelink.signup.pilot_token_rejected.v1",
    "corelink.signup.pilot_rate_limited.v1",
)


def test_public_allowlist_matches_independent_writer_slugs() -> None:
    assert set(verifier.PUBLIC_EVENTS) == set(EXPECTED_PUBLIC_EVENTS)
    source_root = Path(__file__).parents[1] / "crates" / "corelink-container" / "src"
    writer_sources = {
        source_root.parents[1] / "corelink-handler-cas" / "src" / "audit.rs": EXPECTED_PUBLIC_EVENTS[:4],
        source_root / "routes" / "public_revoke.rs": (EXPECTED_PUBLIC_EVENTS[4],),
        source_root / "routes" / "signup.rs": EXPECTED_PUBLIC_EVENTS[5:],
    }
    for path, slugs in writer_sources.items():
        source = path.read_text(encoding="utf-8")
        for slug in slugs:
            assert f'"{slug}"' in source, f"producer slug {slug} missing from {path}"


def response(**overrides: int) -> dict:
    row = {
        "total_rows": 10,
        "customer_rows": 10,
        "public_rows": 0,
        "reserved_public_rows": 0,
        "invalid_public_rows": 0,
        "satisfied_rows": 10,
        "violated_rows": 0,
        "unevaluable_rows": 0,
        "customer_unevaluable_rows": 0,
        "orphan_rows": 0,
        "orphan_tenants": 0,
        "erased_orphan_rows": 0,
        "erased_orphan_tenants": 0,
        "unexplained_orphan_rows": 0,
        "unexplained_orphan_tenants": 0,
        "weur_audit_rows": 0,
        "weur_orphan_rows": 0,
        "weur_tenants": 0,
        "erasure_log_rows": 1,
    }
    row.update(overrides)
    return {"success": True, "result": [{"success": True, "results": [row]}]}


def assess(payload: dict, environment: str = "production") -> tuple[str, str]:
    return verifier.assess(verifier.parse_d1_response(payload), environment=environment)


def sql_counts(
    *,
    include_mismatch: bool = False,
    include_orphan: bool = False,
    include_unexplained: bool = False,
    malformed_region: bool = False,
    public_region: str | None = None,
    public_event: str = "public.revoke",
) -> dict:
    """Execute the actual aggregate against a minimal D1-compatible SQLite schema."""
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT);
        CREATE TABLE audit_outbox (
            tenant_id TEXT NOT NULL, region TEXT,
            event_type TEXT NOT NULL DEFAULT 'corelink.cas.read.served'
        );
        CREATE TABLE dsr_erasure_log (tenant_id TEXT NOT NULL);
        INSERT INTO tenant VALUES ('tenant-e', 'enam');
        INSERT INTO audit_outbox (tenant_id, region) VALUES ('tenant-e', 'enam');
        INSERT INTO dsr_erasure_log VALUES ('erased-tenant');
        """
    )
    if include_mismatch:
        connection.execute("INSERT INTO tenant VALUES ('tenant-w', 'wnam')")
        connection.execute("INSERT INTO audit_outbox (tenant_id, region) VALUES ('tenant-w', 'enam')")
    if include_orphan:
        connection.execute("INSERT INTO audit_outbox (tenant_id, region) VALUES ('erased-tenant', 'weur')")
    if include_unexplained:
        connection.execute("INSERT INTO audit_outbox (tenant_id, region) VALUES ('unexplained-tenant', 'apac')")
    if malformed_region:
        connection.execute("INSERT INTO audit_outbox (tenant_id, region) VALUES ('tenant-e', 'unknown-region')")
    if public_region is not None:
        connection.execute(
            "INSERT INTO audit_outbox (tenant_id, region, event_type) VALUES ('_public', ?, ?)",
            (public_region, public_event),
        )
    row = connection.execute(verifier.RESIDENCY_SQL).fetchone()
    assert row is not None
    return dict(zip((field[0] for field in connection.execute(verifier.RESIDENCY_SQL).description), row, strict=True))


def test_complete_population_with_only_satisfied_rows_is_compliant() -> None:
    assert assess(response())[0] == "COMPLIANT"


def test_sql_classifies_a_matching_tenant_as_satisfied() -> None:
    # Mutation control: changing equality in RESIDENCY_SQL makes this red.
    counts = sql_counts()
    assert counts["total_rows"] == 1
    assert counts["satisfied_rows"] == 1
    assert counts["violated_rows"] == 0
    assert counts["unevaluable_rows"] == 0


def test_known_cross_region_mismatch_fails() -> None:
    # Mutation control: changing only this count to zero makes this test fail.
    assert assess(response(satisfied_rows=9, violated_rows=1))[0] == "FAILED"


def test_sql_keeps_mismatch_and_erased_orphan_in_distinct_failing_buckets() -> None:
    counts = sql_counts(include_mismatch=True, include_orphan=True)
    assert counts["total_rows"] == 3
    assert counts["satisfied_rows"] == 1
    assert counts["violated_rows"] == 1
    assert counts["unevaluable_rows"] == 1
    assert counts["erased_orphan_rows"] == 1
    assert counts["unexplained_orphan_rows"] == 0


def test_sql_accounts_for_reserved_public_without_laundering_customer_orphans() -> None:
    counts = sql_counts(include_orphan=True, public_region="wnam")
    assert counts["total_rows"] == 3
    assert counts["customer_rows"] == 2
    assert counts["public_rows"] == counts["reserved_public_rows"] == 1
    assert counts["invalid_public_rows"] == 0
    assert counts["orphan_rows"] == counts["erased_orphan_rows"] == 1
    assert counts["customer_unevaluable_rows"] == counts["unevaluable_rows"] == 1


@pytest.mark.parametrize("event", EXPECTED_PUBLIC_EVENTS)
def test_canonical_public_event_in_wnam_is_reserved(event: str) -> None:
    counts = sql_counts(public_region="wnam", public_event=event)
    assert counts["total_rows"] == 2
    assert counts["reserved_public_rows"] == 1
    assert counts["unevaluable_rows"] == 0
    assert counts["orphan_rows"] == 0


@pytest.mark.parametrize(
    ("region", "event"),
    [("weur", "public.revoke"), ("wnam", "corelink.dsr.access"),
     ("weur", "corelink.dsr.access")],
)
def test_public_wrong_region_or_event_remains_visible_and_fails(region: str, event: str) -> None:
    counts = sql_counts(public_region=region, public_event=event)
    assert counts["public_rows"] == counts["invalid_public_rows"] == 1
    assert counts["reserved_public_rows"] == 0
    assert counts["unevaluable_rows"] == 1
    assert counts["orphan_rows"] == 0
    assert verifier.assess(verifier.Counts(**counts), environment="production")[0] == "FAILED"


def test_public_rows_do_not_make_customer_residual_compliant() -> None:
    payload = response(
        total_rows=4, customer_rows=3, public_rows=1,
        reserved_public_rows=1, satisfied_rows=2,
        unevaluable_rows=1, customer_unevaluable_rows=1,
        orphan_rows=1, orphan_tenants=1,
        unexplained_orphan_rows=1, unexplained_orphan_tenants=1,
    )
    assert assess(payload)[0] == "FAILED"


def test_sql_classifies_unknown_region_as_unevaluable_not_satisfied() -> None:
    counts = sql_counts(malformed_region=True)
    assert counts["total_rows"] == 2
    assert counts["satisfied_rows"] == 1
    assert counts["unevaluable_rows"] == 1


ERASED_ONLY = dict(
    satisfied_rows=9,
    unevaluable_rows=1,
    customer_unevaluable_rows=1,
    orphan_rows=1,
    orphan_tenants=1,
    erased_orphan_rows=1,
    erased_orphan_tenants=1,
)


def test_retained_dsr_orphan_is_a_documented_exception_never_compliant() -> None:
    # #1669 policy B (owner decision 2026-10-01): a DSR-erased orphan is retained
    # Art. 5(2) evidence in its own erased-lineage state. It is not unevaluable,
    # not non-compliant, and never satisfied or COMPLIANT.
    counts = verifier.parse_d1_response(response(**ERASED_ONLY))
    state, reason = verifier.assess(counts, environment="production")
    assert state == "DOCUMENTED_EXCEPTION"
    assert state != "COMPLIANT"
    assert "policy B" in reason
    assert verifier.partition(counts) == {
        "satisfied": 9,
        "violated": 0,
        "erased_lineage_exception": 1,
        "owner_attested_prelaunch_test_traffic": 0,
        "unevaluable": 0,
        "reserved_public": 0,
    }


@pytest.mark.parametrize(
    ("extra", "failing_state"),
    [
        # One unexplained orphan beside the erased one: the exception must not
        # absorb it (it is an orphan WITHOUT a dsr_erasure_log row).
        (dict(satisfied_rows=8, unevaluable_rows=2, customer_unevaluable_rows=2, orphan_rows=2,
              orphan_tenants=2, unexplained_orphan_rows=1, unexplained_orphan_tenants=1), "unevaluable"),
        # A non-orphan unevaluable customer row (unknown region).
        (dict(satisfied_rows=8, unevaluable_rows=2, customer_unevaluable_rows=2), "unevaluable"),
        # A known cross-region violation.
        (dict(satisfied_rows=8, violated_rows=1), "violated"),
        # An invalid _public row.
        (dict(total_rows=11, public_rows=1, invalid_public_rows=1, unevaluable_rows=2), "unevaluable"),
    ],
)
def test_erased_lineage_exception_does_not_absorb_any_other_failing_row(extra: dict, failing_state: str) -> None:
    counts = verifier.parse_d1_response(response(**{**ERASED_ONLY, **extra}))
    state, reason = verifier.assess(counts, environment="production")
    assert state == "FAILED"
    assert reason == verifier.FAILED_REASON
    states = verifier.partition(counts)
    assert states["erased_lineage_exception"] == 1
    assert states[failing_state] == 1


def test_sql_erased_orphan_end_to_end_is_documented_exception() -> None:
    counts = verifier.Counts(**sql_counts(include_orphan=True))
    assert counts.unevaluable_rows == counts.erased_orphan_rows == 1
    assert verifier.assess(counts, environment="production")[0] == "DOCUMENTED_EXCEPTION"
    assert verifier.partition(counts)["erased_lineage_exception"] == 1
    assert verifier.partition(counts)["unevaluable"] == 0


def test_sql_unexplained_orphan_beside_erased_orphan_still_fails() -> None:
    counts = verifier.Counts(**sql_counts(include_orphan=True, include_unexplained=True))
    assert counts.erased_orphan_rows == 1
    assert counts.unexplained_orphan_rows == 1
    assert verifier.assess(counts, environment="production")[0] == "FAILED"
    assert verifier.partition(counts) == {
        "satisfied": 1,
        "violated": 0,
        "erased_lineage_exception": 1,
        "owner_attested_prelaunch_test_traffic": 0,
        "unevaluable": 1,
        "reserved_public": 0,
    }


# Row/tenant aggregates published on #1669 for retained production receipt
# 35697251287. The weur_* and erasure_log_rows values are NOT from that receipt;
# they are placeholders that satisfy the partition invariants.
RETAINED_PRODUCTION_COUNTS = dict(
    total_rows=84985, customer_rows=84854, public_rows=131, reserved_public_rows=131,
    invalid_public_rows=0, satisfied_rows=81315, violated_rows=0, unevaluable_rows=3539,
    customer_unevaluable_rows=3539, orphan_rows=3539, orphan_tenants=174,
    erased_orphan_rows=3526, erased_orphan_tenants=170, unexplained_orphan_rows=13,
    unexplained_orphan_tenants=4, weur_audit_rows=4, weur_orphan_rows=4, weur_tenants=0,
    erasure_log_rows=2044,
)


def test_retained_production_population_fails_on_the_13_unexplained_rows_only() -> None:
    counts = verifier.Counts(**RETAINED_PRODUCTION_COUNTS)
    assert verifier.assess(counts, environment="production") == ("FAILED", verifier.FAILED_REASON)
    assert verifier.partition(counts) == {
        "satisfied": 81315,
        "violated": 0,
        "erased_lineage_exception": 3526,
        "owner_attested_prelaunch_test_traffic": 0,
        "unevaluable": 13,
        "reserved_public": 131,
    }


def test_partition_refuses_erased_rows_outside_the_customer_unevaluable_bucket() -> None:
    counts = verifier.Counts(**{**response(**ERASED_ONLY)["result"][0]["results"][0],
                                "customer_unevaluable_rows": 0, "unevaluable_rows": 0,
                                "satisfied_rows": 10})
    with pytest.raises(verifier.Indeterminate, match="erased-lineage rows exceed"):
        verifier.partition(counts)


def test_partition_refuses_states_that_do_not_conserve_the_population() -> None:
    # partition() is public; it must fail closed even when called without assess().
    counts = verifier.Counts(**{**response(**ERASED_ONLY)["result"][0]["results"][0], "total_rows": 11})
    with pytest.raises(verifier.Indeterminate, match="do not equal the full audit_outbox population"):
        verifier.partition(counts)


@pytest.mark.parametrize(
    ("overrides", "status", "code"),
    [({}, "COMPLIANT", 0), (ERASED_ONLY, "DOCUMENTED_EXCEPTION", 0),
     ({**ERASED_ONLY, "satisfied_rows": 8, "violated_rows": 1}, "FAILED", 1)],
)
def test_cli_exit_code_and_states_follow_policy_b(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], overrides: dict, status: str, code: int
) -> None:
    evidence = tmp_path / "d1-response.json"
    evidence.write_text(json.dumps(response(**overrides)), encoding="utf-8")
    assert verifier.main(["--environment", "production", "--input", str(evidence)]) == code
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == status
    assert sum(report["states"].values()) == report["counts"]["total_rows"]
    assert report["states"]["erased_lineage_exception"] == report["counts"]["erased_orphan_rows"]
    assert "policy B" in report["exception_policy"]
    # Without residual references the owner attestation is never applied.
    assert report["attestation"] is None


# --- owner-attested prelaunch test traffic (owner decision 2026-10-02) -------

ATTESTED = "owner_attested_prelaunch_test_traffic"
AUTHORITY = "https://github.com/HuGR-dev/corelink-server/issues/1669#issuecomment-5959812722"
LEDGER_PATH = Path(__file__).parents[1] / "scripts" / "i1669_owner_attested_rows.json"


def ledger_of(*row_ids: str) -> "verifier.Ledger":
    return verifier.Ledger(refs=frozenset(verifier.row_ref(i) for i in row_ids), sha256="e" * 64)


THIRTEEN = tuple(f"synthetic-row-{n:02d}" for n in range(13))


def production_with_unexplained(unexplained: int, **extra: int) -> "verifier.Counts":
    base = dict(RETAINED_PRODUCTION_COUNTS)
    delta = unexplained - base["unexplained_orphan_rows"]
    base.update(
        unexplained_orphan_rows=unexplained,
        orphan_rows=base["orphan_rows"] + delta,
        customer_unevaluable_rows=base["customer_unevaluable_rows"] + delta,
        unevaluable_rows=base["unevaluable_rows"] + delta,
        satisfied_rows=base["satisfied_rows"] - delta,
    )
    base.update(extra)
    return verifier.Counts(**base)


def test_repository_ledger_is_exactly_13_opaque_refs_citing_the_owner_decision() -> None:
    ledger = verifier.load_ledger()
    assert len(ledger.refs) == 13
    data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    assert data["authority"] == AUTHORITY
    assert data["category"] == ATTESTED
    assert data["log_confirmed"] is False
    assert all(len(ref) == 64 and set(ref) <= set("0123456789abcdef") for ref in data["refs"])
    # Opaque: no UUID-shaped tenant/row identifier anywhere in the ledger.
    import re

    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", LEDGER_PATH.read_text())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["refs"].append("0" * 64),  # a 14th reference
        lambda d: d["refs"].pop(),  # only 12
        lambda d: d.__setitem__("refs", d["refs"][:12] + d["refs"][:1]),  # duplicate
        lambda d: d.__setitem__("authority", "https://example.invalid/decision"),
        lambda d: d.__setitem__("log_confirmed", True),
        lambda d: d.__setitem__("category", "satisfied"),
        lambda d: d.__setitem__("tenant_ids", []),  # unexpected field
        lambda d: d["refs"].__setitem__(0, "not-a-hash"),
    ],
)
def test_ledger_is_rejected_unless_it_is_exactly_the_recorded_decision(tmp_path: Path, mutate) -> None:
    data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verifier.Indeterminate):
        verifier.load_ledger(path)


def test_row_ref_is_domain_separated_sha256() -> None:
    import hashlib

    assert verifier.row_ref("x") != hashlib.sha256(b"x").hexdigest()
    assert verifier.row_ref("x") == verifier.row_ref("x") != verifier.row_ref("y")


def test_all_13_attested_with_erased_lineage_is_documented_exception_never_compliant() -> None:
    counts = production_with_unexplained(13)
    attestation = verifier.attest([verifier.row_ref(i) for i in THIRTEEN], ledger_of(*THIRTEEN))
    state, reason = verifier.assess(counts, environment="production", attestation=attestation)
    assert state == "DOCUMENTED_EXCEPTION" != "COMPLIANT"
    assert "not log-confirmed" in reason
    states = verifier.partition(counts, attestation)
    assert states == {
        "satisfied": 81315,
        "violated": 0,
        "erased_lineage_exception": 3526,
        ATTESTED: 13,
        "unevaluable": 0,
        "reserved_public": 131,
    }
    summary = attestation.summary()
    assert summary["authority"] == AUTHORITY and summary["log_confirmed"] is False
    assert (summary["attested_rows"], summary["unattested_rows"], summary["attested_refs_missing"]) == (13, 0, 0)


def test_attested_only_population_is_still_never_compliant() -> None:
    counts = verifier.Counts(**{**response(**ERASED_ONLY)["result"][0]["results"][0],
                                "erased_orphan_rows": 0, "erased_orphan_tenants": 0,
                                "unexplained_orphan_rows": 1, "unexplained_orphan_tenants": 1})
    attestation = verifier.attest([verifier.row_ref("only")], ledger_of("only"))
    assert verifier.assess(counts, environment="production", attestation=attestation)[0] == "DOCUMENTED_EXCEPTION"


def test_a_14th_unexplained_row_outside_the_ledger_still_fails() -> None:
    counts = production_with_unexplained(14)
    refs = [verifier.row_ref(i) for i in (*THIRTEEN, "a-fourteenth-row")]
    attestation = verifier.attest(refs, ledger_of(*THIRTEEN))
    assert verifier.assess(counts, environment="production", attestation=attestation) == (
        "FAILED", verifier.FAILED_REASON)
    states = verifier.partition(counts, attestation)
    assert (states[ATTESTED], states["unevaluable"]) == (13, 1)


def test_an_attested_reference_missing_from_the_residual_is_reported_and_fails() -> None:
    counts = production_with_unexplained(12)
    attestation = verifier.attest([verifier.row_ref(i) for i in THIRTEEN[:12]], ledger_of(*THIRTEEN))
    assert attestation.summary()["attested_refs_missing"] == 1
    assert verifier.assess(counts, environment="production", attestation=attestation) == (
        "FAILED", verifier.ATTESTED_MISSING_REASON)


def test_attestation_does_not_absorb_a_violation() -> None:
    counts = production_with_unexplained(13, satisfied_rows=81314, violated_rows=1)
    attestation = verifier.attest([verifier.row_ref(i) for i in THIRTEEN], ledger_of(*THIRTEEN))
    assert verifier.assess(counts, environment="production", attestation=attestation)[0] == "FAILED"


def test_residual_references_must_reconcile_with_the_unexplained_count() -> None:
    counts = production_with_unexplained(13)
    attestation = verifier.attest([verifier.row_ref(i) for i in THIRTEEN[:12]], ledger_of(*THIRTEEN[:12]))
    with pytest.raises(verifier.Indeterminate, match="do not reconcile"):
        verifier.assess(counts, environment="production", attestation=attestation)


def residual_db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE tenant (tenant_id TEXT PRIMARY KEY, primary_region TEXT);
        CREATE TABLE audit_outbox (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, region TEXT,
                                   event_type TEXT NOT NULL DEFAULT 'customer.event');
        CREATE TABLE dsr_erasure_log (tenant_id TEXT NOT NULL);
        INSERT INTO tenant VALUES ('live', 'enam');
        INSERT INTO dsr_erasure_log VALUES ('erased');
        INSERT INTO audit_outbox (id, tenant_id, region) VALUES ('row-live', 'live', 'enam');
        INSERT INTO audit_outbox (id, tenant_id, region) VALUES ('row-erased', 'erased', 'weur');
        INSERT INTO audit_outbox (id, tenant_id, region, event_type)
            VALUES ('row-public', '_public', 'wnam', 'public.revoke');
        INSERT INTO audit_outbox (id, tenant_id, region) VALUES ('row-u1', 'gone', 'apac');
        INSERT INTO audit_outbox (id, tenant_id, region) VALUES ('row-u2', 'gone', 'apac');
        """
    )
    return connection


def d1(rows: list[dict]) -> dict:
    return {"success": True, "result": [{"success": True, "results": rows}]}


def test_residual_refs_sql_selects_exactly_the_unexplained_orphans() -> None:
    connection = residual_db()
    rows = [{"audit_row_id": r[0]} for r in connection.execute(verifier.RESIDUAL_REFS_SQL)]
    assert rows == [{"audit_row_id": "row-u1"}, {"audit_row_id": "row-u2"}]
    counts = verifier.Counts(**dict(zip((c[0] for c in connection.execute(verifier.RESIDENCY_SQL).description),
                                        connection.execute(verifier.RESIDENCY_SQL).fetchone(), strict=True)))
    assert counts.unexplained_orphan_rows == len(rows)
    assert verifier.parse_residual_refs(d1(rows)) == tuple(sorted(verifier.row_ref(r["audit_row_id"]) for r in rows))


@pytest.mark.parametrize(
    "rows",
    [
        [{"audit_row_id": "a", "tenant_id": "leak"}],
        [{"audit_row_id": ""}],
        [{"audit_row_id": 7}],
        [{"audit_row_id": "a"}, {"audit_row_id": "a"}],
        [{"audit_row_id": f"r{n}"} for n in range(65)],
    ],
)
def test_residual_parse_fails_closed(rows: list[dict]) -> None:
    with pytest.raises(verifier.Indeterminate):
        verifier.parse_residual_refs(d1(rows))


def test_cli_applies_the_attestation_without_printing_row_ids(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = residual_db()
    residency = dict(zip((c[0] for c in connection.execute(verifier.RESIDENCY_SQL).description),
                         connection.execute(verifier.RESIDENCY_SQL).fetchone(), strict=True))
    residual = [{"audit_row_id": r[0]} for r in connection.execute(verifier.RESIDUAL_REFS_SQL)]
    (tmp_path / "residency.json").write_text(json.dumps(d1([residency])), encoding="utf-8")
    (tmp_path / "residual.json").write_text(json.dumps(d1(residual)), encoding="utf-8")
    monkeypatch.setattr(verifier, "load_ledger", lambda: ledger_of("row-u1", "row-u2"))
    code = verifier.main(["--environment", "production", "--input", str(tmp_path / "residency.json"),
                          "--residual-refs-input", str(tmp_path / "residual.json")])
    out = capsys.readouterr().out
    report = json.loads(out)
    assert (code, report["status"]) == (0, "DOCUMENTED_EXCEPTION")
    assert report["states"][ATTESTED] == 2 and report["states"]["erased_lineage_exception"] == 1
    assert report["attestation"]["attested_rows"] == 2
    assert "row-u1" not in out and "gone" not in out


def test_cli_residual_input_requires_the_residency_input(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exited:
        verifier.main(["--environment", "test", "--database-id", "x", "--residual-refs-input", str(tmp_path / "r")])
    assert exited.value.code == 2


def test_unexplained_orphan_and_weur_orphan_remain_in_the_denominator() -> None:
    payload = response(
        satisfied_rows=9,
        unevaluable_rows=1,
        customer_unevaluable_rows=1,
        orphan_rows=1,
        orphan_tenants=1,
        unexplained_orphan_rows=1,
        unexplained_orphan_tenants=1,
        weur_audit_rows=1,
        weur_orphan_rows=1,
    )
    state, _ = assess(payload)
    assert state == "FAILED"


def test_staging_without_orphans_can_use_an_empty_dsr_control() -> None:
    assert assess(response(erasure_log_rows=0), environment="staging")[0] == "COMPLIANT"


def test_missing_evidence_source_is_indeterminate() -> None:
    with pytest.raises(SystemExit) as exited:
        verifier.main(["--environment", "test"])
    assert exited.value.code == 2


@pytest.mark.parametrize("result_success", [False, None, 0, 1, "true"])
def test_result_set_success_must_be_exact_boolean_true(result_success: object) -> None:
    payload = response()
    payload["result"][0]["success"] = result_success
    with pytest.raises(verifier.Indeterminate):
        verifier.parse_d1_response(payload)


def test_result_set_success_is_required() -> None:
    payload = response()
    del payload["result"][0]["success"]
    with pytest.raises(verifier.Indeterminate):
        verifier.parse_d1_response(payload)


def test_aggregate_row_must_contain_only_the_allowlisted_counts() -> None:
    payload = response()
    payload["result"][0]["results"][0]["tenant_id"] = "row-level-identity-must-not-be-accepted"

    with pytest.raises(verifier.Indeterminate, match="fields are missing or unexpected"):
        verifier.parse_d1_response(payload)


@pytest.mark.parametrize("result_success", [False, None, 0, 1, "true"])
def test_incomplete_result_set_evidence_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], result_success: object
) -> None:
    payload = response()
    payload["result"][0]["success"] = result_success
    evidence = tmp_path / "d1-response.json"
    evidence.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit) as exited:
        verifier.main(["--environment", "production", "--input", str(evidence)])

    assert exited.value.code == 2
    assert "status=INDETERMINATE" in capsys.readouterr().err


@pytest.mark.parametrize(
    "payload",
    [
        response(total_rows=0, satisfied_rows=0),
        response(total_rows=10, customer_rows=9),
        response(public_rows=1),
        response(customer_rows=9, public_rows=1),
        response(total_rows=10, customer_rows=9, public_rows=1, reserved_public_rows=1),
        response(total_rows=10, satisfied_rows=9),
        response(orphan_rows=1),
        response(orphan_tenants=1),
        response(erasure_log_rows=0),
        {"success": True, "result": [{"success": True, "results": [{}]}]},
    ],
)
def test_empty_partial_or_malformed_evidence_is_indeterminate(payload: dict) -> None:
    with pytest.raises(verifier.Indeterminate):
        assess(payload)


def test_query_uses_left_join_exists_customer_states_and_reserved_public() -> None:
    # Source-level negative control for the old INNER JOIN / multiplicative DSR join.
    sql = verifier.RESIDENCY_SQL.lower()
    assert "left join tenant" in sql
    assert "exists (" in sql
    assert "'satisfied'" in sql and "'violated'" in sql and "'unevaluable'" in sql
    assert "'reserved_public'" in sql
    assert "join dsr_erasure_log" not in sql
