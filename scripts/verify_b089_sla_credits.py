#!/usr/bin/env python3
"""Fail-closed repository guard for B-089.

This guard proves the repo-owned mechanics only.  It intentionally keeps B-089
parked: a live Stripe test-mode mutation and a subsequent invoice reconciliation
remain owner/provider evidence, not something a source grep can claim.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(root: Path = ROOT) -> dict[str, object]:
    failures: list[str] = []

    def need(path: str, needles: tuple[str, ...]) -> None:
        target = root / path
        if not target.is_file():
            failures.append(f"missing {path}")
            return
        body = target.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in body:
                failures.append(f"{path}: missing {needle}")

    need("apps/signup-worker/src/webhooks/sla_credit_cron.ts", (
        "publishClosedSlaMeasurements", "recordCanonicalSlaObservation", "handleSlaObservationIngest", "parseUtcMonth",
        "monthlyCutoffAtMs", "LIMIT ?", "state = 'pending'", "tenant_mapping_pending",
        "SLA_CREDITS_ENABLED", "provider_disabled", "Number.isSafeInteger", "BigInt",
        "sla_credit_outbox", "sla_credit_reconciliation", "db.batch",
        "Idempotency-Key", "Math.min(100, percent)", "attempts = attempts + 1",
        "x-corelink-sla-observation-key", "SLA_OBSERVATIONS_ENABLED", "stripe_reconcile_mismatch",
        "provider_recovery_reconcile_failed", "status = 'needs_review'",
    ))
    need("migrations/d1/0117_sla_credit_ledger.sql", (
        "sla_monthly_observations", "sla_monthly_measurements", "sla_credit_ledger",
        "sla_credit_outbox", "sla_credit_reconciliation", "sla_credit_audit_events",
        "UNIQUE (tenant_id, service_period)", "idempotency_key TEXT NOT NULL UNIQUE",
        "published_at_ms", "cutoff_at_ms", "next_attempt_at_ms", "lease_until_ms",
    ))
    need("apps/signup-worker/tests/sla_credit_cron.test.ts", (
        "does not starve a newer row", "mapping misses starve", "missing tenant mapping", "accepted provider object",
        "provider_disabled", "outbox and reconciliation", "canonical observation producer",
    ))
    need("apps/signup-worker/wrangler.toml", ("SLA_CREDITS_ENABLED = \"false\"", "SLA_OBSERVATIONS_ENABLED = \"false\"", "STRIPE_SECRET_KEY", "FOUR sweep families"))

    historical = root / "legal/sla/v1.0.0.md"
    draft = root / "legal/sla/v1.1.0.md"
    if not historical.is_file():
        failures.append("missing immutable historical legal/sla/v1.0.0.md")
    if not draft.is_file():
        failures.append("missing prelaunch legal/sla/v1.1.0.md draft")
    else:
        body = draft.read_text(encoding="utf-8")
        for required in (
            "DRAFT", "not effective", "Enterprise", "Free", "Solo", "Starter", "Pro", "Max",
            "SLA_CREDITS_ENABLED", "Stripe", "Counsel", "100%", "sole and exclusive remedy",
        ):
            if required.lower() not in body.lower():
                failures.append(f"legal/sla/v1.1.0.md: missing fail-closed policy marker {required}")
        for forbidden in ("issued automatically against the next invoice", "credits are issued automatically"):
            if forbidden.lower() in body.lower():
                failures.append(f"legal/sla/v1.1.0.md: active issuance promise is forbidden: {forbidden}")

    for path, required in (
        ("apps/docs/src/pages/legal/terms.tsx", ("No SLA service-credit program is currently active",)),
        ("marketing/sales/FAQ-MASTER.md", ("SLA service credits are not active for any tier today", "valid termination under that SLA")),
        ("apps/docs/src/pages/pricing.tsx", ("99.9% SLA + credits",)),
    ):
        target = root / path
        if not target.is_file():
            failures.append(f"missing {path}")
            continue
        source = target.read_text(encoding="utf-8").lower()
        for marker in required:
            present = marker.lower() in source
            if path.endswith("pricing.tsx"):
                if present:
                    failures.append("public pricing page reintroduced the inactive SLA-credit claim")
            elif not present:
                failures.append(f"{path}: missing inactive-credit guard {marker}")

    return {
        "ok": not failures,
        "failures": failures,
        "status": "parked_until_provider_proof",
        "post_deploy_proof_remaining": [
            "confirm migration 0117 is applied to the production D1 binding",
            "run one owner-approved Stripe test-mode invoice-item mutation with the gate enabled",
            "replay the same sweep and verify one provider object for the stable idempotency key",
            "reconcile the provider object against the next invoice and retain the D1 audit rows",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = verify(Path(args.root).resolve())
    if args.json:
        print(json.dumps(result, indent=2))
    elif result["ok"]:
        print("B-089 SLA-credit repository guard: PASS (parked until provider proof)")
        for item in result["post_deploy_proof_remaining"]:
            print(f"POST-DEPLOY: {item}")
    else:
        print("B-089 SLA-credit repository guard: FAIL")
        for failure in result["failures"]:
            print(f"FAIL: {failure}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
