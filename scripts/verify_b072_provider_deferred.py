#!/usr/bin/env python3
"""Static contract for the credentialless B-072 provider-deferred terminal receipt."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

CONTRACT = ROOT / "apps/synthetic-pager-worker/src/contract.ts"
RECEIVER = ROOT / "apps/synthetic-pager-worker/src/index.ts"
SCHEDULER = ROOT / "worker/src/index_schedule.ts"
MIGRATION = ROOT / "migrations/d1/0150_b072_provider_deferred_receipts.sql"
RECEIVER_CONFIG = ROOT / "apps/synthetic-pager-worker/wrangler.toml"

REQUIRED = {
    "explicit provider mode": '"pagerduty" | "provider_deferred"',
    "credentialless deferred validation": 'if (env.SYNTHETIC_DRILL_PROVIDER_MODE === "provider_deferred") return null;',
    "closed provider-mode values": '["pagerduty", "provider_deferred"]',
    "SHA validation": '!/^[0-9a-f]{40}$/i.test(page.serving_sha)',
    "deferred provenance binding": "worker_revision: env.SENTRY_RELEASE ?? \"\"",
    "receiver revision fail-closed": "receiverRevision === undefined || receiverRevision.length < 1 || receiverRevision.length > 200",
    "persist before terminal": "INSERT OR IGNORE INTO synthetic_page_provider_receipts",
    "audit on durable receipt": "INSERT OR IGNORE INTO synthetic_page_provider_audit_events",
    "receipt readback": "FROM synthetic_page_provider_receipts WHERE drill_id = ?",
    "replay equality": "persisted[key as keyof ProviderDeferredReceipt] === receipt[key as keyof ProviderDeferredReceipt]",
    "terminal output": 'outcome: "provider_deferred"',
    "deferred queue exclusion": "NOT EXISTS (SELECT 1 FROM synthetic_page_provider_receipts",
    "provider deferred no-send sweep": 'if (env.SYNTHETIC_DRILL_PROVIDER_MODE === "provider_deferred") return;',
    "scheduler terminality": 'terminalReceipt["terminal"] !== true',
    "scheduler correlation check": 'terminalReceipt["correlation_id"] !== `PAT-CORRELATION-ID-001:${deliveryId}`',
    "scheduler execution check": 'terminalReceipt["scheduled_at_ms"] !== controller.scheduledTime',
    "scheduler serving SHA check": 'terminalReceipt["serving_sha"] !== expectedServingSha',
    "scheduler receiver revision non-empty": 'terminalReceipt["receiver_worker_revision"].length < 1',
    "scheduler receiver revision max length": 'terminalReceipt["receiver_worker_revision"].length > 200',
}


def verify(contract: str, receiver: str, scheduler: str, migration: str, config: str) -> None:
    for label, fragment in REQUIRED.items():
        source = contract + receiver + scheduler
        if fragment not in source:
            raise AssertionError(f"missing {label}")
    for fragment in (
        "provider_mode           TEXT    NOT NULL CHECK (provider_mode = 'provider_deferred')",
        "outcome                 TEXT    NOT NULL CHECK (outcome = 'provider_deferred')",
        "serving_sha             TEXT    NOT NULL CHECK (length(serving_sha) = 40",
        "receiver_result         TEXT    NOT NULL CHECK (receiver_result = 'persisted_provider_deferred')",
        "event_type     TEXT NOT NULL CHECK (event_type = 'provider_deferred')",
        "source_event_id TEXT NOT NULL UNIQUE",
    ):
        if fragment not in migration:
            raise AssertionError(f"migration missing constrained field: {fragment}")
    if "workers_dev = false" not in config:
        raise AssertionError("receiver must disable workers.dev")
    if 'version_metadata = { binding = "CF_VERSION_METADATA" }' not in config:
        raise AssertionError("receiver must bind CF_VERSION_METADATA")
    if '[env.staging]' not in config or 'SYNTHETIC_DRILL_PROVIDER_MODE = "provider_deferred"' not in config:
        raise AssertionError("staging receiver must declare provider_deferred mode")
    if 'routes = [{ pattern = "staging.corelink.humangr.com/v1/webhooks/pagerduty"' in config:
        raise AssertionError("provider-deferred staging receiver must remain service-binding-only")


def main() -> None:
    verify(CONTRACT.read_text(), RECEIVER.read_text(), SCHEDULER.read_text(), MIGRATION.read_text(), RECEIVER_CONFIG.read_text())
    print("B-072 provider-deferred terminal receipt: PASS")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError) as error:
        print(f"B-072 provider-deferred terminal receipt: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
