#!/usr/bin/env python3
"""Dependency-free static guard for B-072 receiver/schedule wiring."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


def fail(message: str) -> None:
    raise AssertionError(message)


def _has_staging_deploy(deploy_source: str) -> bool:
    """Require env-bound input, an exact staging guard, and the deploy command."""
    return all(
        fragment in deploy_source
        for fragment in (
            "DEPLOY_ENV: ${{ inputs.environment }}",
            'if [[ "$DEPLOY_ENV" != "staging" ]]',
            'pnpm exec wrangler deploy --env "$DEPLOY_ENV"',
        )
    )


def main(root: Path) -> None:
    root_config = root / "wrangler.toml"
    staging_contract = root / "infra/staging/topology.json"
    receiver_config = root / "apps/synthetic-pager-worker/wrangler.toml"
    scheduler = root / "worker/src/index_schedule.ts"
    receiver = root / "apps/synthetic-pager-worker/src/index.ts"
    contract = root / "apps/synthetic-pager-worker/src/contract.ts"
    migration = root / "migrations/d1/0116_synthetic_page_delivery_lifecycle.sql"
    workspace = root / "pnpm-workspace.yaml"
    deploy_workflow = root / ".github/workflows/synthetic-pager-worker-deploy.yml"
    for path in (root_config, staging_contract, receiver_config, scheduler, receiver, contract, migration, workspace, deploy_workflow):
        if not path.is_file():
            fail(f"missing B-072 contract file: {path.relative_to(root)}")

    root_data = tomllib.loads(root_config.read_text())
    triggers = root_data.get("triggers", {}).get("crons", [])
    if triggers != []:
        fail(
            "root synthetic schedule must remain disabled until owner evidence exists, "
            f"got {triggers!r}"
        )
    root_receivers = [
        item
        for item in root_data.get("services", [])
        if item.get("binding") == "SCHEDULED_DRILL_DELIVERY"
    ]
    if root_receivers != [{"binding": "SCHEDULED_DRILL_DELIVERY", "service": "corelink-synthetic-pager"}]:
        fail("default/dev receiver service binding is missing or ambiguous")

    if "staging" in root_data.get("env", {}):
        fail("partial root staging environment is forbidden before provisioning")
    desired = json.loads(staging_contract.read_text())
    if desired.get("deployment_state") != "unprovisioned":
        fail("staging contract must remain unprovisioned before apply evidence")
    staging_bindings = desired.get("cloudflare", {}).get("service_bindings", [])
    if not any(
        item.get("binding") == "SCHEDULED_DRILL_DELIVERY"
        and item.get("worker") == "corelink-staging"
        and item.get("service") == "corelink-synthetic-pager-staging"
        for item in staging_bindings
    ):
        fail("staging receiver service binding is missing from desired-state contract")
    root_vars = desired.get("cloudflare", {}).get("root_worker_settings", {}).get("vars", {})
    if root_vars.get("SYNTHETIC_DRILL_ENABLED") != "false" or root_vars.get("SYNTHETIC_DRILL_PROVIDER_MODE") != "provider_deferred":
        fail("root staging provider-deferred mode is missing or activated")
    if root_vars.get("SENTRY_RELEASE") != {"source": "github_sha"}:
        fail("root staging release must come from the exact dispatch SHA")

    for environment in ("prod", "prod-sam", "prod-lhr", "prod-nrt", "prod-syd"):
        env_data = root_data.get("env", {}).get(environment, {})
        if env_data.get("triggers", {}).get("crons") != []:
            fail(f"{environment} does not explicitly disable schedules")
        if any(item.get("binding") == "SCHEDULED_DRILL_DELIVERY" for item in env_data.get("services", [])):
            fail(f"{environment} has an accidental synthetic receiver binding")

    receiver_data = tomllib.loads(receiver_config.read_text())
    if receiver_data.get("vars", {}).get("SYNTHETIC_DRILL_ENABLED") != "false":
        fail("receiver default activation is not fail-closed")
    for environment in ("staging", "prod"):
        env_data = receiver_data.get("env", {}).get(environment, {})
        if env_data.get("vars", {}).get("SYNTHETIC_DRILL_ENABLED") != "false":
            fail(f"receiver {environment} activation is not disabled")
    staging = receiver_data.get("env", {}).get("staging", {})
    if staging.get("vars", {}).get("SYNTHETIC_DRILL_PROVIDER_MODE") != "provider_deferred":
        fail("staging receiver provider mode is not deferred")
    if staging.get("routes", []) != []:
        fail("staging provider-deferred receiver must remain service-binding-only")
    if receiver_data.get("version_metadata", {}).get("binding") != "CF_VERSION_METADATA":
        fail("receiver version metadata binding is missing")
    if receiver_data.get("env", {}).get("prod", {}).get("routes") != []:
        fail("receiver production routes are not explicitly disabled")
    if receiver_data.get("triggers", {}).get("crons") != ["59 23 * * 1"]:
        fail("receiver deferred-delivery cron is missing")
    if receiver_data.get("env", {}).get("staging", {}).get("triggers", {}).get("crons") != ["59 23 * * 1"]:
        fail("staging deferred-delivery cron is missing")
    if receiver_data.get("env", {}).get("prod", {}).get("triggers", {}).get("crons") != []:
        fail("receiver production cron is not explicitly disabled")

    receiver_source = receiver.read_text()
    contract_source = contract.read_text()
    migration_source = migration.read_text()
    scheduler_source = scheduler.read_text()
    workspace_source = workspace.read_text()
    deploy_source = deploy_workflow.read_text()
    required_fragments = {
        "production environment guard": 'environment === "prod" || environment?.startsWith("prod-")',
        "activation gate": 'env.SYNTHETIC_DRILL_ENABLED !== "true"',
        "canonical endpoint gate": "env.PAGERDUTY_EVENTS_URL !== PAGERDUTY_EVENTS_URL",
        "routing-key gate": "PAGERDUTY_SYNTHETIC_ROUTING_KEY?.trim()",
        "header/payload correlation gate": "deliveryId !== envelope.synthetic_page.dedup_key",
        "scheduled timestamp identity": "page.dedup_key !== scheduledDrillId",
        "scheduled rotation identity": "page.rotation_week !== expectedRotation",
        "scheduled emit identity": "page.emit_at_ms !== expectedEmitAt",
        "PagerDuty non-2xx guard": "response === null || !response.ok",
        "D1-before-PagerDuty path": "await persistDelivery(env, envelope)",
        "no delivery claim before PagerDuty": "envelope.scheduled_at_ms,\n      null",
        "durable delivery receipt": "await markDelivered(env, deliveryId, envelope.synthetic_page.correlation_id, Date.now())",
        "deferred durability path": "delivery_mode = 'deferred'",
        "deferred undelivered filter": "delivered_at_ms IS NULL",
        "deferred acceptance-time receipt": "await markDelivered(env, row.drill_id, row.correlation_id, nowImpl())",
        "conditional delivery transition": "WHERE drill_id = ? AND delivered_at_ms IS NULL",
        "webhook signature gate": "verifyPagerDutySignature",
        "webhook delivery receipt gate": "row.delivered_at_ms === null",
        "webhook terminal race guard": "WHERE drill_id = ? AND outcome = 'unacked' AND delivered_at_ms IS NOT NULL",
        "webhook D1 outcome update": "SET outcome = ?, engineer_slug = ?, ack_ts_ms = ?, mtta_ms = ?, ack_vector = ?",
        "webhook persisted outcome readback": "SELECT outcome FROM synthetic_page_drills_b072 WHERE drill_id = ?",
        "webhook production gate": "validateWebhookEnvironment",
        "receiver unknown-cron gate": 'controller.cron !== "59 23 * * 1"',
        "receiver unknown-cron no-retry": "controller.noRetry()",
    }
    for label, fragment in required_fragments.items():
        combined_source = receiver_source + contract_source
        if label in {"production environment guard", "webhook production gate"}:
            if combined_source.count(fragment) < 2:
                fail(f"missing {label}")
            continue
        if fragment not in combined_source:
            fail(f"missing {label}")
    if receiver_source.count("WHERE drill_id = ? AND outcome = 'unacked' AND delivered_at_ms IS NOT NULL") < 2:
        fail("webhook event insert and outcome update must share the terminal race guard")
    for label, fragment in {
        "scheduler canonical delivery id": "const deliveryId = `SP-${controller.scheduledTime}`",
        "scheduler correlation id": "correlation_id: `PAT-CORRELATION-ID-001:${deliveryId}`",
        "scheduler retry on non-2xx": "if (!response.ok)",
    }.items():
        if fragment not in scheduler_source:
            fail(f"missing {label}")
    if "`SP-<13-digit scheduled timestamp>`" not in migration_source:
        fail("migration does not document canonical drill id/dedup format")
    if "apps/synthetic-pager-worker" not in workspace_source:
        fail("receiver package is not in the pnpm workspace")
    desired_routes = desired.get("cloudflare", {}).get("routes", [])
    if desired_routes != [{
        "worker": "corelink-staging",
        "pattern": "staging.corelink.humangr.com/*",
        "zone_name": "humangr.com",
    }]:
        fail("root must own the sole canonical staging wildcard route")
    if not re.search(r"(?m)^\s+workflow_dispatch:\s*$", deploy_source):
        fail("receiver deploy must be manually dispatched")
    if re.search(r"(?m)^\s+(push|pull_request|schedule):\s*$", deploy_source):
        fail("receiver deploy must not have an automatic trigger")
    for label, fragment in {
        "staging-only input": "options: [staging]",
        "staging environment": "environment: synthetic-drill-staging",
        "inert pre-deploy guard": "python3 scripts/verify_b072_receiver.py",
        "receiver typecheck": "pnpm run typecheck",
        "receiver lifecycle test": "pnpm run test",
        "terminal race test": "python3 scripts/test_b072_terminal_race.py",
    }.items():
        if fragment not in deploy_source:
            fail(f"missing {label}")
    if not _has_staging_deploy(deploy_source):
        fail("missing staging deploy")

    print("B-072 receiver/schedule guard: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        main(args.root.resolve())
    except (AssertionError, json.JSONDecodeError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"B-072 receiver/schedule guard: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
