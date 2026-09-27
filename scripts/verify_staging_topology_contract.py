#!/usr/bin/env python3
"""Fail-closed desired-state guard for the unprovisioned staging topology."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


CONTRACT = Path("infra/staging/topology.json")
RECEIPT = Path("evidence/owner-actions/B-029/staging-base-resources.json")
ROOT_WRANGLER = Path("wrangler.toml")
LOAD_WORKFLOW = Path(".github/workflows/load-test-nightly.yml")
ENDURANCE_WORKFLOW = Path(".github/workflows/endurance-2h-nightly.yml")
SYNTHETIC_RECEIVER_WRANGLER = Path("apps/synthetic-pager-worker/wrangler.toml")
SIGNUP_WRANGLER = Path("apps/signup-worker/wrangler.toml")
CANONICAL_ORIGIN = "https://staging.corelink.humangr.com"
CONFIG_DB_ID = "d72a6b39-6a48-4338-bfda-1111dda98604"
KV_NAMESPACE_IDS = {
    "corelink-metadata-staging": "558e939750fa4e09a7aeca8bebcf9777",
    "corelink-clerk-jwks-staging": "77f2ddcfe36d42c5a7c5eb1d7bba1e82",
    "corelink-negative-cache-staging": "cdc815918f0642e8bfb393048879bbe3",
}
QUEUE_IDS = {
    "queue_id": "18fb0837cecd4dddacf2c0ddea196910",
    "dead_letter_queue_id": "51565488711a404d9395512b2442157d",
}

EXPECTED = {
    "workers": {
        "root_worker": "corelink-staging",
        "signup_worker": "corelink-signup-staging",
        "synthetic_receiver_worker": "corelink-synthetic-pager-staging",
    },
    "d1": {
        (
            "corelink-config-staging",
            "migrations/d1",
            (
                ("corelink-signup-staging", "BILLING_DB"),
                ("corelink-signup-staging", "CONFIG_DB"),
                ("corelink-staging", "CONFIG_DB"),
                ("corelink-synthetic-pager-staging", "CONFIG_DB"),
            ),
        )
    },
    "r2": {
        ("corelink-staging", "CAS_BUCKET", "corelink-cas-staging"),
        ("corelink-staging", "AC_BUCKET_IAD", "corelink-ac-iad-staging"),
        ("corelink-staging", "CHUNK_BUCKET_IAD", "corelink-chunk-iad-staging"),
        ("corelink-staging", "MANIFEST_BUCKET_IAD", "corelink-manifest-iad-staging"),
    },
    "kv": {
        ("corelink-staging", "METADATA_KV", "corelink-metadata-staging"),
        ("corelink-staging", "CLERK_JWKS_KV", "corelink-clerk-jwks-staging"),
        ("corelink-staging", "NEGATIVE_CACHE_KV", "corelink-negative-cache-staging"),
    },
    "do": {
        ("corelink-staging", "CORELINK_SERVER", "CoreLinkServer"),
        ("corelink-staging", "ROLLOUT_DO", "RolloutController"),
        ("corelink-staging", "EVENT_LOG_DO", "EventLogDO"),
        ("corelink-staging", "REPLICATION_COORDINATOR_DO", "ReplicationCoordinatorDO"),
        ("corelink-staging", "REQUEST_METER_COORDINATOR_DO", "RequestMeterCoordinatorDO"),
        ("corelink-staging", "REQUEST_METER_SHARD_DO", "RequestMeterShardDO"),
    },
    "queues": {
        ("DSR_QUEUE", "corelink-dsr-erasure-staging", "corelink-dsr-erasure-dlq-staging", "corelink-signup-staging")
    },
    "services": {
        ("corelink-staging", "SCHEDULED_DRILL_DELIVERY", "corelink-synthetic-pager-staging"),
        ("corelink-signup-staging", "CORELINK_API_SVC", "corelink-staging"),
    },
}

EXPECTED_ROOT_SETTINGS = {
    "main": "worker/src/index.ts",
    "workers_dev": False,
    "compatibility_date": "2026-04-01",
    "compatibility_flags": ["nodejs_compat"],
    "crons": [],
    "observability": {"enabled": True, "head_sampling_rate": 1},
    "vars": {
        "ENVIRONMENT": "staging",
        "R2_S3_ENDPOINT": {"source": "provider_output", "name": "r2_s3_endpoint"},
        "D1_DATABASE_ID": CONFIG_DB_ID,
        "R2_AC_BUCKET": "corelink-ac-iad-staging",
        "R2_AC_REGION": "iad",
        "R2_CAS_BUCKET": "corelink-cas-staging",
        "R2_CAS_REGION": "iad",
        "R2_CHUNK_BUCKET": "corelink-chunk-iad-staging",
        "R2_CHUNK_REGION": "iad",
        "EDGE_PUBLIC_READ": "shadow",
        "EDGE_ASYNC_METER": "off",
        "EDGE_DO_METER": "off",
        "OCI_PUBLIC_DEDUP_ENABLED": "0",
        "OCI_UPSTREAM_ON_MISS": "0",
        "AUDIT_DRAIN_BATCH_LIMIT": "512",
        "AUDIT_DRAIN_LEASE_ENABLED": "1",
        "EDGE_FIND_MISSING": "off",
        "SYNTHETIC_DRILL_ENABLED": "false",
        "SYNTHETIC_DRILL_PROVIDER_MODE": "provider_deferred",
        "SENTRY_RELEASE": {"source": "github_sha"},
    },
}

EXPECTED_SIGNUP_SETTINGS = {
    "main": "apps/signup-worker/src/index.ts",
    "workers_dev": False,
    "compatibility_date": "2026-05-01",
    "compatibility_flags": ["nodejs_compat"],
    "crons": ["0 * * * *"],
    "vars": {
        "CORELINK_API_BASE": CANONICAL_ORIGIN,
        "ENVIRONMENT": "staging",
        "SLA_CREDITS_ENABLED": "false",
        "SLA_OBSERVATIONS_ENABLED": "false",
    },
}

EXPECTED_RECEIVER_SETTINGS = {
    "main": "apps/synthetic-pager-worker/src/index.ts",
    "workers_dev": False,
    "compatibility_date": "2026-04-01",
    "compatibility_flags": [],
    "crons": ["59 23 * * 1"],
    "vars": {
        "ENVIRONMENT": "staging",
        "SYNTHETIC_DRILL_ENABLED": "false",
        "SYNTHETIC_DRILL_PROVIDER_MODE": "provider_deferred",
    },
}

EXPECTED_SECRETS = {
    "corelink-staging": {
        "CF_API_TOKEN", "CLERK_ISSUER_URL", "CLERK_SECRET_KEY",
        "CLOUDFLARE_ACCOUNT_ID", "CORELINK_ADMIN_AUTH_KEY",
        "CORELINK_ERASE_AUTH_KEY", "CORELINK_INTERNAL_AUTH_KEY",
        "PAT_SIGNING_KEY", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
    },
    "corelink-signup-staging": {
        "CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET", "CORELINK_ERASE_AUTH_KEY",
        "CORELINK_INTERNAL_AUTH_KEY", "DSR_DLQ_REDRIVE_AUTH_KEY", "ERASURE_SALT_KEY",
    },
    "corelink-synthetic-pager-staging": set(),
    "github_environment_staging": {
        "STAGING_DSR_DLQ_REDRIVE_AUTH_KEY",
        "K6_STAGING_BYOK_CMK_ID", "K6_STAGING_MFA_STUB", "K6_STAGING_PAT",
        "K6_STAGING_STRIPE_WHSEC", "K6_STAGING_TEARDOWN_TOKEN",
        "K6_TARGET_IDENTITY_RECEIPT", "K6_TARGET_HOST",
    },
}


class InstrumentError(RuntimeError):
    pass


def _read(root: Path, relative: Path) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InstrumentError(f"cannot read {relative}: {error}") from error


def assess(root: Path = Path(".")) -> list[str]:
    try:
        contract = json.loads(_read(root, CONTRACT))
        receipt = json.loads(_read(root, RECEIPT))
        wrangler = tomllib.loads(_read(root, ROOT_WRANGLER))
        receiver_wrangler = tomllib.loads(_read(root, SYNTHETIC_RECEIVER_WRANGLER))
        signup_wrangler = tomllib.loads(_read(root, SIGNUP_WRANGLER))
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise InstrumentError(f"cannot parse staging contract input: {error}") from error

    gaps: list[str] = []
    if contract.get("schema_version") != 1:
        gaps.append("schema-version")
    if contract.get("deployment_state") != "unprovisioned":
        gaps.append("deployment-state-must-remain-unprovisioned")
    if contract.get("provider_resource_state") != "base_resources_provisioned":
        gaps.append("provider-resource-state")
    if contract.get("provider_receipt") != str(RECEIPT):
        gaps.append("provider-receipt-binding")
    if contract.get("canonical_origin") != CANONICAL_ORIGIN:
        gaps.append("canonical-origin")
    cloudflare = contract.get("cloudflare")
    if not isinstance(cloudflare, dict):
        return gaps + ["cloudflare-contract"]

    for key, expected in EXPECTED["workers"].items():
        if cloudflare.get(key) != expected:
            gaps.append(f"worker:{key}")
    if cloudflare.get("zone_name") != "humangr.com":
        gaps.append("zone-name")
    if cloudflare.get("root_worker_settings") != EXPECTED_ROOT_SETTINGS:
        gaps.append("root-worker-settings")
    if cloudflare.get("signup_worker_settings") != EXPECTED_SIGNUP_SETTINGS:
        gaps.append("signup-worker-settings")
    if cloudflare.get("synthetic_receiver_worker_settings") != EXPECTED_RECEIVER_SETTINGS:
        gaps.append("synthetic-receiver-worker-settings")
    if cloudflare.get("routes") != [
        {"worker": "corelink-staging", "pattern": "staging.corelink.humangr.com/*", "zone_name": "humangr.com"},
    ]:
        gaps.append("canonical-route")
    if cloudflare.get("container") != {
        "worker": "corelink-staging", "class_name": "CoreLinkServer", "source": "./Dockerfile",
        "instance_type": "basic", "max_instances": 5,
    }:
        gaps.append("container")

    families = {
        "d1": {
            (
                x.get("database_name"),
                x.get("migrations_dir"),
                tuple(sorted(
                    (binding.get("worker"), binding.get("binding"))
                    for binding in x.get("bindings", [])
                    if isinstance(binding, dict)
                )),
            )
            for x in cloudflare.get("d1", [])
            if isinstance(x, dict)
        },
        "r2": {(x.get("worker"), x.get("binding"), x.get("bucket_name")) for x in cloudflare.get("r2", []) if isinstance(x, dict)},
        "kv": {(x.get("worker"), x.get("binding"), x.get("namespace_title")) for x in cloudflare.get("kv", []) if isinstance(x, dict)},
        "do": {(x.get("worker"), x.get("binding"), x.get("class_name")) for x in cloudflare.get("durable_objects", []) if isinstance(x, dict)},
        "queues": {(x.get("producer_binding"), x.get("queue_name"), x.get("dead_letter_queue"), x.get("consumer_worker")) for x in cloudflare.get("queues", []) if isinstance(x, dict)},
        "services": {(x.get("worker"), x.get("binding"), x.get("service")) for x in cloudflare.get("service_bindings", []) if isinstance(x, dict)},
    }
    for family, expected in ((name, EXPECTED[name]) for name in families):
        if families[family] != expected:
            gaps.append(f"binding-family:{family}")

    d1_resources = cloudflare.get("d1", [])
    kv_resources = cloudflare.get("kv", [])
    queue_resources = cloudflare.get("queues", [])
    if len(d1_resources) != 1 or {
        "database_id": d1_resources[0].get("database_id"),
        "location": d1_resources[0].get("location"),
    } != {"database_id": CONFIG_DB_ID, "location": "ENAM"}:
        gaps.append("provider-resource-ids:d1")
    if {
        item.get("namespace_title"): item.get("namespace_id")
        for item in kv_resources if isinstance(item, dict)
    } != KV_NAMESPACE_IDS:
        gaps.append("provider-resource-ids:kv")
    if len(queue_resources) != 1 or any(
        queue_resources[0].get(key) != value for key, value in QUEUE_IDS.items()
    ):
        gaps.append("provider-resource-ids:queues")
    if any(item.get("location") != "ENAM" for item in cloudflare.get("r2", [])):
        gaps.append("provider-resource-location:r2")

    expected_readback = {
        "resources_captured_at": "2026-09-09T08:57:51Z",
        "dns_checked_at": "2026-09-09T09:05:19Z",
        "account_resource_scope": "staging-only",
        "dns": {
            "hostname": "staging.corelink.humangr.com",
            "state": "permission_blocked",
            "public_dns_result": "NXDOMAIN",
            "dns_records_read_error_code": 10000,
            "zone_settings_read_error_code": 9109,
        },
    }
    if contract.get("provider_readback") != expected_readback:
        gaps.append("provider-readback")

    expected_receipt_keys = {
        "schema_version", "receipt_type", "backlog_ids", "captured_at",
        "account_id_redacted", "scope", "deployment_state", "resources",
        "workers", "dns", "secrets", "readback",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_receipt_keys:
        gaps.append("provider-receipt-schema")
    else:
        if (
            receipt.get("schema_version") != 1
            or receipt.get("receipt_type") != "cloudflare_staging_base_resources"
            or receipt.get("backlog_ids") != ["B-029", "B-070"]
            or not re.fullmatch(r"2026-09-09T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", str(receipt.get("captured_at", "")))
            or receipt.get("account_id_redacted") != "6a1f...f5cd"
            or receipt.get("scope") != "staging-only"
            or receipt.get("deployment_state") != "unprovisioned"
        ):
            gaps.append("provider-receipt-metadata")
        resources = receipt.get("resources")
        if not isinstance(resources, dict) or set(resources) != {"d1", "r2", "kv", "queues"}:
            gaps.append("provider-receipt-resources")
        else:
            expected_d1 = [{
                "name": "corelink-config-staging", "id": CONFIG_DB_ID,
                "location": "ENAM", "jurisdiction": None,
                "user_table_count": 0, "readback_state": "empty",
            }]
            if resources.get("d1") != expected_d1:
                gaps.append("provider-receipt-d1")
            expected_r2 = {
                name: {"location": "ENAM", "storage_class": "Standard", "object_count": 0,
                       "bucket_size_bytes": 0, "readback_state": "empty"}
                for name in {
                    "corelink-cas-staging", "corelink-ac-iad-staging",
                    "corelink-chunk-iad-staging", "corelink-manifest-iad-staging",
                }
            }
            actual_r2 = {
                item.get("name"): {key: item.get(key) for key in expected_r2.get(item.get("name"), {})}
                for item in resources.get("r2", []) if isinstance(item, dict)
            }
            r2_keys = {"name", "location", "storage_class", "object_count", "bucket_size_bytes", "readback_state"}
            if (actual_r2 != expected_r2 or len(resources.get("r2", [])) != 4
                    or any(not isinstance(item, dict) or set(item) != r2_keys for item in resources.get("r2", []))):
                gaps.append("provider-receipt-r2")
            expected_kv = {
                name: {"id": namespace_id, "key_count": 0, "readback_state": "empty"}
                for name, namespace_id in KV_NAMESPACE_IDS.items()
            }
            actual_kv = {
                item.get("name"): {key: item.get(key) for key in expected_kv.get(item.get("name"), {})}
                for item in resources.get("kv", []) if isinstance(item, dict)
            }
            kv_keys = {"name", "id", "key_count", "readback_state"}
            if (actual_kv != expected_kv or len(resources.get("kv", [])) != 3
                    or any(not isinstance(item, dict) or set(item) != kv_keys for item in resources.get("kv", []))):
                gaps.append("provider-receipt-kv")
            expected_queues = {
                "corelink-dsr-erasure-staging": {
                    "id": QUEUE_IDS["queue_id"], "producer_count": 0,
                    "consumer_count": 0, "readback_state": "created_unbound",
                },
                "corelink-dsr-erasure-dlq-staging": {
                    "id": QUEUE_IDS["dead_letter_queue_id"], "producer_count": 0,
                    "consumer_count": 0, "readback_state": "created_unbound",
                },
            }
            actual_queues = {
                item.get("name"): {key: item.get(key) for key in expected_queues.get(item.get("name"), {})}
                for item in resources.get("queues", []) if isinstance(item, dict)
            }
            queue_keys = {"name", "id", "producer_count", "consumer_count", "readback_state"}
            if (actual_queues != expected_queues or len(resources.get("queues", [])) != 2
                    or any(not isinstance(item, dict) or set(item) != queue_keys for item in resources.get("queues", []))):
                gaps.append("provider-receipt-queues")
        if receipt.get("workers") != {
            "corelink-staging": "absent_10007",
            "corelink-signup-staging": "absent_10007",
            "corelink-synthetic-pager-staging": "absent_10007",
        }:
            gaps.append("provider-receipt-workers")
        receipt_dns = receipt.get("dns")
        expected_dns_receipt = dict(expected_readback["dns"], checked_at=expected_readback["dns_checked_at"])
        if receipt_dns != expected_dns_receipt:
            gaps.append("provider-receipt-dns")
        if receipt.get("secrets") != {
            "worker_secret_values_recorded": False,
            "github_environment_secret_values_recorded": False,
            "bindings_claimed": False,
        }:
            gaps.append("provider-receipt-secrets")
        if receipt.get("readback") != {
            "normalized_only": True,
            "production_resources_modified": False,
            "workers_deployed": False,
            "migrations_applied": False,
        }:
            gaps.append("provider-receipt-claims")

    serialized = json.dumps(contract, sort_keys=True)
    if re.search(r'(?i)(secret|token|key|password)_value', serialized):
        gaps.append("embedded-secret-value-field")
    resource_names = [value for family in (families["d1"], families["r2"], families["kv"], families["queues"]) for row in family for value in row if isinstance(value, str) and value.startswith("corelink-")]
    if any(not name.endswith("-staging") for name in resource_names):
        gaps.append("resource-reuses-non-staging-name")

    secrets = contract.get("required_secret_names")
    if not isinstance(secrets, dict):
        gaps.append("secret-name-contract")
    else:
        for owner, expected in EXPECTED_SECRETS.items():
            actual = secrets.get(owner)
            if not isinstance(actual, list) or set(actual) != expected or len(actual) != len(expected):
                gaps.append(f"secret-name-contract:{owner}")

    envs = wrangler.get("env", {})
    if not isinstance(envs, dict) or "staging" in envs:
        gaps.append("partial-or-unrendered-root-staging-env")

    receiver_envs = receiver_wrangler.get("env", {})
    receiver_staging = receiver_envs.get("staging", {}) if isinstance(receiver_envs, dict) else {}
    if {
        "main": receiver_wrangler.get("main"),
        "workers_dev": receiver_wrangler.get("workers_dev"),
        "compatibility_date": receiver_wrangler.get("compatibility_date"),
        "compatibility_flags": receiver_wrangler.get("compatibility_flags", []),
    } != {
        "main": "src/index.ts",
        "workers_dev": False,
        "compatibility_date": "2026-04-01",
        "compatibility_flags": [],
    }:
        gaps.append("synthetic-receiver-source-settings")
    if not isinstance(receiver_staging, dict) or receiver_staging.get("name") != "corelink-synthetic-pager-staging":
        gaps.append("synthetic-receiver-staging-name")
    if not isinstance(receiver_staging, dict) or receiver_staging.get("vars") != EXPECTED_RECEIVER_SETTINGS["vars"]:
        gaps.append("synthetic-receiver-staging-vars")
    if not isinstance(receiver_staging, dict) or receiver_staging.get("triggers", {}).get("crons") != EXPECTED_RECEIVER_SETTINGS["crons"]:
        gaps.append("synthetic-receiver-staging-crons")
    receiver_d1 = receiver_staging.get("d1_databases", []) if isinstance(receiver_staging, dict) else []
    expected_receiver_d1 = [{
        "binding": "CONFIG_DB",
        "database_name": "corelink-config-staging",
        "database_id": CONFIG_DB_ID,
        "migrations_dir": "../../migrations/d1",
    }]
    if receiver_d1 != expected_receiver_d1:
        gaps.append("synthetic-receiver-staging-d1")

    if {
        "main": signup_wrangler.get("main"),
        "workers_dev": signup_wrangler.get("workers_dev"),
        "compatibility_date": signup_wrangler.get("compatibility_date"),
        "compatibility_flags": signup_wrangler.get("compatibility_flags", []),
        "crons": signup_wrangler.get("triggers", {}).get("crons"),
    } != {
        "main": "src/index.ts",
        "workers_dev": False,
        "compatibility_date": "2026-05-01",
        "compatibility_flags": ["nodejs_compat"],
        "crons": ["0 * * * *"],
    }:
        gaps.append("signup-worker-source-settings")

    for workflow_path in (LOAD_WORKFLOW, ENDURANCE_WORKFLOW):
        workflow = _read(root, workflow_path)
        if f"CANONICAL_TARGET='{CANONICAL_ORIGIN}'" not in workflow:
            gaps.append(f"workflow-canonical-target:{workflow_path.name}")
        if 'TARGET_HOST="${K6_TARGET_HOST%/}"' not in workflow:
            gaps.append(f"workflow-target-normalization:{workflow_path.name}")
        if '[[ "$TARGET_HOST" != "$CANONICAL_TARGET" ]]' not in workflow:
            gaps.append(f"workflow-target-equality:{workflow_path.name}")
    return gaps


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--expect", choices=("ready", "open"), default="ready")
    args = parser.parse_args()
    try:
        gaps = assess(args.root.resolve())
    except InstrumentError as error:
        print(f"staging topology contract INSTRUMENT_ERROR: {error}", file=sys.stderr)
        return 2
    actual = "open" if gaps else "ready"
    print(f"staging topology contract {actual}: {len(gaps)} gap(s)")
    for gap in gaps:
        print(f"- {gap}")
    return 0 if actual == args.expect else 1


if __name__ == "__main__":
    raise SystemExit(main())
