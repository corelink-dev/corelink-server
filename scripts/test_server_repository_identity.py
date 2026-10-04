#!/usr/bin/env python3
"""Regression tests for CoreLink's GitHub identity source of truth.

``config/github-identity.json`` (read by ``scripts/server_repository.py``) is
the only live source for the owner, repository names and numeric IDs. This
suite pins:

* the committed identity: current owner, peer repositories, distribution,
  historical owners and retired IDs, and that an unread ID (0) is refused;
* the resolver and its Actions-context guard, against a synthetic read-back
  identity, including a teeth test that injects the retired
  ``HuGR-dev/corelink-server`` identity on every path and requires a failure;
* the classification gate: every tracked file under ``SCAN_DIRECTORIES`` that
  carries a retired owner/repository name, a retired numeric repository ID or
  a current-owner repository literal must be ACTIVE, HISTORICAL or
  PENDING-migration, and every numeric repository ID on a ``.github/`` guard
  expression must be a read-back current ID, unless it is frozen debt in a
  PENDING/HISTORICAL row. Frozen paths and exact retired-line counts forbid growth. Each defect class has a planted-defect
  test that must fail and name the file.
"""

from __future__ import annotations

import copy
import hashlib
import dataclasses
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from server_repository import (
    IDENTITY_PATH,
    REPOSITORY_KEYS,
    GitHubIdentity,
    IdentityError,
    current_repository,
    load_identity,
    main,
    parse_identity,
    read_identity,
    read_identity_document,
    require_github_context,
    require_repository_context,
    resolve_server_repository,
    validate_server_repository,
)

ROOT = Path(__file__).resolve().parents[1]

# Tracked files under these directories form the classification population.
SCAN_DIRECTORIES = (
    ".github",
    "apps",
    "config",
    "crates",
    "examples",
    "infra",
    "marketing",
    "scripts",
    "tests",
    "tools",
)

# ACTIVE rows are the identity source and explicit positive/negative test fixtures.
# Current surfaces still carrying retired destinations belong in PENDING;
# retired lines in every classification are bounded by the frozen baseline.
ACTIVE_IDENTITY_LITERAL_ALLOWLIST = {
    "tests/test_b132_secrets_evidence.py": "Behavioral test passes the exact source repo explicitly; it is not a fallback default.",
    "tests/test_b142_codeql_selfhost.py": "Behavioral test passes the exact source repo explicitly; it is not a fallback default.",
    "tests/test_cli_release_b112_behavior.py": "Release tests exercise the exact pre-transfer server source identity.",
    "tests/test_verify_b155_batch_g.py": "Adversarial workflow tests inject the old owner-name guard to prove it is rejected.",
    "tests/test_verify_b028_dependabot.py": "Negative fixture: proves the resolver refuses the retired destination server name.",
    "scripts/test_server_repository_identity.py": "This regression suite contains positive and negative identity examples and scan rules.",
    "scripts/test_org_migration_audit.py": "Reusable migration-auditor fixtures deliberately exercise historical and current server identities.",
    "config/github-identity.json": "Identity source of truth: lists the retired repository IDs so the loader refuses them as current values.",
    "scripts/test_b152_actions_diagnostic.py": "Negative fixture: proves the B-152 diagnostic refuses the retired server names before any API call.",
    "tests/test_i1721_r2_lock_probe.py": "Negative fixture: proves the #1721 preflight refuses the retired server name and ID.",
    "tests/test_issue_2568_sla_credit_real.py": "Negative fixture: proves the #2568 operator refuses the retired server name and ID before any remote read.",
    "tests/test_verify_b046_object_lock_probe.py": "Negative fixture: proves the B-046 receipt builder refuses the retired server name and ID.",
}

# These references bind retained records, cryptographic certificates, or dated
# audit history, not a live API destination. Their identities must not be
# rewritten as part of the repository transfer or the org recreate.
HISTORICAL_IDENTITY_LITERAL_ALLOWLIST = {
    "scripts/verify_b152_check_annotations.py": "Validates the stored B-152 packet repository identity; changing it would rewrite provenance.",
    "scripts/verify_owner_action_packets.py": "Validates immutable owner-action packets whose repository field is part of the reviewed record.",
    "scripts/b250_deleted_workflow_startup_failure.py": "Replays the byte-bound B-250 historical startup snapshot and its canonical source identity.",
    "scripts/verify_d03_graduation.py": "Checks historical owner procedure packets containing the exact command that was reviewed then.",
    "tests/test_verify_d03_graduation.py": "Tests mutation-rejecting checks over a retained historical D03 packet command.",
    "crates/corelink-ops/tests/supply_chain_verify_adversarial.rs": "Historical SLSA certificate/provenance fixture proving old signed server artifacts still verify.",
    ".github/CODEOWNERS": "Comment records a pre-transfer endpoint used in a dated audit example, not an API consumer.",
    "crates/corelink-ops/src/deploy/verifier.rs": "Historical signed deployment records remain identity-bound verification fixtures.",
    "crates/corelink-ops/examples/deploy_audit_fail_closed.rs": "Historical deployment fixture intentionally verifies the old signed SAN.",
    "crates/corelink-ops/examples/deploy_verify_signed_deploy.rs": "Historical signed deployment fixture intentionally verifies the old SAN.",
    "crates/corelink-ops/tests/deploy_adversarial.rs": "Historical signed deployment fixture; attacker variants are verified against original bytes.",
    "crates/corelink-ops/tests/deploy_chaos.rs": "Historical signed deployment fixture remains bound to its original SAN.",
    "crates/corelink-ops/tests/deploy_prop_verify.rs": "Historical signed deployment fixture remains bound to its original SAN.",
    "crates/corelink-ops/tests/supply_chain_verify_prop_verify.rs": "Historical SLSA property-test artifacts keep their signed builder identity unchanged.",
    "docs/security/report-security.md": "The quoted pre-transfer scope clause is retained as a dated correction to an earlier report, not an operational target.",
    "scripts/published_claims_inventory.json": "Generated published-claims inventory is a retained source snapshot, not a live trust or API target.",
    "docs/security/b373-dependabot-census-2026-09-09.json": "Dated Dependabot census preserves the repository identity observed when captured.",
    "docs/security/b028-dependabot-census-2026-09-06.json": "Dated Dependabot census preserves the repository identity observed when captured.",
    "docs/handoff/2026-09-06-d03-graduation-packets.json": "Sealed D03 handoff packets preserve their reviewed repository identity.",
    "docs/handoff/2026-09-05-b142-codeql-selfhost-action-packet.md": "Dated owner action packet preserves its original repository identity.",
    "docs/handoff/2026-09-05-owner-action-packets-b008-b154.json": "Dated owner action packets preserve their original repository identity.",
    "docs/internal/b250-deleted-workflow-control-plane-evidence-20260908.md": "Dated B-250 control-plane evidence preserves the observed source identity.",
    "docs/campaigns/HANDOFF-go-live-validation.md": "Historical go-live handoff preserves commands and links reviewed at the time.",
    "docs/perf/2026-09-09-wp-b152-historical-annotations.md": "Historical B-152 annotation evidence remains bound to its source repository.",
    "docs/operator/audit-archive-partition-remediation.md": "Completed remediation record preserves its historical repository references.",
    "docs/campaigns/remediation/ROADMAP.md": "Campaign roadmap retains reviewed historical repository references.",
    "docs/knowledge/adr/adr-0025-deploy-gate-hard-cosign-keyless.md": "Sealed ADR preserves the repository identity in its reviewed decision record.",
    "docs/knowledge/adr/adr-s12-001-sbom-cyclonedx-ntia-tsa-dt.md": "Sealed ADR preserves the repository identity in its reviewed decision record.",
    "tests/fixtures/i2574_old_base_bytes/.github/workflows/issue-2176-grpc-deny-gate.yml": "Byte-frozen #2574 old-base fixture; its bytes are the oracle and are never edited.",
    "tests/fixtures/i2574_old_base_bytes/scripts/verify_i2176_grpc_deny_gate.py": "Byte-frozen #2574 old-base fixture; its bytes are the oracle and are never edited.",
}

# Work packages that own a PENDING row (PLAN §4.2 and its critic).
PENDING_WORK_PACKAGES = {
    "I2a": "PLAN §4.2 I2a: unpinned workflow guard, or the verifier/test asserting it (lockstep).",
    "I2b": "PLAN §4.2 I2b: cross-repo routing (checkouts, URLs, peer-repository API targets).",
    "I3": "Also rebind verify_real_ignored_harnesses.py in CodeQL source_file_blobs. PLAN §4.2 I3: sha256-pinned identity file, edited only with the coupled root-reviewed re-pin.",
    "I4": "PLAN §4.2 I4: signing identities and their current examples, preserving historical SANs.",
    "I6": "PLAN §4.2 I6: CodeQL reviewed-dispositions binding, regenerated after the first scan in the new repo.",
    "I9": "PLAN §4.2 I9: customer-facing documentation.",
    "I9/B154": "I9 with coupled B-154 PUBLIC_COPY_PATHS sha256 re-pin; frozen prelaunch claim-resolution bytes enforce this file.",
    "P3": "PLAN §4.2 P3: internal prose and the transfer-era migration kit.",
    "b216": "PLAN critic K1.4: dedicated receiver-identity PR (receiver path boundary).",
    "R6": "02 §R.6: verifier bound to a receipt on an old GitHub object; keep as history or re-receipt (owner decision).",
}

# Files that still carry a retired identity literal and are owned by a later
# migration work package. The baseline freezes both the path set and exact
# retired lines (including duplicate counts). A migrated file must lose its
# row, or be reclassified with a written fixture/history reason. Owning WPs
# remove the corresponding baseline paths/hashes; no new debt is admitted.
PENDING_IDENTITY_MIGRATION = {
    ".github/ISSUE_TEMPLATE/config.yml": "I2b",
    ".github/workflow-state-waivers.yml": "P3",
    ".github/workflows/audit-archive-lag.yml": "I2a",
    ".github/workflows/audit-keyed-epoch.yml": "I2a",
    ".github/workflows/aws-s3-object-lock-live-proof.yml": "I2a",
    ".github/workflows/b029-load-gate.yml": "I2a",
    ".github/workflows/b103-cargo-write-reproducer.yml": "I2a",
    ".github/workflows/b125-audit-throughput-read-only.yml": "I2a",
    ".github/workflows/b216-receiver-deploy-nonprod.yml": "b216",
    ".github/workflows/b251-d03-read-only-probe.yml": "I2b",
    ".github/workflows/bot-pr-has-checks.yml": "I2a",
    ".github/workflows/campaign-ci.yml": "I3",
    ".github/workflows/cas_foundation.yml": "I2a",
    ".github/workflows/cf-deploy-prod.yml": "I3",
    ".github/workflows/cloudflare-scoped-token-handoff.yml": "I2a",
    ".github/workflows/container-build-push-prod.yml": "I3",
    ".github/workflows/corelink-server.yml": "I2a",
    ".github/workflows/endurance-2h-nightly.yml": "I2a",
    ".github/workflows/i1629-effect-ledger-sql.yml": "I2a",
    ".github/workflows/i1633-byok-accounting.yml": "I2a",
    ".github/workflows/i1664-gpg-release-identity-audit.yml": "I2a",
    ".github/workflows/i1675-live-probe.yml": "I2a",
    ".github/workflows/i2587-gpg-audit-ci.yml": "I2a",
    ".github/workflows/issue-1641-pagerduty-contract.yml": "I2a",
    ".github/workflows/issue-1648-b063-read-only-evidence.yml": "I2a",
    ".github/workflows/issue-1649-stripe-test-mode.yml": "I2a",
    ".github/workflows/issue-1652-b072-evidence.yml": "I3",
    ".github/workflows/issue-1656-capacity-refresh.yml": "I2a",
    ".github/workflows/issue-1658-b102-cap-propagation.yml": "I2a",
    ".github/workflows/issue-1658-b102-cargo-put.yml": "I2a",
    ".github/workflows/issue-1660-b104-authenticated-404.yml": "I2a",
    ".github/workflows/issue-1662-b106-cold-warm.yml": "I2a",
    ".github/workflows/issue-1665-b112-hosted-contract.yml": "I2a",
    ".github/workflows/issue-1666-mutants-evidence-contract.yml": "I2a",
    ".github/workflows/issue-1669-read-only-evidence.yml": "I2a",
    ".github/workflows/issue-1670-fleet-classification.yml": "I2a",
    ".github/workflows/issue-1670-fleet-contract.yml": "I2a",
    ".github/workflows/issue-1671-b129-diagnostic.yml": "I2a",
    ".github/workflows/issue-1681-b314-exact-head.yml": "I2a",
    ".github/workflows/issue-1690-p12-p14-verifier.yml": "I2a",
    ".github/workflows/issue-1700-container-staging-deploy.yml": "I3",
    ".github/workflows/issue-1700-staging-custom-domain.yml": "I2a",
    ".github/workflows/issue-1700-staging-readiness.yml": "I2a",
    ".github/workflows/issue-1724-cli-provenance.yml": "I2a",
    ".github/workflows/issue-1863-mutants-hosted.yml": "I2a",
    ".github/workflows/issue-1949-verifier-contract.yml": "I2a",
    ".github/workflows/issue-1952-openapi-version-contract.yml": "I2a",
    ".github/workflows/issue-2050-cli-release-dry-run.yml": "I2a",
    ".github/workflows/issue-2092-dsr-classification.yml": "I2a",
    ".github/workflows/issue-2152-cyclonedx-diagnostic.yml": "I2a",
    ".github/workflows/issue-2161-staging-ownership.yml": "I2a",
    ".github/workflows/issue-2165-ecr-image-build.yml": "I2a",
    ".github/workflows/issue-2167-b071-owner-packet.yml": "I2a",
    ".github/workflows/issue-2176-grpc-deny-gate.yml": "I3",
    ".github/workflows/issue-2568-sla-credit-real.yml": "I3",
    ".github/workflows/issue-2572-draft-contract.yml": "I2a",
    ".github/workflows/issue-2574-staging-grpc-diagnostic.yml": "I2a",
    ".github/workflows/issue-2575-staging-grpc-probe.yml": "I3",
    ".github/workflows/issue-2576-admission.yml": "I2a",
    ".github/workflows/issue-2579-cas-ownership.yml": "I2a",
    ".github/workflows/issue-2580-webhook-ownership.yml": "I2a",
    ".github/workflows/issue-2581-dsr-audit.yml": "I2a",
    ".github/workflows/issue-2582-signup-ownership.yml": "I2a",
    ".github/workflows/issue-2583-byok-ownership.yml": "I2a",
    ".github/workflows/issue-2586-windows-contract.yml": "I2a",
    ".github/workflows/issue-2586-windows-readiness.yml": "I2a",
    ".github/workflows/issue-2610-mutants-failure-receipt.yml": "I2a",
    ".github/workflows/issue-2612-provider-deferred.yml": "I2a",
    ".github/workflows/issue-2623-ownership-contract.yml": "I2a",
    ".github/workflows/issue-2627-stripe-fixtures.yml": "I2a",
    ".github/workflows/issue-2628-codeql-severity.yml": "I2a",
    ".github/workflows/issue-2649-b114-policy.yml": "I2a",
    ".github/workflows/issue-2663-teardown-contract.yml": "I2a",
    ".github/workflows/issue-2664-worker-synthetic-tenant.yml": "I2a",
    ".github/workflows/issue-2665-dsr-teardown.yml": "I2a",
    ".github/workflows/issue-2666-byok-teardown.yml": "I2a",
    ".github/workflows/issue-2776-r2-cleanup.yml": "I2a",
    ".github/workflows/issue-605-billing-fixture.yml": "I2a",
    ".github/workflows/issue-ci-pack.yml": "I2a",
    ".github/workflows/load-test-nightly.yml": "I3",
    ".github/workflows/mutation-nightly.yml": "I2a",
    ".github/workflows/perf-production-evidence.yml": "I2a",
    ".github/workflows/pr-601-hosted-spawn-worker-consumer.yml": "I2b",
    ".github/workflows/real-ignored-harnesses.yml": "I3",
    ".github/workflows/release-cli.yml": "I2a",
    ".github/workflows/runner-fleet-health.yml": "I2a",
    ".github/workflows/sbom-clone-bundle.yml": "I2a",
    ".github/workflows/semgrep.yml": "I2a",
    ".github/workflows/sign-linux.yml": "I2a",
    ".github/workflows/staging-load-seal-contract.yml": "I2a",
    ".github/workflows/staging-provider-preflight.yml": "I2a",
    ".github/workflows/staging-quarantine-apply.yml": "I3",
    ".github/workflows/workflow-state-guard.yml": "I2a",
    "apps/docs/docs/explanation/security/byok.mdx": "I9/B154",
    "apps/docs/lychee.toml": "I9",
    "apps/docs/src/pages/compare/vs-bazel-remote-s3.mdx": "I9",
    "apps/docs/src/pages/compare/vs-buildbuddy.mdx": "I9",
    "apps/docs/src/pages/compare/vs-engflow.mdx": "I9",
    "apps/docs/src/pages/compare/vs-nx-cloud.mdx": "I9",
    "apps/docs/src/pages/compare/vs-sccache-s3.mdx": "I9",
    "apps/docs/src/pages/compare/vs-turborepo.mdx": "I9",
    "apps/dsr-alert-receiver/scripts/receiver-target.mjs": "b216",
    "apps/dsr-alert-receiver/tests/deploy-route.test.mjs": "b216",
    "apps/get-corelink-worker/README.md": "I9",
    "crates/corelink-audit/src/link_hash.rs": "I9",
    "crates/corelink-client-verify/Cargo.toml": "I9",
    "crates/corelink-hash/Cargo.toml": "I9",
    "crates/corelink-ops/examples/supply_chain_verify_paranoid_mode.rs": "I4",
    "crates/corelink-ops/examples/supply_chain_verify_verify_basic.rs": "I4",
    "crates/corelink-ops/src/deploy.rs": "I4",
    "crates/corelink-ops/src/deploy/types.rs": "I4",
    "crates/corelink-ops/src/supply_chain/verify.rs": "I4",
    "crates/corelink-ops/src/supply_chain/verify/bin/cli.rs": "I4",
    "crates/corelink-ops/src/supply_chain/verify/types.rs": "I4",
    "crates/corelink-ops/src/supply_chain/verify/verifier.rs": "I4",
    "crates/corelink-rate-headers/Cargo.toml": "I9",
    "crates/corelink-rate-headers/README.md": "I9",
    "crates/corelink-stripe-real/src/client.rs": "I3",
    "crates/corelink-stripe-real/tests/live_integration.rs": "I3",
    "crates/tenant-path/Cargo.toml": "I9",
    "docs/OSS_STRATEGY.md": "I9",
    "docs/internal/ENGINEERING-ONBOARDING.md": "P3",
    "docs/internal/OSS-VS-CLOSED-MATRIX.md": "P3",
    "docs/internal/ci-runner-fabric-box.md": "P3",
    "docs/internal/pentest-engagement-checklist.md": "P3",
    "docs/internal/slsa-l3-pipeline.md": "P3",
    "docs/operator/e2e-ci-2026-05-30.md": "P3",
    "examples/bazel-starter/README.md": "I9",
    "examples/buck2-starter/README.md": "I9",
    "infra/ci-runners/linux/docker-compose.yml": "P3",
    "infra/grafana/dashboards/dash-audit-chain.json": "I9",
    "infra/grafana/dashboards/dash-billing.json": "I9",
    "infra/grafana/dashboards/dash-byok-health.json": "I9",
    "infra/grafana/dashboards/dash-capacity-planning.json": "I9",
    "infra/grafana/dashboards/dash-compliance-health.json": "I9",
    "infra/grafana/dashboards/dash-customer-traffic.json": "I9",
    "infra/grafana/dashboards/dash-dr-status.json": "I9",
    "infra/grafana/dashboards/dash-dsr-pipeline.json": "I9",
    "infra/grafana/dashboards/dash-incident-triage.json": "I9",
    "infra/grafana/dashboards/dash-ratelimit-abuse.json": "I9",
    "infra/grafana/dashboards/dash-reliability.json": "I9",
    "infra/grafana/dashboards/dash-slo-burndown.json": "I9",
    "marketing/og/README.md": "I9",
    "marketing/org-readme.md": "I9",
    "marketing/profile-readme.md": "I9",
    "marketing/retention/customer-health/SURVEY-ANALYSIS-PROTOCOL.md": "I9",
    "marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md": "I9",
    "marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md": "I9",
    "marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md": "I9",
    "scripts/check_b114_cross_repo.py": "I2b",
    "scripts/check_b135_cross_repo.py": "I2b",
    "scripts/codeql_reviewed_dispositions.py": "I6",
    "scripts/complete_issue_1700_existing.py": "I2b",
    "scripts/cut-v1-0-0-ga-tag.sh": "P3",
    "scripts/issue_1652_b072_operator.py": "I3",
    "scripts/org_migration_audit.py": "P3",
    "scripts/org_migration_gate_check.py": "P3",
    "scripts/run_i2587_gpg_audit.py": "I6",
    "scripts/staging_bootstrap_provider.py": "I3",
    "scripts/stripe_test_mode_evidence.py": "I2a",
    "scripts/test_b072_receiver_mutations.py": "I3",
    "scripts/test_b102_b108_evidence.py": "I2a",
    "scripts/test_b103_b129_attribution.py": "I2a",
    "scripts/test_b103_cargo_write_contract.py": "I2a",
    "scripts/test_i1687_endurance_lane.py": "I2a",
    "scripts/test_issue_1652_b072_operator.py": "I3",
    "scripts/test_org_migration_gate_check.py": "P3",
    "scripts/test_pinned_gh_consumers.py": "I2a",
    "scripts/verify_audit_archive_lag_workflow.py": "I2a",
    "scripts/verify_b012_bot_pr_evidence.py": "R6",
    "scripts/verify_b029_load_gate.py": "I3",
    "scripts/verify_b063_hosted_build_workflow.py": "I3",
    "scripts/verify_b063_hosted_evidence_workflow.py": "I2a",
    "scripts/verify_b072_receiver.py": "I3",
    "scripts/verify_b103_b129_attribution.py": "I2a",
    "scripts/verify_b154_instrument_claims.py": "R6",
    "scripts/verify_b155_batch_g.py": "I2a",
    "scripts/verify_b170_owner_actions.py": "R6",
    "scripts/verify_b314_gdpr_sigstore.py": "R6",
    "scripts/verify_i1658_b102_contract.py": "I6",
    "scripts/verify_i1687_endurance_lane.py": "I2a",
    "scripts/verify_i2176_grpc_deny_gate.py": "I3",
    "scripts/verify_i2368_hosted_bundle.py": "I2a",
    "scripts/verify_i2457_mutants_shards.py": "I2a",
    "scripts/verify_i2586_windows_readiness.py": "I2a",
    "scripts/verify_i2587_gpg_audit.py": "I2a",
    "scripts/verify_issue_2374_hosted_proof.py": "I2a",
    "scripts/verify_issue_2666_byok_teardown.py": "I2a",
    "scripts/verify_real_ignored_harnesses.py": "I3",
    "scripts/verify_staging_provider_preflight.py": "I3",
    "scripts/windows_signing_readiness.ps1": "I2a",
    "tests/load/README.md": "P3",
    "tests/test_b125_readonly_workflow.py": "I2a",
    "tests/test_i1664_signing_readiness.py": "I2a",
    "tests/test_issue_1700_historical_query.py": "I2a",
    "tests/test_issue_1700_staging_readiness_contract.py": "I2a",
    "tests/test_pull_request_target_spawn_boundary.py": "I3",
    "tests/test_staging_bootstrap_provider.py": "I3",
    "tests/test_verify_b170_owner_actions.py": "R6",
    "tools/cli/tests/release_workflow_contract.rs": "I2a",
    "tools/sbom-publish/src/purl.rs": "I9",
    "tools/sbom-publish/tests/adversarial.rs": "I9",
}

# These verifier/docs surfaces intentionally mention the source owner: the
# signer accepts source artifacts before cutover; the SLSA guide documents
# pre-transfer receipt verification; and the runner-fabric guide contains
# dated source-owner run links. Other current projections must not present the
# source as their current destination.
SOURCE_ALIAS_PROJECTION_ALLOWLIST = {
    "crates/corelink-ops/src/deploy/types.rs": "The canonical Cosign identity pattern explicitly accepts pre-transfer signed server artifacts.",
    "docs/internal/ci-runner-fabric-box.md": "Dated P1/P2 runner probe links preserve the original source-owner action-run URLs; current instructions resolve by repository ID.",
    "docs/internal/slsa-l3-pipeline.md": "The guide names the exact source only for verifying pre-transfer artifacts; destination is the current builder.",
}

# Exact lines inside ACTIVE_NO_STALE_DEFAULTS files where a retired literal is
# the attacker value a verifier must reject, not a default. The line must
# exist exactly once, so the row dies with the line (the file is I3-pinned).
NEGATIVE_FIXTURE_LINES = {
    "scripts/verify_real_ignored_harnesses.py": (
        'expect_rejected("wrong canonical repository", workflow.replace("HuGR-dev/corelink-server", "HuGR-Labs/corelink-server"), runner)',
    ),
}

# The a2 consumers that used to hard-code the server identity and now resolve
# it through scripts/server_repository.py (PLAN §4.2 I1).
RESOLVER_CONSUMERS = (
    "scripts/build_b046_object_lock_receipt.py",
    "scripts/collect_b102_b108_context.py",
    "scripts/issue_2568_sla_credit_real.py",
    "scripts/validate_i1721_r2_dispatch.sh",
    "scripts/verify_b102_b108_evidence.py",
)


def assert_current_projection_owner_is_not_stale(relative: str, contents: str) -> None:
    current_docs = contents
    if relative in {
        "crates/corelink-ops/src/deploy/types.rs",
        "crates/corelink-ops/src/supply_chain/verify/types.rs",
    }:
        current_docs = contents.split("#[cfg(test)]", maxsplit=1)[0]
    if re.search(r"(?i)HumanGuardrail/corelink-server", current_docs):
        raise AssertionError(f"historical owner leaked into current projection: {relative}")
    if relative not in SOURCE_ALIAS_PROJECTION_ALLOWLIST and re.search(
        r"(?i)HuGR-Labs/corelink-server", current_docs
    ):
        raise AssertionError(f"stale source owner leaked into current projection: {relative}")


@dataclasses.dataclass(frozen=True)
class IdentityLiteralPatterns:
    retired: re.Pattern[str]
    current: re.Pattern[str]
    any: re.Pattern[str]


def identity_literal_patterns(identity: GitHubIdentity) -> IdentityLiteralPatterns:
    """Build the scan patterns from the identity file; the gate holds no copy.

    Matching is a raw, case-insensitive substring search with no stripping of
    comments or strings, so it can only over-report.
    """
    names = "|".join(re.escape(repository.name) for repository in identity.repositories)
    owners = "|".join(re.escape(owner) for owner in identity.historical_server_owners)
    retired_ids = "|".join(str(value) for value in sorted(identity.retired_repository_ids))
    retired = rf"(?:{owners})/(?:{names})|(?<![0-9])(?:{retired_ids})(?![0-9])"
    current = rf"{re.escape(identity.owner)}/(?:{names})"
    return IdentityLiteralPatterns(
        retired=re.compile(f"(?i){retired}"),
        current=re.compile(f"(?i){current}"),
        any=re.compile(f"(?i){retired}|{current}"),
    )


IDENTITY_LITERAL_PATTERN = identity_literal_patterns(read_identity()).any

REPOSITORY_ID_CONTEXT = re.compile(r"(?i)repository[_.]?id|repo[_.]?id")
LITERAL_BASELINE_PATH = ROOT / "config/github-identity-literal-baseline.json"


def retired_line_fingerprints(text: str, identity: GitHubIdentity) -> dict[str, int]:
    """Count exact stripped retired-literal lines; deletion is allowed, growth is not."""
    pattern = identity_literal_patterns(identity).retired
    return dict(Counter(
        hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
        for line in text.splitlines() if pattern.search(line)
    ))


def read_literal_baseline() -> dict:
    # This initial migration debt is reviewed data, never regenerated by tests.
    # Owning WPs remove migrated rows/line hashes; they must not add exceptions.
    return json.loads(LITERAL_BASELINE_PATH.read_text(encoding="utf-8"))


def repository_id_tokens(text: str):
    """Read decimal operands tied to ID comparisons/assignments, across newlines.

    Numbers in event names, tag format placeholders and other guard operands
    are not repository IDs. Match the ID operand rather than every number in
    the surrounding expression. Whitespace includes folded/literal YAML lines.
    """
    context = r"(?:repository[_.]?id|repo[_.]?id)"
    operator = r"(?:==|!=|>=|<=|=|:|>|<|-eq|-ne)"
    number = r"['\"]?(?P<id>[+-]?[0-9][A-Za-z0-9_]*)['\"]?"
    forward = re.compile(
        context + r"[\w$}\"')\]]*\s*" + operator + r"\s*" + number,
        re.IGNORECASE,
    )
    reverse = re.compile(
        number + r"\s*" + operator + r"\s*[\"'$\w.{]*" + context,
        re.IGNORECASE,
    )
    return sorted({
        (text.count("\n", 0, match.start("id")) + 1, match.group("id"))
        for pattern in (forward, reverse) for match in pattern.finditer(text)
    })


def tracked_text_population(root: Path = ROOT) -> dict[str, str]:
    """Tracked UTF-8 text in the scan directories and explicit ledger paths."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", *SCAN_DIRECTORIES,
         *ACTIVE_IDENTITY_LITERAL_ALLOWLIST, *HISTORICAL_IDENTITY_LITERAL_ALLOWLIST,
         *PENDING_IDENTITY_MIGRATION],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise AssertionError("git ls-files failed: the identity scan cannot establish its population")
    population: dict[str, str] = {}
    for relative in result.stdout.decode("utf-8").split("\0"):
        path = root / relative
        if not relative or path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            population[relative] = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return population


def read_repository_file(relative: str) -> str | None:
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def classify_identity_literals(
    population: Mapping[str, str],
    identity: GitHubIdentity,
    *,
    active: Mapping[str, str],
    historical: Mapping[str, str],
    pending: Mapping[str, str],
    read_outside: Callable[[str], str | None] = lambda _relative: None,
    baseline: Mapping | None = None,
) -> list[str]:
    """Return every classification defect, each naming its file."""
    if not population:
        return [
            "identity scan population is EMPTY: nothing tracked under the scan "
            "directories, or the scan broke; refusing to report green over zero files"
        ]
    patterns = identity_literal_patterns(identity)
    errors: list[str] = []
    classes: dict[str, str] = {}
    for name, ledger in (("ACTIVE", active), ("HISTORICAL", historical), ("PENDING", pending)):
        for relative, reason in ledger.items():
            if not isinstance(reason, str) or not reason.strip():
                errors.append(f"{name} row has no reason: {relative}")
            if relative in classes:
                errors.append(f"classified twice ({classes[relative]} and {name}): {relative}")
            classes[relative] = name
    for relative, label in pending.items():
        if label not in PENDING_WORK_PACKAGES:
            errors.append(f"PENDING row names unknown work package {label!r}: {relative}")
        if baseline is not None and relative not in baseline["pending_paths"]:
            errors.append(f"PENDING ledger grew beyond its frozen paths: {relative}")
        if relative not in population:
            errors.append(f"PENDING row is outside the tracked scan population: {relative}")

    for relative, name in sorted(classes.items()):
        text = population[relative] if relative in population else read_outside(relative)
        if text is None:
            errors.append(f"{name} row names a file that does not exist: {relative}")
        elif name in {"HISTORICAL", "PENDING"} and not patterns.retired.search(text):
            errors.append(f"stale {name} row (no retired identity literal left; delete the row): {relative}")
        elif name == "ACTIVE" and not patterns.any.search(text):
            errors.append(f"stale ACTIVE row (no identity literal left; delete the row): {relative}")
        if text is not None and baseline is not None:
            allowed = baseline["retired_lines"].get(relative, {})
            for fingerprint, count in retired_line_fingerprints(text, identity).items():
                if count > allowed.get(fingerprint, 0):
                    errors.append(f"retired identity lines grew beyond frozen baseline: {relative}")
                    break

    for relative, text in sorted(population.items()):
        if relative not in classes and patterns.any.search(text):
            errors.append(f"unclassified identity literal: {relative}")

    read_back = {repository.id for repository in identity.repositories if repository.id}
    for relative, text in sorted(population.items()):
        if not relative.startswith(".github/"):
            continue
        for number, token in repository_id_tokens(text):
            value = int(token) if re.fullmatch(r"[1-9][0-9]*", token) else None
            if value in read_back:
                continue
            if value in identity.retired_repository_ids and classes.get(relative) in {"PENDING", "HISTORICAL"}:
                continue
            errors.append(f"numeric repository ID is not a read-back current ID: {relative}:{number}")
    return errors


def read_back_fixture_identity(**overrides: object) -> GitHubIdentity:
    """The committed owner and names with synthetic read-back IDs."""
    return parse_identity(read_back_fixture_document(**overrides)).require_read_back()


def read_back_fixture_document(**overrides: object) -> dict:
    document = copy.deepcopy(read_identity_document())
    document["current"]["owner_id"] = 987650000
    for offset, key in enumerate(REPOSITORY_KEYS, start=1):
        document["current"]["repos"][key]["id"] = 987650000 + offset
    document.update(overrides)
    return document


FIXTURE = read_back_fixture_identity()
SERVER = FIXTURE.repository("server")
RETIRED_SERVER_ID = 1232040291


class CommittedIdentityTests(unittest.TestCase):
    def test_committed_identity_names_the_recreated_owner_and_peer_repositories(self) -> None:
        identity = read_identity()
        self.assertEqual(identity.owner, "corelink-dev")
        self.assertEqual(
            {repository.key: repository.full_name for repository in identity.repositories},
            {
                "server": "corelink-dev/corelink-server",
                "runners": "corelink-dev/corelink-runners",
                "workspaces": "corelink-dev/corelink-workspaces",
            },
        )
        # Distribution stays on HuGR-Labs (alive); moving it is a product decision.
        self.assertTrue(all(value.startswith("HuGR-Labs/") for _key, value in identity.distribution))
        # Never release these names, and never authorize them as live owners.
        self.assertTrue({"HumanGuardrail", "HuGR-Labs", "HuGR-dev"} <= set(identity.historical_server_owners))
        self.assertTrue({1232040291, 1259579816, 1266754321, 1380335483} <= identity.retired_repository_ids)

    def test_committed_ids_are_filled_read_back_and_not_retired(self) -> None:
        identity = read_identity()
        self.assertEqual(identity.unread(), ())
        self.assertEqual(load_identity(), identity)
        for repository in identity.repositories:
            with self.subTest(repository=repository.key):
                self.assertNotIn(repository.id, identity.retired_repository_ids)

    def test_identity_file_is_the_resolver_default(self) -> None:
        self.assertEqual(IDENTITY_PATH, ROOT / "config" / "github-identity.json")


class IdentityLoaderTests(unittest.TestCase):
    def mutated(self, mutate: Callable[[dict], None]) -> dict:
        document = read_back_fixture_document()
        mutate(document)
        return document

    def test_fixture_identity_parses_and_is_read_back(self) -> None:
        self.assertEqual(FIXTURE.unread(), ())
        self.assertEqual(SERVER.full_name, "corelink-dev/corelink-server")

    def test_loader_rejects_malformed_or_unsafe_identity(self) -> None:
        cases: dict[str, Callable[[dict], None]] = {
            "unknown top-level key": lambda d: d.update(extra=1),
            "missing top-level key": lambda d: d.pop("retired_repository_ids"),
            "schema 2": lambda d: d.update(schema=2),
            "schema as bool": lambda d: d.update(schema=True),
            "empty comment": lambda d: d.update(comment=" "),
            "boolean ID": lambda d: d["current"]["repos"]["server"].update(id=True),
            "negative ID": lambda d: d["current"]["repos"]["server"].update(id=-1),
            "string ID": lambda d: d["current"]["repos"]["server"].update(id="987650001"),
            "float ID": lambda d: d["current"]["repos"]["server"].update(id=987650001.0),
            "missing peer repository": lambda d: d["current"]["repos"].pop("workspaces"),
            "extra repository": lambda d: d["current"]["repos"].update(archive={"name": "x", "id": 1}),
            "duplicate repository IDs": lambda d: d["current"]["repos"]["runners"].update(id=987650001),
            "duplicate repository names": lambda d: d["current"]["repos"]["runners"].update(name="corelink-server"),
            "retired ID as current": lambda d: d["current"]["repos"]["server"].update(id=RETIRED_SERVER_ID),
            "retired peer ID as current": lambda d: d["current"]["repos"]["runners"].update(id=1266754321),
            "historical owner as current": lambda d: d["current"].update(owner="HuGR-dev"),
            "historical owner as current, other case": lambda d: d["current"].update(owner="hugr-dev"),
            "invalid owner": lambda d: d["current"].update(owner="-corelink"),
            "invalid repository name": lambda d: d["current"]["repos"]["server"].update(name=".."),
            "empty historical owners": lambda d: d.update(historical_server_owners=[]),
            "duplicate historical owners": lambda d: d.update(historical_server_owners=["HuGR-dev", "hugr-dev"]),
            "empty retired IDs": lambda d: d.update(retired_repository_ids=[]),
            "zero retired ID": lambda d: d.update(retired_repository_ids=[0]),
            "distribution without owner": lambda d: d["distribution"].update(cli="corelink-cli"),
            "github app ID zero": lambda d: d["github_app"].update(id=0),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label), self.assertRaises(IdentityError):
                parse_identity(self.mutated(mutate))

    def test_duplicate_json_keys_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "github-identity.json"
            text = json.dumps(read_back_fixture_document(), indent=1)
            path.write_text(text.replace('"schema": 1,', '"schema": 1,\n "schema": 1,', 1), encoding="utf-8")
            with self.assertRaisesRegex(IdentityError, "duplicate key"):
                read_identity(path)
            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(IdentityError, "not JSON"):
                read_identity(path)
            with self.assertRaisesRegex(IdentityError, "cannot read"):
                read_identity(Path(directory) / "missing.json")

    def test_unread_zero_is_refused_by_the_loader_and_every_authorizer(self) -> None:
        for field in ("owner_id", "server", "runners", "workspaces"):
            with self.subTest(unread=field):
                document = read_back_fixture_document()
                if field == "owner_id":
                    document["current"]["owner_id"] = 0
                else:
                    document["current"]["repos"][field]["id"] = 0
                unread = parse_identity(document)
                self.assertEqual(len(unread.unread()), 1)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "github-identity.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    self.assertEqual(read_identity(path), unread)
                    with self.assertRaisesRegex(IdentityError, "not read back yet"):
                        load_identity(path)
                with self.assertRaisesRegex(IdentityError, "not read back yet"):
                    validate_server_repository(SERVER.full_name, identity=unread)
                with self.assertRaisesRegex(IdentityError, "not read back yet"):
                    require_repository_context(SERVER.full_name, str(SERVER.id), identity=unread)
                with self.assertRaisesRegex(IdentityError, "not read back yet"):
                    resolve_server_repository(SERVER.full_name, identity=unread)


class ServerRepositoryResolverTests(unittest.TestCase):
    def test_only_the_configured_server_name_is_authorized(self) -> None:
        self.assertEqual(validate_server_repository(SERVER.full_name, identity=FIXTURE), SERVER.full_name)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_server_repository(SERVER.full_name, identity=FIXTURE), SERVER.full_name)
        for invalid in (
            "attacker/corelink-server",
            "corelink-dev/corelink-server-evil",
            "CORELINK-DEV/corelink-server",
            "corelink-dev/corelink-runners",
            "corelink-dev/corelink-workspaces",
            "HuGR-Labs/corelink-cli",
            "HuGR-Labs/corelink-server",
            "HuGR-dev/corelink-server",
            "HumanGuardrail/corelink-server",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_server_repository(invalid, identity=FIXTURE)

        canary = "attacker/canary-private-name-7461"
        stderr = io.StringIO()
        with patch("server_repository.load_identity", return_value=FIXTURE), redirect_stderr(stderr):
            self.assertEqual(main(["--repo", canary]), 2)
        self.assertNotIn(canary, stderr.getvalue())
        self.assertIn("not an authorized CoreLink server repository", stderr.getvalue())

    def test_teeth_retired_server_identity_is_refused_on_every_path(self) -> None:
        retired = "HuGR-dev/corelink-server"
        # 1. Explicit caller value and the override environment variables.
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            resolve_server_repository(retired, identity=FIXTURE)
        for variable in ("CORELINK_SERVER_REPOSITORY", "CORELINK_EXPECTED_REPOSITORY"):
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: retired}, clear=True):
                with self.assertRaises(ValueError):
                    resolve_server_repository(identity=FIXTURE)
        # 2. Actions context with the retired name, with the retired and current IDs.
        for repository_id in (str(RETIRED_SERVER_ID), str(SERVER.id)):
            env = {"GITHUB_REPOSITORY": retired, "GITHUB_REPOSITORY_ID": repository_id}
            with self.subTest(repository_id=repository_id), patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ValueError):
                    resolve_server_repository(identity=FIXTURE)
                with self.assertRaises(ValueError):
                    require_github_context(identity=FIXTURE)
        # 3. A gh readback that returns the retired name (a redirect or a stale ID).
        stale = subprocess.CompletedProcess(["gh"], 0, stdout=retired + "\n", stderr="")
        with patch.dict(os.environ, {}, clear=True), patch(
            "server_repository.subprocess.run", return_value=stale
        ), self.assertRaises(ValueError):
            resolve_server_repository(identity=FIXTURE)
        # 4. An identity file that makes the retired owner current again.
        with self.assertRaisesRegex(IdentityError, "historical server owner"):
            parse_identity(read_back_fixture_document(current={
                "owner": "HuGR-dev",
                "owner_id": 987650000,
                "repos": {key: {"name": f"corelink-{key}", "id": 987650001 + index}
                          for index, key in enumerate(REPOSITORY_KEYS)},
            }))
        # 5. The classification gate refuses a new retired literal (see
        #    IdentityClassificationGateTests.test_teeth_injected_retired_server_literal_fails).

    def test_github_context_requires_the_configured_numeric_id_and_name(self) -> None:
        good = {"GITHUB_REPOSITORY_ID": str(SERVER.id), "GITHUB_REPOSITORY": SERVER.full_name}
        with patch.dict(os.environ, good, clear=True):
            self.assertEqual(resolve_server_repository(identity=FIXTURE), SERVER.full_name)
            self.assertEqual(require_github_context(identity=FIXTURE), SERVER.full_name)
        for label, changes in (
            ("wrong ID", {"GITHUB_REPOSITORY_ID": "999"}),
            ("retired ID", {"GITHUB_REPOSITORY_ID": str(RETIRED_SERVER_ID)}),
            ("peer ID", {"GITHUB_REPOSITORY_ID": str(FIXTURE.repository("runners").id)}),
            ("padded ID", {"GITHUB_REPOSITORY_ID": "0" + str(SERVER.id)}),
            ("signed ID", {"GITHUB_REPOSITORY_ID": "+" + str(SERVER.id)}),
            ("spaced ID", {"GITHUB_REPOSITORY_ID": str(SERVER.id) + " "}),
            ("empty ID", {"GITHUB_REPOSITORY_ID": ""}),
            ("missing name", {"GITHUB_REPOSITORY": ""}),
        ):
            with self.subTest(case=label), patch.dict(os.environ, {**good, **changes}, clear=True):
                with self.assertRaises(ValueError):
                    resolve_server_repository(identity=FIXTURE)
        # Only one half of the context present is never enough.
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": SERVER.full_name}, clear=True), self.assertRaises(ValueError):
            resolve_server_repository(identity=FIXTURE)
        # The context check ignores caller overrides that would name the server.
        env = {**good, "GITHUB_REPOSITORY_ID": str(RETIRED_SERVER_ID), "CORELINK_SERVER_REPOSITORY": SERVER.full_name}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError):
            require_github_context(identity=FIXTURE)

    def test_caller_overrides_cannot_bypass_an_actions_context(self) -> None:
        good = {"GITHUB_REPOSITORY": SERVER.full_name, "GITHUB_REPOSITORY_ID": str(SERVER.id)}
        for selected in ("explicit", "CORELINK_SERVER_REPOSITORY", "CORELINK_EXPECTED_REPOSITORY"):
            for changes in ({}, {"GITHUB_REPOSITORY_ID": str(RETIRED_SERVER_ID)},
                            {"GITHUB_REPOSITORY_ID": ""}, {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server"}):
                env = {**good, **changes}
                explicit = SERVER.full_name if selected == "explicit" else None
                if explicit is None:
                    env[selected] = SERVER.full_name
                with self.subTest(selected=selected, changes=changes), patch.dict(os.environ, env, clear=True):
                    if changes:
                        with self.assertRaises(ValueError):
                            resolve_server_repository(explicit, identity=FIXTURE)
                    else:
                        self.assertEqual(resolve_server_repository(explicit, identity=FIXTURE), SERVER.full_name)

    def test_local_default_queries_the_configured_id_and_never_accepts_a_redirect_owner(self) -> None:
        completed = subprocess.CompletedProcess(["gh"], 0, stdout=SERVER.full_name + "\n", stderr="")
        with patch.dict(os.environ, {}, clear=True), patch(
            "server_repository.subprocess.run", return_value=completed
        ) as run:
            self.assertEqual(resolve_server_repository(identity=FIXTURE), SERVER.full_name)
        self.assertEqual(
            run.call_args.args[0],
            ["gh", "api", f"repositories/{SERVER.id}", "--jq", ".full_name"],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        for redirect in ("HumanGuardrail/corelink-server", "HuGR-Labs/corelink-server", "HuGR-dev/corelink-server"):
            historical_redirect = subprocess.CompletedProcess(["gh"], 0, stdout=redirect + "\n", stderr="")
            with self.subTest(redirect=redirect), patch.dict(os.environ, {}, clear=True), patch(
                "server_repository.subprocess.run", return_value=historical_redirect
            ), self.assertRaises(ValueError):
                resolve_server_repository(identity=FIXTURE)

    def test_peer_repositories_resolve_by_their_own_name_and_id(self) -> None:
        for key in ("runners", "workspaces"):
            peer = FIXTURE.repository(key)
            with self.subTest(peer=key):
                self.assertEqual(peer.full_name, f"corelink-dev/corelink-{key}")
                self.assertEqual(current_repository(key, identity=FIXTURE), peer)
                self.assertEqual(
                    require_repository_context(peer.full_name, str(peer.id), key=key, identity=FIXTURE),
                    peer.full_name,
                )
                # A peer is never a server alias, and the server is never a peer.
                with self.assertRaises(ValueError):
                    validate_server_repository(peer.full_name, identity=FIXTURE)
                with self.assertRaises(ValueError):
                    require_repository_context(peer.full_name, str(peer.id), identity=FIXTURE)
                with self.assertRaises(ValueError):
                    require_repository_context(SERVER.full_name, str(SERVER.id), key=key, identity=FIXTURE)
        with self.assertRaises(IdentityError):
            current_repository("archive", identity=FIXTURE)

    def test_cli_requires_github_context_and_reports_unread_identity(self) -> None:
        good = {"GITHUB_REPOSITORY_ID": str(SERVER.id), "GITHUB_REPOSITORY": SERVER.full_name}
        stdout = io.StringIO()
        with patch("server_repository.load_identity", return_value=FIXTURE), patch.dict(
            os.environ, good, clear=True
        ), redirect_stdout(stdout):
            self.assertEqual(main(["--require-github-context"]), 0)
        self.assertEqual(stdout.getvalue(), SERVER.full_name + "\n")
        stderr = io.StringIO()
        with patch("server_repository.load_identity", return_value=FIXTURE), patch.dict(
            os.environ, {**good, "GITHUB_REPOSITORY": "HuGR-dev/corelink-server"}, clear=True
        ), redirect_stderr(stderr):
            self.assertEqual(main(["--require-github-context"]), 2)
        self.assertIn("not the configured CoreLink server repository", stderr.getvalue())
        if read_identity().unread():
            stderr = io.StringIO()
            with patch.dict(os.environ, good, clear=True), redirect_stderr(stderr):
                self.assertEqual(main(["--require-github-context"]), 2)
            self.assertIn("not read back yet", stderr.getvalue())

    def test_a2_consumers_resolve_through_the_identity_source(self) -> None:
        patterns = identity_literal_patterns(read_identity())
        for relative in RESOLVER_CONSUMERS:
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                self.assertIn("server_repository", text)
                self.assertIsNone(patterns.any.search(text))


class IdentityClassificationGateTests(unittest.TestCase):
    CLEAN = {
        "scripts/server_repository.py": "def resolve(): return load_identity()\n",
        "scripts/history.py": "RECORD = 'https://github.com/HuGR-dev/corelink-server/pull/1'\n",
        "scripts/pending.py": "if repo != 'HuGR-dev/corelink-server': raise SystemExit\n",
        "scripts/active.py": "NEGATIVE = 'HuGR-Labs/corelink-server'\n",
        ".github/workflows/lane.yml": "    if: github.repository_id == vars.CORELINK_SERVER_REPO_ID\n",
    }
    LEDGERS = {
        "active": {"scripts/active.py": "negative fixture"},
        "historical": {"scripts/history.py": "dated record"},
        "pending": {"scripts/pending.py": "I2a"},
    }

    @classmethod
    def setUpClass(cls) -> None:
        # The real tree is read once per suite; planted defects mutate copies.
        cls.real_population = tracked_text_population()

    def fixture_baseline(self) -> dict:
        return {
            "pending_paths": list(self.LEDGERS["pending"]),
            "retired_lines": {
                path: retired_line_fingerprints(text, FIXTURE)
                for path, text in self.CLEAN.items()
            },
        }

    def classify(self, population: Mapping[str, str], *, baseline=None, **ledgers: Mapping[str, str]) -> list[str]:
        merged = {**self.LEDGERS, **ledgers}
        return classify_identity_literals(
            population, FIXTURE, baseline=baseline or self.fixture_baseline(), **merged
        )

    def assert_fails_naming(self, errors: list[str], fragment: str, path: str) -> None:
        self.assertTrue(errors, "the planted defect passed the identity gate")
        self.assertTrue(
            any(fragment in error and path in error for error in errors),
            f"no error names {path!r} with {fragment!r}: {errors}",
        )

    def test_clean_population_passes(self) -> None:
        self.assertEqual(self.classify(self.CLEAN), [])

    def test_teeth_injected_retired_server_literal_fails(self) -> None:
        for literal in (
            "HuGR-dev/corelink-server",
            "https://github.com/HuGR-dev/corelink-server.git",
            "git@github.com:hugr-dev/corelink-server.git",
            "repos/HuGR-dev/corelink-server/actions/runs",
        ):
            with self.subTest(literal=literal):
                population = dict(self.CLEAN)
                population["scripts/server_repository.py"] += f"REPOSITORY = {literal!r}\n"
                self.assert_fails_naming(
                    self.classify(population), "unclassified identity literal", "scripts/server_repository.py"
                )

    def test_teeth_injected_into_the_real_tree_fails(self) -> None:
        population = dict(self.real_population)
        population["scripts/server_repository.py"] += '\nLEGACY = "HuGR-dev/corelink-server"\n'
        errors = classify_identity_literals(
            population,
            read_identity(),
            active=ACTIVE_IDENTITY_LITERAL_ALLOWLIST,
            historical=HISTORICAL_IDENTITY_LITERAL_ALLOWLIST,
            pending=PENDING_IDENTITY_MIGRATION,
            read_outside=read_repository_file,
            baseline=read_literal_baseline(),
        )
        self.assertEqual(errors, ["unclassified identity literal: scripts/server_repository.py"])

    def test_peer_retired_names_and_ids_and_current_literals_must_be_classified(self) -> None:
        for label, addition in (
            ("retired runners name", "RUNNERS = 'HuGR-dev/corelink-runners'\n"),
            ("retired workspaces name", "URL = 'https://github.com/HuGR-Labs/corelink-workspaces'\n"),
            ("retired server ID", f"REPOSITORY_ID = '{RETIRED_SERVER_ID}'\n"),
            ("retired peer ID", "PEER = 1266754321\n"),
            ("current owner literal", "REPO = 'corelink-dev/corelink-server'\n"),
            ("current peer literal", "REPO = 'corelink-dev/corelink-runners'\n"),
        ):
            with self.subTest(case=label):
                population = {**self.CLEAN, "tools/new.py": addition}
                self.assert_fails_naming(self.classify(population), "unclassified identity literal", "tools/new.py")
        # Not identity literals: other repositories, longer numbers.
        population = {**self.CLEAN, "tools/new.py": "CLI = 'HuGR-Labs/corelink-cli'\nRUN = 12320402910\n"}
        self.assertEqual(self.classify(population), [])

    def test_stale_missing_and_duplicate_rows_fail(self) -> None:
        population = dict(self.CLEAN)
        population["scripts/pending.py"] = "migrated = True\n"
        self.assert_fails_naming(self.classify(population), "stale PENDING row", "scripts/pending.py")
        population = dict(self.CLEAN)
        population["scripts/history.py"] = "rewritten = True\n"
        self.assert_fails_naming(self.classify(population), "stale HISTORICAL row", "scripts/history.py")
        population = dict(self.CLEAN)
        population["scripts/active.py"] = "nothing = True\n"
        self.assert_fails_naming(self.classify(population), "stale ACTIVE row", "scripts/active.py")
        population = {k: v for k, v in self.CLEAN.items() if k != "scripts/pending.py"}
        self.assert_fails_naming(self.classify(population), "outside the tracked scan population", "scripts/pending.py")
        self.assert_fails_naming(
            self.classify(self.CLEAN, pending={"scripts/pending.py": "I2a", "scripts/active.py": "I2a"}),
            "classified twice",
            "scripts/active.py",
        )
        self.assert_fails_naming(
            self.classify(self.CLEAN, pending={"scripts/pending.py": "someday"}),
            "unknown work package",
            "scripts/pending.py",
        )
        self.assert_fails_naming(
            self.classify(self.CLEAN, active={"scripts/active.py": " "}), "has no reason", "scripts/active.py"
        )
        for classification in ("active", "historical"):
            path = "scripts/missing.py"
            ledger = {**self.LEDGERS[classification], path: "dated fixture"}
            self.assert_fails_naming(self.classify(self.CLEAN, **{classification: ledger}), "does not exist", path)


    def test_github_numeric_repository_ids_must_be_read_back(self) -> None:
        for label, line, ok in (
            ("vars form", "if: github.repository_id == vars.CORELINK_SERVER_REPO_ID", True),
            ("read-back current ID", f"if: github.repository_id == '{SERVER.id}'", True),
            ("read-back peer ID", f"RUNNERS_REPOSITORY_ID: '{FIXTURE.repository('runners').id}'", True),
            ("guessed ID", "if: github.repository_id == '123456789'", False),
            ("zero placeholder", "if: github.repository_id == '0'", False),
            ("one-digit guess", "if: github.repository_id == '1'", False),
            ("five-digit guess", "if: github.repository_id == '12345'", False),
            ("folded multiline zero", "if: >-\n      github.repository_id ==\n      '0'", False),
            ("literal multiline guess", "if: |\n      github.repository_id ==\n      '123456789'", False),
            ("bare multiline guess", "github.repository_id ==\n      '123456789'", False),
            ("reverse zero", "if: '0' == github.repository_id", False),
            ("multiline reverse zero", "if: >-\n      '0' ==\n      github.repository_id", False),
            ("signed ID", "if: github.repository_id == '+987650001'", False),
            ("padded ID", "if: github.repository_id == '0987650001'", False),
            ("hex ID", "if: github.repository_id == '0x1234'", False),
            ("non-ID numeric strings", f"if: github.repository_id == '{SERVER.id}' && inputs.confirm == 'run-1670-lane' && startsWith(github.ref, format('refs/tags/{{0}}', inputs.tag))", True),
            ("multiline read-back", f"if: >-\n      github.repository_id ==\n      '{SERVER.id}'", True),
            ("multiline vars", "if: >-\n      github.repository_id ==\n      vars.CORELINK_SERVER_REPO_ID", True),
            ("guessed ID in shell", 'test "$GITHUB_REPOSITORY_ID" = "4815162342"', False),
            ("retired ID in an unclassified file", f"if: github.repository_id == '{RETIRED_SERVER_ID}'", False),
        ):
            with self.subTest(case=label):
                population = {**self.CLEAN, ".github/workflows/new.yml": f"    {line}\n"}
                errors = self.classify(population)
                if ok:
                    self.assertEqual(errors, [])
                else:
                    self.assertTrue(any(".github/workflows/new.yml" in error for error in errors), errors)
        # A retired ID in a PENDING workflow is the declared migration debt.
        population = {**self.CLEAN, ".github/workflows/old.yml": f"if: github.repository_id == '{RETIRED_SERVER_ID}'\n"}
        baseline = self.fixture_baseline()
        baseline["pending_paths"].append(".github/workflows/old.yml")
        baseline["retired_lines"][".github/workflows/old.yml"] = retired_line_fingerprints(population[".github/workflows/old.yml"], FIXTURE)
        self.assertEqual(self.classify(population, baseline=baseline, pending={"scripts/pending.py": "I2a", ".github/workflows/old.yml": "I2a"}), [])
        # ACTIVE cannot grant the numeric-ID exemption, even with frozen lines.
        self.assert_fails_naming(
            self.classify(population, baseline=baseline, active={"scripts/active.py": "negative fixture", ".github/workflows/old.yml": "live"}),
            "numeric repository ID", ".github/workflows/old.yml",
        )
        self.assertEqual(self.classify(population, baseline=baseline, historical={"scripts/history.py": "dated record", ".github/workflows/old.yml": "dated workflow"}), [])

    def test_pending_path_set_cannot_grow_even_with_a_new_classification(self) -> None:
        path = "scripts/new.py"
        population = {**self.CLEAN, path: "DEFAULT = 'HuGR-dev/corelink-server'\n"}
        # Give the planted file a line budget too: path membership has its own teeth.
        baseline = self.fixture_baseline()
        baseline["retired_lines"][path] = retired_line_fingerprints(population[path], FIXTURE)
        self.assert_fails_naming(
            self.classify(population, baseline=baseline, pending={**self.LEDGERS["pending"], path: "I2a"}),
            "PENDING ledger grew", path,
        )

    def test_classified_files_cannot_gain_new_or_duplicate_retired_lines(self) -> None:
        for path in ("scripts/active.py", "scripts/history.py", "scripts/pending.py"):
            for addition in ("DEFAULT = 'HuGR-dev/corelink-server'\n", self.CLEAN[path]):
                with self.subTest(path=path, addition=addition):
                    population = dict(self.CLEAN)
                    population[path] += addition
                    self.assert_fails_naming(self.classify(population), "retired identity lines grew", path)
        population = dict(self.CLEAN)
        population["scripts/pending.py"] = population["scripts/pending.py"].replace("HuGR-dev", "HumanGuardrail")
        self.assert_fails_naming(self.classify(population), "retired identity lines grew", "scripts/pending.py")
        # Removing migration debt is permitted once its stale classification is removed.
        population = dict(self.CLEAN)
        population["scripts/pending.py"] = "migrated = True\n"
        self.assertEqual(self.classify(population, pending={}), [])

    def test_new_retired_lines_fail_in_every_real_classification(self) -> None:
        population = dict(self.real_population)
        cases = (
            "scripts/stripe_test_mode_evidence.py",
            ".github/workflows/corelink-server.yml",
            ".github/workflows/bot-pr-has-checks.yml",
            "scripts/test_b152_actions_diagnostic.py",
            "scripts/b250_deleted_workflow_startup_failure.py",
        )
        for path in cases:
            with self.subTest(path=path):
                candidate = dict(population)
                candidate[path] += "\nDEFAULT = 'HuGR-dev/corelink-server'\n"
                errors = classify_identity_literals(
                    {path: candidate[path]}, read_identity(),
                    active={path: ACTIVE_IDENTITY_LITERAL_ALLOWLIST[path]} if path in ACTIVE_IDENTITY_LITERAL_ALLOWLIST else {},
                    historical={path: HISTORICAL_IDENTITY_LITERAL_ALLOWLIST[path]} if path in HISTORICAL_IDENTITY_LITERAL_ALLOWLIST else {},
                    pending={path: PENDING_IDENTITY_MIGRATION[path]} if path in PENDING_IDENTITY_MIGRATION else {},
                    baseline=read_literal_baseline(),
                )
                self.assert_fails_naming(errors, "retired identity lines grew", path)

    def test_empty_population_is_a_failure_not_a_pass(self) -> None:
        errors = self.classify({})
        self.assertEqual(len(errors), 1)
        self.assertIn("EMPTY", errors[0])

    def test_scan_reaches_the_files_it_must_see(self) -> None:
        population = dict(self.real_population)
        for relative in (
            "config/github-identity.json",
            "config/github-identity-literal-baseline.json",
            "scripts/server_repository.py",
            "scripts/test_server_repository_identity.py",
            ".github/workflows/python-tests.yml",
            "scripts/windows_signing_readiness.ps1",
            "apps/dsr-alert-receiver/scripts/receiver-target.mjs",
        ):
            with self.subTest(path=relative):
                self.assertTrue(relative in population, f"scan missed tracked file: {relative}")
        self.assertGreater(len(population), 1000)

    def test_all_identity_literals_in_the_tree_are_classified(self) -> None:
        errors = classify_identity_literals(
            self.real_population,
            read_identity(),
            active=ACTIVE_IDENTITY_LITERAL_ALLOWLIST,
            historical=HISTORICAL_IDENTITY_LITERAL_ALLOWLIST,
            pending=PENDING_IDENTITY_MIGRATION,
            read_outside=read_repository_file,
            baseline=read_literal_baseline(),
        )
        self.assertEqual(errors, [], "\n".join(errors))


class ExistingIdentityContractTests(unittest.TestCase):
    def test_literal_scanner_covers_url_api_peer_numeric_and_current_variants(self) -> None:
        for literal in (
            "https://github.com/HuGR-Labs/corelink-server",
            "https://github.com/HuGR-dev/corelink-server.git",
            "git@github.com:HumanGuardrail/corelink-server.git",
            "repos/HuGR-Labs/corelink-server/actions/runs",
            "https://github.com/HuGR-dev/corelink-runners",
            "HuGR-dev/corelink-workspaces",
            "github.repository_id == '1232040291'",
            "corelink-dev/corelink-server",
        ):
            with self.subTest(literal=literal):
                self.assertRegex(literal, IDENTITY_LITERAL_PATTERN)
        for unrelated in ("https://github.com/HuGR-Labs/corelink-cli", "run 12320402910", "corelink-dev"):
            with self.subTest(unrelated=unrelated):
                self.assertNotRegex(unrelated, IDENTITY_LITERAL_PATTERN)

    def test_evidence_pack_signer_preserves_historical_and_current_exact_owners(self) -> None:
        script = (ROOT / "scripts/build-pentest-evidence-pack.sh").read_text(encoding="utf-8")
        match = re.search(r"--certificate-identity-regexp '([^']+)'", script)
        self.assertIsNotNone(match)
        pattern = match.group(1)
        for owner in ("HumanGuardrail", "HuGR-Labs", "HuGR-dev"):
            with self.subTest(owner=owner):
                self.assertIsNotNone(
                    re.fullmatch(
                        pattern,
                        f"https://github.com/{owner}/corelink-server/.github/workflows/sign.yml",
                    )
                )
        for unauthorized in (
            "attacker",
            "HuGR-Labs-fork",
            "HuGR-dev-evil",
        ):
            with self.subTest(unauthorized=unauthorized):
                self.assertIsNone(
                    re.fullmatch(
                        pattern,
                        f"https://github.com/{unauthorized}/corelink-server/.github/workflows/sign.yml",
                    )
                )

    def test_reintroduced_source_owner_fails_current_projection_guard(self) -> None:
        current_readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for owner, error in (("HuGR-Labs", "stale source owner"), ("HumanGuardrail", "historical owner")):
            mutated = current_readme + f"\nhttps://github.com/{owner}/corelink-server/issues\n"
            with self.subTest(owner=owner), self.assertRaisesRegex(AssertionError, error):
                assert_current_projection_owner_is_not_stale("README.md", mutated)

    def test_active_consumers_have_no_silent_retired_default(self) -> None:
        identity = read_identity()
        server = identity.repository("server").name
        pre_transfer = ("HuGR-Labs", "HumanGuardrail")
        for relative in ACTIVE_NO_STALE_DEFAULTS:
            contents = (ROOT / relative).read_text(encoding="utf-8")
            declared = NEGATIVE_FIXTURE_LINES.get(relative, ())
            for line in declared:
                with self.subTest(path=relative, negative_fixture=line):
                    self.assertEqual(
                        [candidate.strip() for candidate in contents.splitlines()].count(line),
                        1,
                        "stale NEGATIVE_FIXTURE_LINES row: the declared line is gone or duplicated",
                    )
            executable = "\n".join(
                line
                for line in contents.splitlines()
                if not line.lstrip().startswith("#") and line.strip() not in declared
            )
            # A file still pending migration may carry the retired destination
            # until its owning PR; no consumer may carry a pre-transfer owner.
            owners = pre_transfer if relative in PENDING_IDENTITY_MIGRATION else identity.historical_server_owners
            with self.subTest(path=relative):
                for owner in owners:
                    self.assertNotIn(f"{owner}/{server}", executable)

    def test_silent_defaults_and_duplicate_declared_negative_fixtures_have_teeth(self) -> None:
        original_read = Path.read_text
        server = read_identity().repository("server").name
        cases = [
            ("scripts/server_repository.py", f"\nDEFAULT = '{owner}/{server}'\n")
            for owner in read_identity().historical_server_owners
        ]
        pinned = "scripts/verify_real_ignored_harnesses.py"
        cases.append((pinned, "\n" + NEGATIVE_FIXTURE_LINES[pinned][0] + "\n"))
        for relative, addition in cases:
            target = ROOT / relative
            def planted_read(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                return text + addition if path == target else text
            with self.subTest(path=relative, addition=addition), patch.object(Path, "read_text", planted_read):
                result = unittest.TestResult()
                type(self)("test_active_consumers_have_no_silent_retired_default").run(result)
                self.assertTrue(result.failures, "planted default/duplicated fixture passed its consumer gate")

    def test_history_allowlist_is_explicit_and_remains_byte_identity_bound(self) -> None:
        self.assertEqual(
            len(ACTIVE_IDENTITY_LITERAL_ALLOWLIST)
            + len(HISTORICAL_IDENTITY_LITERAL_ALLOWLIST)
            + len(PENDING_IDENTITY_MIGRATION),
            len(
                set(ACTIVE_IDENTITY_LITERAL_ALLOWLIST)
                | set(HISTORICAL_IDENTITY_LITERAL_ALLOWLIST)
                | set(PENDING_IDENTITY_MIGRATION)
            ),
            "an identity literal must have one unambiguous classification",
        )
        retired = identity_literal_patterns(read_identity()).retired
        for relative, reason in HISTORICAL_IDENTITY_LITERAL_ALLOWLIST.items():
            with self.subTest(path=relative):
                self.assertTrue(reason.strip())
                contents = (ROOT / relative).read_text(encoding="utf-8")
                self.assertRegex(contents, retired)

    # Lockstep with I2b/I4/I9 (PLAN §4.2): these projections still name the
    # pre-recreate destination; the PR that moves each file updates it here.
    def test_current_user_facing_projections_name_the_destination_or_stable_resolver(self) -> None:
        destination = "HuGR-dev/corelink-server"
        projections = {
            ".github/ISSUE_TEMPLATE/config.yml": (destination,),
            "README.md": (destination,),
            "CONTRIBUTING.md": (destination,),
            "apps/get-corelink-worker/README.md": (destination,),
            "apps/docs/lychee.toml": (destination,),
            "apps/docs/src/pages/compare/vs-bazel-remote-s3.mdx": (destination,),
            "apps/docs/src/pages/compare/vs-buildbuddy.mdx": (destination,),
            "apps/docs/src/pages/compare/vs-engflow.mdx": (destination,),
            "apps/docs/src/pages/compare/vs-nx-cloud.mdx": (destination,),
            "apps/docs/src/pages/compare/vs-sccache-s3.mdx": (destination,),
            "apps/docs/src/pages/compare/vs-turborepo.mdx": (destination,),
            "crates/corelink-audit/src/link_hash.rs": (destination,),
            "crates/corelink-rate-headers/README.md": (destination,),
            "tools/sbom-publish/src/purl.rs": (destination,),
            "docs/internal/ENGINEERING-ONBOARDING.md": (destination,),
            "docs/internal/pentest-engagement-checklist.md": (destination,),
            "docs/internal/slsa-l3-pipeline.md": (destination, "HuGR-Labs/corelink-server"),
            "docs/build/reproducible.md": ("python3 scripts/server_repository.py",),
            "docs/internal/ci-runner-fabric-box.md": ("python3 scripts/server_repository.py",),
            "docs/internal/FORENSICS-GUIDE.md": ("repositories/1232040291",),
            "crates/corelink-ops/src/deploy.rs": (destination,),
            "crates/corelink-ops/src/deploy/types.rs": (destination,),
            "crates/corelink-ops/src/supply_chain/verify.rs": (destination,),
            "crates/corelink-ops/src/supply_chain/verify/verifier.rs": (destination,),
            "crates/corelink-ops/src/supply_chain/verify/bin/cli.rs": (destination,),
            "crates/corelink-ops/src/supply_chain/verify/types.rs": (destination,),
            "crates/corelink-ops/examples/supply_chain_verify_verify_basic.rs": (destination,),
            "docs/operator/e2e-ci-2026-05-30.md": (destination,),
            "docs/internal/OSS-VS-CLOSED-MATRIX.md": (destination,),
            "docs/OSS_STRATEGY.md": (destination,),
            "examples/bazel-starter/README.md": (destination,),
            "examples/buck2-starter/README.md": (destination,),
            "marketing/profile-readme.md": (destination,),
            "marketing/org-readme.md": (destination,),
            "marketing/og/README.md": (destination,),
            "marketing/retention/customer-health/SURVEY-ANALYSIS-PROTOCOL.md": (destination,),
            "marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md": (destination,),
            "marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md": (destination,),
            "marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md": (destination,),
        }
        for relative, markers in projections.items():
            contents = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                for marker in markers:
                    self.assertIn(marker, contents)
                assert_current_projection_owner_is_not_stale(relative, contents)
        runner_doc = (ROOT / "docs/internal/ci-runner-fabric-box.md").read_text(encoding="utf-8")
        live_commands = runner_doc.split("## 11. Re-measuring", maxsplit=1)[1].split(
            "## Provenance note", maxsplit=1
        )[0]
        self.assertIn('--repo "$(python3 scripts/server_repository.py)"', live_commands)
        self.assertNotRegex(live_commands, r"(?i)HuGR-Labs/corelink-server")
        compose = (ROOT / "infra/ci-runners/linux/docker-compose.yml").read_text()
        self.assertIn("${REPO_URL:?", compose)
        self.assertIn("HuGR-Labs/corelink-server", compose)
        self.assertIn("HuGR-dev/corelink-server", compose)
        for path in (ROOT / "infra/grafana/dashboards").glob("*.json"):
            contents = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIn(destination, contents)
                self.assertNotRegex(contents, r"(?i)(?:HuGR-Labs|HumanGuardrail)/corelink-server")

    # Lockstep with I2a: the guards below move to the configured ID in I2a.
    def test_self_repository_workflows_use_numeric_id_guards(self) -> None:
        for relative in (
            ".github/workflows/runner-fleet-health.yml",
            ".github/workflows/real-ignored-harnesses.yml",
            ".github/workflows/workflow-state-guard.yml",
            ".github/workflows/bot-pr-has-checks.yml",
        ):
            with self.subTest(path=relative):
                self.assertIn("github.repository_id == '1232040291'", (ROOT / relative).read_text())

    def test_bot_workflow_accepts_only_exact_source_and_destination_contexts(self) -> None:
        workflow = (ROOT / ".github/workflows/bot-pr-has-checks.yml").read_text()
        self.assertIn('"HuGR-Labs/corelink-server", "HuGR-dev/corelink-server"', workflow)
        self.assertIn('os.environ.get("REPOSITORY_ID") != "1232040291"', workflow)
        self.assertNotIn('os.environ.get("REPO") or "HuGR-Labs/corelink-server"', workflow)

    def test_evidence_verifier_has_no_implicit_source_owner(self) -> None:
        verifier = (ROOT / "scripts/verify_b102_b108_evidence.py").read_text()
        self.assertIn("REPO: str | None = None", verifier)
        self.assertIn("REPO = resolve_server_repository(args.repo)", verifier)
        self.assertNotIn("os.environ.get(\"CORELINK_EXPECTED_REPOSITORY\", SOURCE_REPO)", verifier)
        self.assertNotIn("SOURCE_REPO", verifier)

    def test_cli_repository_and_runner_labels_are_not_server_aliases(self) -> None:
        workflow = (ROOT / ".github/workflows/release-cli.yml").read_text()
        watchdog = (ROOT / "scripts/runner_wedge_watchdog.py").read_text()
        self.assertIn("HuGR-Labs/corelink-cli", workflow)
        self.assertIn("actions.runner.HuGR-Labs-corelink-server", watchdog)

    def assert_identity_path_coverage(self, workflows: Mapping[str, str]) -> None:
        for name in ("python-tests.yml", "b046-object-lock-receipt-contract.yml", "issue-1721-r2-lock-proof.yml"):
            workflow = workflows[name]
            count = 2 if name == "python-tests.yml" else 1
            for path in ("config/github-identity.json", "scripts/server_repository.py"):
                covered = workflow.count(f"- '{path}'") + workflow.count(f"- {path}\n")
                if path == "scripts/server_repository.py" and name == "python-tests.yml":
                    covered += workflow.count("- 'scripts/**'")
                self.assertGreaterEqual(covered, count, f"{name} does not trigger on {path}")
        self.assertGreaterEqual(workflows["python-tests.yml"].count("- 'config/github-identity-literal-baseline.json'"), 2)

    def test_ci_path_coverage_rejects_each_removed_identity_dependency(self) -> None:
        workflows = {name: (ROOT / ".github/workflows" / name).read_text() for name in (
            "python-tests.yml", "b046-object-lock-receipt-contract.yml", "issue-1721-r2-lock-proof.yml",
        )}
        self.assert_identity_path_coverage(workflows)
        for name, workflow in workflows.items():
            paths = ("config/github-identity.json", "scripts/server_repository.py")
            if name == "python-tests.yml":
                paths = (*paths, "config/github-identity-literal-baseline.json")
            for path in paths:
                with self.subTest(workflow=name, path=path):
                    candidate = dict(workflows)
                    candidate[name] = "\n".join(line for line in workflow.splitlines() if not (
                        line.strip() in {f"- '{path}'", f"- {path}"} or
                        (path == "scripts/server_repository.py" and line.strip() == "- 'scripts/**'")
                    ))
                    with self.assertRaises(AssertionError):
                        self.assert_identity_path_coverage(candidate)

    def test_identity_suite_is_registered_with_matching_path_coverage(self) -> None:
        workflows = {name: (ROOT / ".github/workflows" / name).read_text() for name in (
            "python-tests.yml", "b046-object-lock-receipt-contract.yml", "issue-1721-r2-lock-proof.yml",
        )}
        self.assert_identity_path_coverage(workflows)
        workflow = workflows["python-tests.yml"]
        self.assertIn("scripts/test_server_repository_identity.py", workflow)
        self.assertIn('python3 -m pytest "${FILES[@]}" "${REQUIRED_SUITES[@]}" -q', workflow)
        self.assertGreaterEqual(workflow.count("- 'scripts/**'"), 2)
        self.assertGreaterEqual(workflow.count("- 'CHANGELOG.md'"), 2)
        self.assertGreaterEqual(workflow.count("- 'crates/**'"), 2)
        self.assertGreaterEqual(workflow.count("- 'tools/sbom-publish/**'"), 2)
        self.assertGreaterEqual(workflow.count("- '**/Cargo.toml'"), 2)
        self.assertGreaterEqual(workflow.count("- 'Cargo.lock'"), 2)
        self.assertGreaterEqual(workflow.count("- '.github/workflows/python-tests.yml'"), 2)
        for glob in (
            "infra/**",
            "marketing/**",
            "apps/docs/lychee.toml",
            "specs/_dashboards/**",
            "examples/**",
            "docs/OSS_STRATEGY.md",
        ):
            self.assertGreaterEqual(workflow.count(f"- '{glob}'"), 2)
        for path in (
            ".github/workflows/bot-pr-has-checks.yml",
            ".github/workflows/cas_foundation.yml",
            ".github/workflows/mutation-nightly.yml",
            ".github/workflows/perf-production-evidence.yml",
            ".github/workflows/real-ignored-harnesses.yml",
            ".github/workflows/release-cli.yml",
            ".github/workflows/release-slsa3.yml",
            ".github/workflows/runner-fleet-health.yml",
            ".github/workflows/semgrep.yml",
            ".github/workflows/workflow-state-guard.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/CODEOWNERS",
            "README.md",
            "CONTRIBUTING.md",
            "apps/get-corelink-worker/README.md",
            "apps/docs/src/pages/compare/vs-bazel-remote-s3.mdx",
            "apps/docs/src/pages/compare/vs-buildbuddy.mdx",
            "apps/docs/src/pages/compare/vs-engflow.mdx",
            "apps/docs/src/pages/compare/vs-nx-cloud.mdx",
            "apps/docs/src/pages/compare/vs-sccache-s3.mdx",
            "apps/docs/src/pages/compare/vs-turborepo.mdx",
            "docs/build/reproducible.md",
            "docs/internal/ci-runner-fabric-box.md",
            "docs/internal/ENGINEERING-ONBOARDING.md",
            "docs/internal/FORENSICS-GUIDE.md",
            "docs/internal/pentest-engagement-checklist.md",
            "docs/internal/slsa-l3-pipeline.md",
            "docs/security/report-security.md",
        ):
            with self.subTest(path=path):
                self.assertGreaterEqual(workflow.count(f"- '{path}'"), 2)


# Live API consumers must not carry a fixed retired default. Exact aliases
# remain only in the shared allow-list, explicit transfer cutover, and the
# workflow that validates the context name alongside the immutable repo ID.
ACTIVE_NO_STALE_DEFAULTS = (
    ".github/workflows/runner-fleet-health.yml",
    ".github/workflows/real-ignored-harnesses.yml",
    ".github/workflows/workflow-state-guard.yml",
    "scripts/check_runner_fleet.py",
    "scripts/verify_real_ignored_harnesses.py",
    "scripts/ci/full-ci-dispatch.sh",
    "scripts/runner_wedge_watchdog.py",
    "scripts/check_workflow_state.py",
    "scripts/rotate-cli-release-token.sh",
    "scripts/b152_actions_diagnostic.py",
    "scripts/verify_b028_dependabot.py",
    "scripts/verify_b373_dependabot.py",
    "scripts/gen-grafana-provision.py",
    ".github/workflows/release-slsa3.yml",
    ".github/workflows/release-cli.yml",
    "scripts/build-pentest-evidence-pack.sh",
    "scripts/server_repository.py",
    "scripts/build_b046_object_lock_receipt.py",
    "scripts/collect_b102_b108_context.py",
    "scripts/issue_2568_sla_credit_real.py",
    "scripts/validate_i1721_r2_dispatch.sh",
    "scripts/verify_b102_b108_evidence.py",
)


if __name__ == "__main__":
    unittest.main()
