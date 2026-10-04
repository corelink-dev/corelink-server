#!/usr/bin/env python3
"""Focused regression tests for server identity resolution and consumers."""

from __future__ import annotations

import io
import os
import re
import subprocess
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from server_repository import (
    DESTINATION_REPOSITORY,
    REPOSITORY_ID,
    SOURCE_REPOSITORY,
    main,
    resolve_server_repository,
    validate_server_repository,
)

ROOT = Path(__file__).resolve().parents[1]

# These references bind retained records, not a live API destination. Their
# owner/repository fields and signed/hashed payloads must remain unchanged.
ACTIVE_IDENTITY_LITERAL_ALLOWLIST = {
    ".github/ISSUE_TEMPLATE/config.yml": "Current security-advisory and discussion destinations use the post-transfer server owner.",
    ".github/workflows/bot-pr-has-checks.yml": "This live workflow allows exactly source/destination repo names only after checking stable repository ID.",
     ".github/workflows/ci-clone-bundle.yml": "Clone-only guard accepts the destination only with its exact numeric repository ID.",
     ".github/workflows/sbom-clone-bundle.yml": "Bounded SBOM clone job accepts the destination only with its exact numeric repository ID.",
     "scripts/verify_ci_clone_bundle.py": "The stdlib verifier pins the exact clone destination repository identity.",
    "apps/docs/src/pages/compare/vs-bazel-remote-s3.mdx": "Current product documentation references the post-transfer server security intake.",
    "apps/docs/src/pages/compare/vs-buildbuddy.mdx": "Current product documentation references the post-transfer server security intake.",
    "apps/docs/src/pages/compare/vs-engflow.mdx": "Current product documentation references the post-transfer server security intake.",
    "apps/docs/src/pages/compare/vs-nx-cloud.mdx": "Current product documentation references the post-transfer server security intake.",
    "apps/docs/src/pages/compare/vs-sccache-s3.mdx": "Current product documentation references the post-transfer server security intake.",
    "apps/docs/src/pages/compare/vs-turborepo.mdx": "Current product documentation references the post-transfer server security intake.",
    "apps/docs/lychee.toml": "Current link-check exception uses the destination server edit URL pattern.",
    "apps/get-corelink-worker/README.md": "Current server deployment documentation names the post-transfer owner and keeps CLI identity separate.",
    "crates/corelink-audit/src/link_hash.rs": "The source-code documentation link resolves to the current server specification location.",
    "crates/corelink-client-verify/Cargo.toml": "Published crate metadata advertises the post-transfer server repository.",
    "crates/corelink-hash/Cargo.toml": "Published crate metadata advertises the post-transfer server repository.",
    "crates/corelink-rate-headers/Cargo.toml": "Published crate metadata advertises the post-transfer server repository.",
    "crates/tenant-path/Cargo.toml": "Published crate metadata advertises the post-transfer server repository.",
    "crates/corelink-rate-headers/README.md": "Current source documentation link targets the post-transfer server repository.",
    "crates/corelink-ops/src/deploy/types.rs": "Current API docs use the destination; Cosign tests retain the historic signer and test exact source/destination and whole-SAN matching.",
    "crates/corelink-ops/src/deploy.rs": "Current deploy API example uses the destination; immutable signed test fixtures remain in dedicated tests.",
    "crates/corelink-ops/src/supply_chain/verify.rs": "Current public quick-start example selects the destination builder identity.",
    "crates/corelink-ops/src/supply_chain/verify/verifier.rs": "Current public verifier example selects the destination builder identity.",
    "crates/corelink-ops/src/supply_chain/verify/bin/cli.rs": "Current CLI examples/reporting use destination; historical SAN examples remain explicit fixtures.",
    "crates/corelink-ops/src/supply_chain/verify/types.rs": "Current BuilderIdentity docs use destination while explicit historical/source/destination tests preserve verification behavior.",
    "crates/corelink-ops/examples/supply_chain_verify_verify_basic.rs": "Current runnable SLSA example selects the destination builder identity.",
    "crates/corelink-ops/examples/supply_chain_verify_paranoid_mode.rs": "Example reports to current security intake while preserving a historical provenance SAN fixture.",
    "tests/test_b132_secrets_evidence.py": "Behavioral test passes the exact source repo explicitly; it is not a fallback default.",
    "tests/test_b142_codeql_selfhost.py": "Behavioral test passes the exact source repo explicitly; it is not a fallback default.",
    "tests/test_cli_release_b112_behavior.py": "Release tests exercise the exact pre-transfer server source identity.",
    "tests/test_verify_b155_batch_g.py": "Adversarial workflow tests inject the old owner-name guard to prove it is rejected.",
    "tools/sbom-publish/src/purl.rs": "Current SBOM workspace PURLs use the post-transfer repository URL.",
    "tools/sbom-publish/tests/adversarial.rs": "Adversarial SBOM test asserts the current emitted workspace VCS URL.",
    "scripts/collect_b102_b108_context.py": "Evidence capture accepts only exact server source/destination identities.",
    "scripts/cut-v1-0-0-ga-tag.sh": "Transfer cutover remote check accepts exactly the source and destination remotes.",
    "scripts/server_repository.py": "Shared live resolver maps numeric repository ID to the exact authorized source/destination allowlist.",
    "scripts/test_b102_b108_evidence.py": "Behavioral tests exercise exact source/destination evidence contexts and reject CLI/lookalikes.",
    "tests/test_verify_b028_dependabot.py": "The API-failure fixture supplies the repository resolved by the exact destination resolver contract.",
    "scripts/test_server_repository_identity.py": "This regression suite contains positive and negative identity examples and scan rules.",
    "scripts/verify_b102_b108_evidence.py": "Packet verification requires a selected exact repo; source constant denotes historical packet identity, not a live default.",
    "infra/ci-runners/linux/docker-compose.yml": "Self-hosted runner checkout URL is a required exact source/destination setting, not an old-owner default; runner labels remain unchanged.",
    "infra/grafana/dashboards/dash-audit-chain.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-billing.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-byok-health.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-capacity-planning.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-compliance-health.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-customer-traffic.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-dr-status.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-dsr-pipeline.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-incident-triage.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-ratelimit-abuse.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-reliability.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "infra/grafana/dashboards/dash-slo-burndown.json": "Generated current dashboard source/catalog links use the post-transfer server location.",
    "docs/operator/e2e-ci-2026-05-30.md": "Current operator setup instructions target the destination server repo.",
    "docs/internal/OSS-VS-CLOSED-MATRIX.md": "Current repository ownership projection names the destination server repo.",
    "docs/OSS_STRATEGY.md": "Current strategy ownership and source-location references name the destination server repo.",
    "examples/bazel-starter/README.md": "Current starter example clone instructions target the destination server repo.",
    "examples/buck2-starter/README.md": "Current starter example clone instructions target the destination server repo.",
    "marketing/profile-readme.md": "Current profile README links to the destination server repo; CLI stays independent.",
    "marketing/org-readme.md": "Current org README links to the destination server repo; CLI stays independent.",
    "marketing/og/README.md": "Current Open Graph image setup points to the destination server settings.",
    "marketing/retention/customer-health/SURVEY-ANALYSIS-PROTOCOL.md": "Current engineering-issue routing points to the destination server repo.",
    "marketing/sales/legal-questionnaires/EVIDENCE-PACK-INDEX.md": "Current evidence packet source-of-truth location is the destination server repo.",
    "marketing/sales/legal-questionnaires/SIG-LITE-2026-pre-filled.md": "Current security-evidence response identifies the destination server repo.",
    "marketing/sales/legal-questionnaires/VENDOR-QUESTIONNAIRE-RESPONSE-TEMPLATE.md": "Current response template identifies the destination server repo.",
    "docs/internal/ENGINEERING-ONBOARDING.md": "Current onboarding links point to the destination server repository.",
    "docs/internal/pentest-engagement-checklist.md": "Current pentest workflow points to the destination server repository.",
    "docs/internal/ci-runner-fabric-box.md": "Current commands resolve the live repository while dated run links retain the source identity.",
    "docs/internal/slsa-l3-pipeline.md": "Current builder guidance names the destination while retaining pre-transfer verification examples.",
    "scripts/test_org_migration_audit.py": "Reusable migration-auditor fixtures deliberately exercise historical and current server identities.",
}

# These references bind retained records, cryptographic certificates, or dated
# audit history, not a live API destination. Their identities must not be
# rewritten as part of the repository transfer.
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
}

# These docs intentionally mention the source owner: the SLSA guide documents
# pre-transfer receipt verification, and the runner-fabric guide contains
# dated source-owner run links. Other current projections must not present the
# source as their current destination.
SOURCE_ALIAS_PROJECTION_ALLOWLIST = {
    "docs/internal/ci-runner-fabric-box.md": "Dated P1/P2 runner probe links preserve the original source-owner action-run URLs; current instructions resolve by repository ID.",
    "docs/internal/slsa-l3-pipeline.md": "The guide names the exact source only for verifying pre-transfer artifacts; destination is the current builder.",
}


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

IDENTITY_LITERAL_PATTERN = re.compile(
    r"(?i)(?:https?://)?(?:github\.com[/:])?(?:hugr-labs|hugr-dev|humanguardrail)/corelink-server"
)

# Live API consumers must not carry a fixed pre-transfer default. Exact aliases
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
)


class ServerRepositoryIdentityTests(unittest.TestCase):
    def test_literal_scanner_covers_github_url_and_api_path_variants(self) -> None:
        for literal in (
            "https://github.com/HuGR-Labs/corelink-server",
            "https://github.com/HuGR-dev/corelink-server.git",
            "git@github.com:HumanGuardrail/corelink-server.git",
            "repos/HuGR-Labs/corelink-server/actions/runs",
        ):
            with self.subTest(literal=literal):
                self.assertRegex(literal, IDENTITY_LITERAL_PATTERN)
        self.assertNotRegex("https://github.com/HuGR-Labs/corelink-cli", IDENTITY_LITERAL_PATTERN)

    def test_only_exact_source_and_destination_names_are_authorized(self) -> None:
        self.assertEqual(validate_server_repository(SOURCE_REPOSITORY), SOURCE_REPOSITORY)
        self.assertEqual(validate_server_repository(DESTINATION_REPOSITORY), DESTINATION_REPOSITORY)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_server_repository(SOURCE_REPOSITORY), SOURCE_REPOSITORY)
            self.assertEqual(resolve_server_repository(DESTINATION_REPOSITORY), DESTINATION_REPOSITORY)
            with self.assertRaises(ValueError):
                resolve_server_repository("attacker/corelink-server")
        for invalid in (
            "attacker/corelink-server",
            "HuGR-Labs/corelink-server-evil",
            "HuGR-dev/corelink-server-fork",
            "HuGR-Labs/corelink-cli",
            "HumanGuardrail/corelink-server",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_server_repository(invalid)

        canary = "attacker/canary-private-name-7461"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(main(["--repo", canary]), 2)
        self.assertNotIn(canary, stderr.getvalue())
        self.assertIn("not an authorized CoreLink server repository", stderr.getvalue())

    def test_repository_topology_matrix_source_destination_peers_distinct_and_attacker(self) -> None:
        source_peers = ("HuGR-Labs/corelink-cli", "HuGR-Labs/corelink-workspaces")
        topologies = (
            ("all-source", SOURCE_REPOSITORY, source_peers, True),
            ("server-destination-peers-source", DESTINATION_REPOSITORY, source_peers, True),
            # Peer organizations are independent. This fixture intentionally
            # puts the workspace peer elsewhere without creating a new server
            # alias or changing the independent CLI identity.
            (
                "peers-in-distinct-orgs",
                DESTINATION_REPOSITORY,
                ("HuGR-Labs/corelink-cli", "HuGR-dev/corelink-workspaces"),
                True,
            ),
            ("attacker-server", "attacker/corelink-server", source_peers, False),
        )
        for topology, repository, peers, authorized in topologies:
            with self.subTest(topology=topology):
                if authorized:
                    self.assertEqual(validate_server_repository(repository), repository)
                    self.assertEqual(resolve_server_repository(repository), repository)
                    for peer in peers:
                        with self.subTest(peer=peer), self.assertRaises(ValueError):
                            validate_server_repository(peer)
                else:
                    with self.assertRaises(ValueError):
                        validate_server_repository(repository)
                    with self.assertRaises(ValueError):
                        resolve_server_repository(repository)

    def test_github_context_requires_stable_numeric_repository_id(self) -> None:
        with patch.dict(
            os.environ,
            {"GITHUB_REPOSITORY_ID": REPOSITORY_ID, "GITHUB_REPOSITORY": DESTINATION_REPOSITORY},
            clear=True,
        ):
            self.assertEqual(resolve_server_repository(), DESTINATION_REPOSITORY)
        with patch.dict(
            os.environ,
            {"GITHUB_REPOSITORY_ID": "999", "GITHUB_REPOSITORY": SOURCE_REPOSITORY},
            clear=True,
        ), self.assertRaises(ValueError):
            resolve_server_repository()

    def test_local_default_queries_numeric_id_and_never_accepts_redirect_owner(self) -> None:
        completed = subprocess.CompletedProcess(
            ["gh"], 0, stdout=DESTINATION_REPOSITORY + "\n", stderr=""
        )
        with patch.dict(os.environ, {}, clear=True), patch(
            "server_repository.subprocess.run", return_value=completed
        ) as run:
            self.assertEqual(resolve_server_repository(), DESTINATION_REPOSITORY)
        self.assertEqual(
            run.call_args.args[0],
            ["gh", "api", f"repositories/{REPOSITORY_ID}", "--jq", ".full_name"],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        historical_redirect = subprocess.CompletedProcess(
            ["gh"], 0, stdout="HumanGuardrail/corelink-server\n", stderr=""
        )
        with patch.dict(os.environ, {}, clear=True), patch(
            "server_repository.subprocess.run", return_value=historical_redirect
        ), self.assertRaises(ValueError):
            resolve_server_repository()

    def test_evidence_pack_signer_preserves_historical_and_current_exact_owners(self) -> None:
        script = (ROOT / "scripts/build-pentest-evidence-pack.sh").read_text(encoding="utf-8")
        matches = re.findall(r"--certificate-identity-regexp '([^']+)'", script)
        self.assertEqual(len(matches), 2)
        pattern = matches[1]
        # cosign compiles this with Go RE2, which rejects \Z ("invalid escape
        # sequence"); Python 3.12, which runs this suite, rejects \z. ^ and $
        # mean start and end of text in RE2 without the m flag.
        self.assertNotRegex(pattern, r"\\[zZ]")
        # cosign matches the SAN unanchored (regexp.MatchString), so this test
        # uses re.search: the pattern's own anchors must do the rejecting.
        workflow = "/corelink-server/.github/workflows/sign.yml"
        # corelink-dev is the current owner. The earlier owners stay so packs
        # they signed still verify in this historical-only command.
        owners = ("HumanGuardrail", "HuGR-Labs", "HuGR-dev", "corelink-dev")
        for owner in owners:
            with self.subTest(owner=owner):
                self.assertIsNotNone(re.search(pattern, f"https://github.com/{owner}{workflow}"))
        for unauthorized in (
            "attacker",
            "HuGR-Labs-fork",
            "HuGR-dev-evil",
            "corelink-dev-evil",
            "attacker/corelink-dev",
        ):
            with self.subTest(unauthorized=unauthorized):
                self.assertIsNone(re.search(pattern, f"https://github.com/{unauthorized}{workflow}"))
        for owner in owners:
            for repository in ("corelink-server-evil", "corelink-runners", "corelink-workspaces"):
                with self.subTest(owner=owner, repository=repository):
                    self.assertIsNone(
                        re.search(
                            pattern,
                            f"https://github.com/{owner}/{repository}/.github/workflows/sign.yml",
                        )
                    )
        current = f"https://github.com/corelink-dev{workflow}"
        for embedded in (
            f"https://evil.example/?next={current}",
            f"{current}\nhttps://evil.example/",
        ):
            with self.subTest(embedded=embedded):
                self.assertIsNone(re.search(pattern, embedded))

    def test_current_release_and_historical_pack_have_separate_trust(self) -> None:
        script = (ROOT / "scripts/build-pentest-evidence-pack.sh").read_text(encoding="utf-8")
        patterns = re.findall(r"--certificate-identity-regexp '([^']+)'", script)
        self.assertEqual(len(patterns), 2, "current command and historical command required")
        self.assertIn("Historical artifacts only", script)
        deploy_types = (ROOT / "crates/corelink-ops/src/deploy/types.rs").read_text(encoding="utf-8")
        release = re.search(
            r'fn corelink_release\(\) -> Self \{\s*Self \{\s*pattern: r"([^"]+)"', deploy_types
        )
        self.assertIsNotNone(release, "CosignIdentityPattern::corelink_release pattern not found")
        self.assertIn(f"/// {release.group(1)}\n", deploy_types)
        for owner in ("HumanGuardrail", "HuGR-Labs", "HuGR-dev", "corelink-dev"):
            san = f"https://github.com/{owner}/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
            for label, pattern in (("current-pack", patterns[0]), ("current-deploy", release.group(1))):
                with self.subTest(owner=owner, path=label):
                    self.assertEqual(bool(re.search(pattern, san)), owner == "corelink-dev")
            with self.subTest(owner=owner, path="historical-pack"):
                self.assertIsNotNone(re.search(patterns[1], san))
        current = "https://github.com/corelink-dev/corelink-server/.github/workflows/release-slsa3.yml@refs/tags/v0.1.0"
        for label, pattern in (("current-pack", patterns[0]), ("current-deploy", release.group(1))):
            self.assertTrue(pattern.startswith("^") and pattern.endswith("$"))
            for invalid in (
                current.replace("corelink-dev/", "corelink-dev-evil/"),
                current.replace("corelink-server/", "corelink-server-evil/"),
                current.replace("corelink-server/", "corelink-runners/"),
                current.replace("corelink-dev/", "attacker/corelink-dev/"),
                f"https://evil.example/?next={current}",
                f"{current}\nhttps://evil.example/",
            ):
                with self.subTest(path=label, invalid=invalid):
                    self.assertIsNone(re.search(pattern, invalid))

    def test_signing_rustdoc_examples_use_current_owner(self) -> None:
        deploy = (ROOT / "crates/corelink-ops/src/deploy/types.rs").read_text(encoding="utf-8")
        workflow_doc = deploy.split("pub struct GitHubActor {", 1)[1].split("pub workflow_ref:", 1)[0]
        self.assertIn('"corelink-dev/corelink-server/', workflow_doc)
        builder = (ROOT / "crates/corelink-ops/src/supply_chain/verify/types.rs").read_text(encoding="utf-8")
        identity_doc = builder.split("/// Identity of the expected SLSA L3 builder", 1)[1].split("impl BuilderIdentity", 1)[0]
        self.assertIn("/// `https://github.com/corelink-dev/corelink-server/", identity_doc)
        self.assertIn("(e.g., `corelink-dev/corelink-server`)", identity_doc)
        self.assertIn("/// Must include org + repo, e.g., `corelink-dev/corelink-server`.", identity_doc)
        self.assertNotIn("HuGR-dev/corelink-server", identity_doc)
        fixtures = builder.split("#[cfg(test)]", 1)[1]
        self.assertIn('const DESTINATION_SAN: &str = "https://github.com/corelink-dev/corelink-server/', fixtures)

    def test_reintroduced_source_owner_fails_current_projection_guard(self) -> None:
        current_readme = (ROOT / "README.md").read_text(encoding="utf-8")
        mutated = current_readme + "\nhttps://github.com/HuGR-Labs/corelink-server/issues\n"
        with self.assertRaisesRegex(AssertionError, "stale source owner"):
            assert_current_projection_owner_is_not_stale("README.md", mutated)

    def test_active_consumers_have_no_silent_pre_transfer_default(self) -> None:
        forbidden = ("HuGR-Labs/corelink-server", "HumanGuardrail/corelink-server")
        for relative in ACTIVE_NO_STALE_DEFAULTS:
            contents = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                executable = "\n".join(
                    line for line in contents.splitlines() if not line.lstrip().startswith("#")
                )
                for literal in forbidden:
                    self.assertNotIn(literal, executable)

    def test_history_allowlist_is_explicit_and_remains_byte_identity_bound(self) -> None:
        self.assertEqual(
            len(ACTIVE_IDENTITY_LITERAL_ALLOWLIST) + len(HISTORICAL_IDENTITY_LITERAL_ALLOWLIST),
            len(set(ACTIVE_IDENTITY_LITERAL_ALLOWLIST) | set(HISTORICAL_IDENTITY_LITERAL_ALLOWLIST)),
            "an identity literal must have one unambiguous classification",
        )
        for relative, reason in HISTORICAL_IDENTITY_LITERAL_ALLOWLIST.items():
            with self.subTest(path=relative):
                self.assertTrue(reason.strip())
                contents = (ROOT / relative).read_text(encoding="utf-8")
                self.assertRegex(contents, IDENTITY_LITERAL_PATTERN)

    def test_all_code_identity_literals_are_classified_by_reason(self) -> None:
        classifications = {
            **ACTIVE_IDENTITY_LITERAL_ALLOWLIST,
            **HISTORICAL_IDENTITY_LITERAL_ALLOWLIST,
        }
        suffixes = {".py", ".sh", ".yml", ".yaml", ".rs", ".toml", ".md", ".mdx", ".json"}
        for directory in (
            ROOT / ".github",
            ROOT / "scripts",
            ROOT / "crates",
            ROOT / "tests",
            ROOT / "tools",
            ROOT / "infra",
            ROOT / "apps",
            ROOT / "marketing",
            ROOT / "examples",
        ):
            for path in directory.rglob("*"):
                if not path.is_file() or path.suffix not in suffixes and path.name != "CODEOWNERS":
                    continue
                if any(part in {"target", "node_modules", ".git"} for part in path.parts):
                    continue
                try:
                    contents = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                if not IDENTITY_LITERAL_PATTERN.search(contents):
                    continue
                relative = path.relative_to(ROOT).as_posix()
                with self.subTest(path=relative):
                    self.assertIn(relative, classifications, "unclassified live or historical server identity literal")
                    self.assertTrue(classifications[relative].strip())

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
            "crates/corelink-ops/src/deploy.rs": ("corelink-dev/corelink-server",),
            "crates/corelink-ops/src/deploy/types.rs": ("corelink-dev/corelink-server",),
            "crates/corelink-ops/src/supply_chain/verify.rs": ("corelink-dev/corelink-server",),
            "crates/corelink-ops/src/supply_chain/verify/verifier.rs": ("corelink-dev/corelink-server",),
            "crates/corelink-ops/src/supply_chain/verify/bin/cli.rs": (destination,),
            "crates/corelink-ops/src/supply_chain/verify/types.rs": ("corelink-dev/corelink-server",),
            "crates/corelink-ops/examples/supply_chain_verify_verify_basic.rs": ("corelink-dev/corelink-server",),
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
                current_docs = contents
                if relative in {
                    "crates/corelink-ops/src/deploy/types.rs",
                    "crates/corelink-ops/src/supply_chain/verify/types.rs",
                }:
                    current_docs = contents.split("#[cfg(test)]", maxsplit=1)[0]
                for marker in markers:
                    self.assertIn(marker, current_docs)
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

    def test_cli_repository_and_runner_labels_are_not_server_aliases(self) -> None:
        workflow = (ROOT / ".github/workflows/release-cli.yml").read_text()
        watchdog = (ROOT / "scripts/runner_wedge_watchdog.py").read_text()
        self.assertIn("HuGR-Labs/corelink-cli", workflow)
        self.assertIn("actions.runner.HuGR-Labs-corelink-server", watchdog)

    def test_identity_suite_is_registered_with_matching_path_coverage(self) -> None:
        workflow = (ROOT / ".github/workflows/python-tests.yml").read_text()
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


if __name__ == "__main__":
    unittest.main()
