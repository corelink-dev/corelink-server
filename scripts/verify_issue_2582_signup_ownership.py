#!/usr/bin/env python3
"""Fail-closed ownership census for signup-family writer changes (#2582)."""
from pathlib import Path
import os
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    ".github/workflows/issue-2582-signup-ownership.yml",
    "apps/signup-worker/src/signup_writer_ownership.ts",
    "apps/signup-worker/src/webhooks/clerk.ts",
    "apps/signup-worker/src/webhooks/github_install_callback.ts",
    "apps/signup-worker/src/webhooks/github_provision.ts",
    "apps/signup-worker/tests/signup_writer_ownership.test.ts",
    "crates/corelink-container/src/routes/signup.rs",
    "crates/corelink-container/src/routes/signup_support.rs",
    "crates/corelink-container/src/routes/signup_tests.rs",
    "crates/corelink-container/src/signup_d1_http.rs",
    "scripts/verify_issue_2582_signup_ownership.py",
    "tests/test_verify_issue_2582_signup_ownership.py",
}
# changelog-validate requires an ADDED changelog.d fragment on every feat:/fix:
# PR, so a signup-writer change may carry exactly one more shape: a flat,
# lowercase, ADDED fragment. A modified or deleted fragment, a nested or dotted
# path, CHANGELOG.md and every other path stay out of scope. Added-ness comes
# from git (--diff-filter=A), never from the path alone. The README exclusion
# mirrors changelog-validate; the lowercase first character already refuses it.
CHANGELOG_FRAGMENT = re.compile(r"^changelog\.d/[a-z0-9][a-z0-9._-]*\.md$")
CHANGELOG_README = "changelog.d/README.md"


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def is_added_changelog_fragment(path: str, added: frozenset[str] | set[str]) -> bool:
    return (
        path in added
        and path != CHANGELOG_README
        and CHANGELOG_FRAGMENT.fullmatch(path) is not None
    )


def out_of_scope_paths(changed: set[str], added: frozenset[str] | set[str]) -> list[str]:
    return sorted(
        path for path in changed
        if path not in ALLOWED and not is_added_changelog_fragment(path, added)
    )


def git_names(*diff_args: str) -> list[str]:
    return subprocess.check_output(
        ["git", "diff", "--name-only", *diff_args],
        cwd=ROOT,
        text=True,
    ).splitlines()


def verify_diff_scope() -> None:
    base = os.environ.get("EXPECTED_BASE")
    head = os.environ.get("EXPECTED_HEAD")
    if not base or not head:
        raise RuntimeError("EXPECTED_BASE and EXPECTED_HEAD are required")
    changed = git_names(f"{base}...{head}")
    if not changed:
        # The workflow only fires on a PR that changes a trigger path, so an
        # empty diff means the diff was read wrong, not that nothing changed.
        raise RuntimeError(f"empty changed-path list for {base}...{head}; refusing to pass vacuously")
    added = frozenset(git_names("--diff-filter=A", f"{base}...{head}"))
    outside = out_of_scope_paths(set(changed), added)
    if outside:
        raise RuntimeError("out-of-scope changed paths: " + ", ".join(outside))


def verify_census() -> None:
    rust_route = source("crates/corelink-container/src/routes/signup.rs")
    rust_d1 = source("crates/corelink-container/src/signup_d1_http.rs")
    clerk = source("apps/signup-worker/src/webhooks/clerk.ts")
    github = source("apps/signup-worker/src/webhooks/github_provision.ts")
    adapter = source("apps/signup-worker/src/signup_writer_ownership.ts")
    checks = {
        "Rust request consumes authenticated signup context":
            "admit_staging_load_test_request(" in rust_route
            and "StagingLoadTestScenario::Signup" in rust_route,
        "Rust signup record and ownership share D1 batch":
            "insert_or_existing_with_context" in rust_d1
            and "StagingLoadTestResourceClass::SignupArtifact" in rust_d1
            and "StagingLoadTestDisposition::Disposable" in rust_d1
            and ".batch(vec![" in rust_d1,
        "Clerk tenant and PAT writers use the signup adapter":
            "writeSignupArtifactBatch(" in clerk
            and "insertTenantStatement(" in clerk
            and "insertPatStatement(" in clerk,
        "Clerk org-map and entitlement writers use the signup adapter":
            "insertTenantOrgMapStatement(" in clerk
            and "seedTenantEntitlementStatements(" in clerk,
        "GitHub provisioning maps and batches signup_artifact":
            "writeSignupArtifactBatch(" in github
            and 'signupArtifactHandle("github-installation", opts.installationId)' in github,
        "Worker verifies request-bound signup envelopes":
            'verifyStagingOwnershipEnvelope(envelope, "signup", requestId' in adapter
            and 'environment !== "staging"' in adapter,
        "Worker rejects registered handle before another write":
            "SELECT 1 AS present FROM staging_load_test_resources" in adapter
            and "if (prior !== null) throw" in adapter,
        "Worker registration is appended to one atomic batch":
            "runAtomicD1Batch(" in adapter
            and "ownership as unknown as SignupPreparedStatement" in adapter
            and "requireFreshOwnershipInsert(db, opaqueHandle)" in adapter
            and "AND changes() = 0 LIMIT 1" in adapter,
        "Clerk ownership handles derive from logical artifact identities":
            'signupArtifactHandle("clerk-tenant", ownerUserId)' in clerk
            and 'signupArtifactHandle("clerk-initial-pat", tenantId)' in clerk
            and 'signupArtifactHandle("clerk-org-map", clerkOrgId)' in clerk
            and 'signupArtifactHandle("clerk-entitlements", tenantId)' in clerk,
        "GitHub ownership handle derives from the installation identity":
            'signupArtifactHandle("github-installation", opts.installationId)' in github,
        "Signup classification is the only registered resource class":
            adapter.count('"signup_artifact"') == 1
            and '"disposable"' in adapter,
        "No admission, migration, shared D1, or teardown ownership edits":
            all(path not in ALLOWED for path in (
                "apps/signup-worker/src/staging_load_test_ownership.ts",
                "apps/signup-worker/src/lib/d1.ts",
                "migrations/d1/0147_staging_load_test_run_ownership.sql",
                "crates/corelink-container/src/storage/staging_load_test_admission.rs",
            )),
    }
    missing = [label for label, passed in checks.items() if not passed]
    if missing:
        raise RuntimeError("census/adversarial verification failed: " + "; ".join(missing))


def main() -> int:
    try:
        verify_diff_scope()
        verify_census()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"issue-2582 signup ownership verification failed: {error}", file=sys.stderr)
        return 1

    print("issue-2582 signup ownership census: PASS")
    print("class map: signup pilot / Clerk tenant, PAT, org-map, entitlement / GitHub installation bundle -> signup_artifact (disposable)")
    print("excluded: Clerk provider-state mutation/publishUserMetadata (provider state is explicitly out of scope), provision locks/analytics, GitHub deprovision and audit outbox; sibling writer families remain untouched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
