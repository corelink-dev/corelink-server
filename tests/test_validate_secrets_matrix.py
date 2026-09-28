"""Fail-closed tests for path-scoped synthetic raw-curl environment data."""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/validate_secrets_matrix.py"
spec = importlib.util.spec_from_file_location("validate_secrets_matrix", SCRIPT)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)

VERIFIER = ROOT / "scripts/verify_b245_secrets_matrix.py"
verifier_spec = importlib.util.spec_from_file_location("verify_b245_secrets_matrix", VERIFIER)
assert verifier_spec and verifier_spec.loader
b245 = importlib.util.module_from_spec(verifier_spec)
sys.modules[verifier_spec.name] = b245
verifier_spec.loader.exec_module(b245)


SYNTHETIC_NAMES = {
    "CORELINK_HTTP_PORT_FILE",
    "CORELINK_HTTP_REQUEST_FILE",
    "CORELINK_HTTP_STATUS",
}

GC_SAFETY_FLAGS = {
    "GC_LIVE_DELETE",
    "GC_OBSERVATION_ONLY",
}

PUBLIC_NON_SECRET_CONFIG = {
    "PAGERDUTY_EVENTS_URL",
    "PAGERDUTY_SERVICE",
    "SLA_CREDITS_ENABLED",
    "SLA_OBSERVATIONS_ENABLED",
    "SYNTHETIC_DRILL_ENABLED",
    "CORELINK_BYOK_REVOCATION_SCHEDULER_ENABLED",
}

GC_MATRIX_NAMES = {
    "GC_R2_BUCKET",
    "GC_RUN_ID",
    "GC_VALIDATE_ONLY",
}

GC_SENSITIVE_NAMES = {
    "GC_LIVE_DELETE_CONFIRM",
}

GC_UNCLASSIFIED_NAMES = {
    "GC_ADMIN_TOKEN",
    "GC_OBSERVATION_ONLY_TOKEN",
}

NON_SECRET_CONFIG_NAMES = {
    "D1_DATABASE_ID",
    "R2_S3_ENDPOINT",
    "EXPECTED_CONTAINER_APP_VERSION",
    "EXPECTED_CONTAINER_IMAGE_DIGEST",
    "EXPECTED_SHA",
    "IMAGE_DIGEST",
    "MIN_CONTAINER_APP_VERSION",
    "PREIMAGE_CONTAINER_IMAGE",
    "B216_BOOTSTRAP_STAGE",
    "B216_BOOTSTRAP_HANDOFF_PATH",
    "GITHUB_RUN_ATTEMPT",
}

I2193_MATRIX_BOUND_NAMES = {
    "CORELINK_B102_STAGING_PAT",
    "CORELINK_B104_STAGING_PAT",
    "CORELINK_B106_OWNER_SESSION",
    "CORELINK_DEPLOYED_REGION",
    "CORELINK_DEPLOYED_SHA",
    "CORELINK_DOGFOOD_PAT",
    "K6_STAGING_TEARDOWN_TOKEN",
    "K6_TARGET_IDENTITY_RECEIPT",
    "STAGING_CF_ACCOUNT_ID",
    "STAGING_CF_API_TOKEN",
    "STAGING_CF_WORKER_API_TOKEN",
    "STAGING_CLERK_ISSUER_URL",
    "STAGING_CLERK_SECRET_KEY",
    "STAGING_CLERK_WEBHOOK_SECRET",
    "STAGING_ERASURE_SALT_KEY",
    "STAGING_PAGERDUTY_ROUTING_KEY",
    "STAGING_R2_S3_ACCESS_KEY_ID",
    "STAGING_R2_S3_ENDPOINT",
    "STAGING_R2_S3_SECRET_ACCESS_KEY",
    "STAGING_TF_BACKEND_ACCESS_KEY_ID",
    "STAGING_TF_BACKEND_SECRET_ACCESS_KEY",
    "TF_BACKEND_ACCESS_KEY_ID",
    "TF_BACKEND_SECRET_ACCESS_KEY",
}

I2193_NEAR_NAME_SENSITIVE_INPUTS = {
    "CORELINK_DEPLOYED_SHA_TOKEN",
    "CORELINK_DEPLOYED_REGION_KEY",
    "STAGING_CLERK_ISSUER_URL_TOKEN",
    "STAGING_R2_S3_ENDPOINT_SECRET",
}

A11Y_REPORT_DESTINATIONS = {
    "A11Y_AUDIT_REPORT",
    "A11Y_AUDIT_SUMMARY",
}

A11Y_SENSITIVE_OR_UNCLASSIFIED = {
    "A11Y_AUDIT_TOKEN",
    "A11Y_AUDIT_REPORT_TOKEN",
    "A11Y_AUDIT_SUMMARY_SECRET",
}

def _source(names: set[str]) -> str:
    return "\n".join(f"const value = process.env.{name};" for name in sorted(names))


def test_only_exact_raw_curl_paths_skip_the_three_synthetic_names(tmp_path: Path) -> None:
    for relative in gate.SYNTHETIC_ENV_MANIFEST:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_source(SYNTHETIC_NAMES), encoding="utf-8")

    assert gate.scan_ts(tmp_path) == set()


def test_moving_the_fixture_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "apps/docs/tests/fixtures/raw-curl-http-server-renamed.mjs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_source(SYNTHETIC_NAMES), encoding="utf-8")

    assert gate.scan_ts(tmp_path) == SYNTHETIC_NAMES


def test_a_fourth_name_in_an_exact_fixture_path_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "apps/docs/tests/fixtures/raw-curl-http-server.mjs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_source(SYNTHETIC_NAMES | {"CORELINK_HTTP_SECRET_FILE"}), encoding="utf-8")

    assert gate.scan_ts(tmp_path) == {"CORELINK_HTTP_SECRET_FILE"}


def test_synthetic_names_in_production_paths_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "worker/src/secrets.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_source(SYNTHETIC_NAMES), encoding="utf-8")

    assert gate.scan_ts(tmp_path) == SYNTHETIC_NAMES

    rust_path = tmp_path / "crates/corelink-container/src/secrets.rs"
    rust_path.parent.mkdir(parents=True, exist_ok=True)
    rust_path.write_text(
        "\n".join(f'std::env::var("{name}");' for name in sorted(SYNTHETIC_NAMES)),
        encoding="utf-8",
    )

    assert gate.scan_rust(tmp_path) == SYNTHETIC_NAMES


def test_gc_safety_flags_are_exact_non_secret_allowlist_entries() -> None:
    assert all(gate.ALLOWLIST_REGEX.match(name) for name in GC_SAFETY_FLAGS)
    assert all(gate.ALLOWLIST_REGEX.match(name) for name in PUBLIC_NON_SECRET_CONFIG)
    assert all(not gate.ALLOWLIST_REGEX.match(name) for name in GC_MATRIX_NAMES)
    assert all(not gate.ALLOWLIST_REGEX.match(name) for name in GC_SENSITIVE_NAMES)
    assert all(not gate.ALLOWLIST_REGEX.match(name) for name in GC_UNCLASSIFIED_NAMES)

    shell_gate = (ROOT / "scripts/secrets-checklist-verify.sh").read_text(
        encoding="utf-8"
    )
    regex = re.search(r"^ALLOWLIST_REGEX='([^']+)'$", shell_gate, re.MULTILINE)
    assert regex, "Bash allowlist must have one canonical assignment"
    for name in GC_SAFETY_FLAGS | PUBLIC_NON_SECRET_CONFIG:
        assert subprocess.run(
            ["grep", "-E", regex.group(1)],
            input=f"{name}\n",
            text=True,
            capture_output=True,
            check=False,
        ).returncode == 0
    for name in GC_MATRIX_NAMES | GC_SENSITIVE_NAMES | GC_UNCLASSIFIED_NAMES:
        assert subprocess.run(
            ["grep", "-E", regex.group(1)],
            input=f"{name}\n",
            text=True,
            capture_output=True,
            check=False,
        ).returncode != 0


def test_b245_gc_contract_rejects_a_broad_allowlist_mutation() -> None:
    """The B-245 preflight must reject every GC name except the two flags."""
    broad = SimpleNamespace(ALLOWLIST_REGEX=re.compile(r"^GC_"))
    try:
        b245.validate_gc_allowlist_contract(broad)
    except AssertionError:
        return
    raise AssertionError("broad GC_* allowlist mutation was accepted")


def test_b245_closed_scope_and_mutations() -> None:
    """Run B-245's exact fixture annotation and fail-closed mutation checks."""
    assert b245.main() == 0


def test_bash_repo_root_override_requires_canonical_sentinels(tmp_path: Path) -> None:
    """A matrix-shaped arbitrary directory cannot become a trusted root."""
    matrix = tmp_path / "docs/internal/secrets-checklist.md"
    matrix.parent.mkdir(parents=True)
    matrix.write_text(
        "\n".join(
            f"| {i} | Fixture {i} | `FIXTURE_{i}` |" for i in range(1, 21)
        )
        + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/secrets-checklist-verify.sh"), "--repo-root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "canonical sentinels" in result.stderr


def test_bash_repo_root_override_accepts_isolated_canonical_fixture(tmp_path: Path) -> None:
    """The verifier remains testable against an isolated, complete fixture root."""
    for relative in (
        "Cargo.toml",
        "scripts/validate_secrets_matrix.py",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (tmp_path / ".github/workflows").mkdir(parents=True)
    matrix = tmp_path / "docs/internal/secrets-checklist.md"
    matrix.parent.mkdir(parents=True, exist_ok=True)
    matrix.write_text(
        "\n".join(
            f"| {i} | Fixture {i} | `FIXTURE_{i}` |" for i in range(1, 21)
        )
        + "\n",
        encoding="utf-8",
    )
    source = tmp_path / "crates/fixture/src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        'std::env::var("GC_LIVE_DELETE");\n'
        'std::env::var("GC_OBSERVATION_ONLY");\n',
        encoding="utf-8",
    )
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/secrets-checklist-verify.sh"), "--repo-root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_non_secret_config_names_are_allowlisted_by_both_validators() -> None:
    """Keep the Bash deploy gate aligned with Python's narrow classifications."""
    assert all(gate.ALLOWLIST_REGEX.match(name) for name in NON_SECRET_CONFIG_NAMES)

    shell_gate = (ROOT / "scripts/secrets-checklist-verify.sh").read_text(encoding="utf-8")
    regex = re.search(r"^ALLOWLIST_REGEX='([^']+)'$", shell_gate, re.MULTILINE)
    assert regex, "Bash allowlist must have one canonical assignment"
    for name in NON_SECRET_CONFIG_NAMES:
        assert subprocess.run(
            ["grep", "-E", regex.group(1)], input=f"{name}\n", text=True,
            capture_output=True, check=False,
        ).returncode == 0

    assert not gate.ALLOWLIST_REGEX.match("D1_DATABASE_TOKEN")
    assert not gate.ALLOWLIST_REGEX.match("R2_S3_SECRET_ACCESS_KEY")
    assert not gate.ALLOWLIST_REGEX.match("CORELINK_HTTP_SECRET_FILE")
    assert not gate.ALLOWLIST_REGEX.fullmatch("EXPECTED_SHA_TOKEN")
    assert not gate.ALLOWLIST_REGEX.fullmatch("IMAGE_DIGEST_SECRET")
    for name in (
        "B216_BOOTSTRAP_STAGE_TOKEN",
        "B216_BOOTSTRAP_STAGE_SECRET",
        "B216_BOOTSTRAP_HANDOFF_PATH_TOKEN",
        "B216_BOOTSTRAP_HANDOFF_PATH_SECRET",
        "B216_BOOTSTRAP_UNKNOWN",
        "GITHUB_RUN_ATTEMPT_SECRET",
    ):
        assert not gate.ALLOWLIST_REGEX.fullmatch(name)
        assert subprocess.run(
            ["grep", "-E", regex.group(1)], input=f"{name}\n", text=True,
            capture_output=True, check=False,
        ).returncode != 0


def test_i2193_matrix_bindings_remain_fail_closed() -> None:
    """Credentials, identifiers, and active config remain matrix-bound."""
    shell_gate = (ROOT / "scripts/secrets-checklist-verify.sh").read_text(encoding="utf-8")
    regex = re.search(r"^ALLOWLIST_REGEX='([^']+)'$", shell_gate, re.MULTILINE)
    assert regex, "Bash allowlist must have one canonical assignment"

    for name in I2193_MATRIX_BOUND_NAMES | I2193_NEAR_NAME_SENSITIVE_INPUTS:
        assert not gate.ALLOWLIST_REGEX.fullmatch(name)
        assert subprocess.run(
            ["grep", "-E", regex.group(1)], input=f"{name}\n", text=True,
            capture_output=True, check=False,
        ).returncode != 0

    assert I2193_MATRIX_BOUND_NAMES <= gate.parse_matrix(
        ROOT / gate.MATRIX_FILE_REL
    )


def test_a11y_report_destinations_are_exact_non_secret_entries() -> None:
    """The docs audit writes local files; similarly named secrets stay visible."""
    shell_gate = (ROOT / "scripts/secrets-checklist-verify.sh").read_text(encoding="utf-8")
    regex = re.search(r"^ALLOWLIST_REGEX='([^']+)'$", shell_gate, re.MULTILINE)
    assert regex

    for name in A11Y_REPORT_DESTINATIONS:
        assert gate.ALLOWLIST_REGEX.fullmatch(name)
        assert subprocess.run(
            ["grep", "-E", regex.group(1)],
            input=f"{name}\n",
            text=True,
            capture_output=True,
            check=False,
        ).returncode == 0
    for name in A11Y_SENSITIVE_OR_UNCLASSIFIED:
        assert not gate.ALLOWLIST_REGEX.fullmatch(name)
        assert subprocess.run(
            ["grep", "-E", regex.group(1)],
            input=f"{name}\n",
            text=True,
            capture_output=True,
            check=False,
        ).returncode != 0


def test_synthetic_names_are_not_global_allowlist_entries() -> None:
    """Synthetic raw-curl names stay visible outside their exact fixture paths."""
    shell_gate = (ROOT / "scripts/secrets-checklist-verify.sh").read_text(encoding="utf-8")
    for name in SYNTHETIC_NAMES:
        assert not gate.ALLOWLIST_REGEX.match(name)
        assert f"|{name}$" not in shell_gate


def test_bash_repo_root_override_preserves_exact_raw_curl_fixture_exclusion(
    tmp_path: Path,
) -> None:
    """The synthetic names stay excluded only at their exact fixture paths."""
    names = (
        "CORELINK_HTTP_PORT_FILE",
        "CORELINK_HTTP_REQUEST_FILE",
        "CORELINK_HTTP_STATUS",
    )
    fixture = tmp_path / "apps/docs/tests/fixtures/raw-curl-http-server.mjs"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(
        "".join(f"console.log(process.env.{name});\n" for name in names),
        encoding="utf-8",
    )
    matrix = tmp_path / "docs/internal/secrets-checklist.md"
    matrix.parent.mkdir(parents=True, exist_ok=True)
    matrix.write_text(
        "\n".join(
            f"| {i} | Fixture {i} | `UNRELATED_FIXTURE_KEY_{i}` |"
            for i in range(1, 21)
        )
        + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/secrets-checklist-verify.sh"), "--repo-root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    production = tmp_path / "apps/admin-ui/src/http-leak.mjs"
    production.parent.mkdir(parents=True, exist_ok=True)
    production.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/secrets-checklist-verify.sh"), "--repo-root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert all(name in result.stderr for name in names)
