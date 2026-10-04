"""Adversarial regression for B083's executable backlog verifier."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GIT_DIR = subprocess.run(
    ["git", "rev-parse", "--absolute-git-dir"],
    cwd=ROOT,
    text=True,
    capture_output=True,
    check=True,
).stdout.strip()
INPUTS = (
    Path("BACKLOG.md"),
    Path("Dockerfile"),
    Path("scripts/verify_b083_kms_lifecycle_evidence.py"),
    Path("scripts/verify_owner_action_packets.py"),
    Path("docs/handoff/2026-09-05-owner-action-packets-b008-b154.json"),
    # The owner-packet verifier validates the B-111 workflow/release-chain
    # contract even when selecting another packet item.
    Path(".github/workflows/notarize-macos.yml"),
    Path(".github/workflows/sign-windows.yml"),
    Path(".github/workflows/release-cli.yml"),
    Path("crates/corelink-container/Cargo.toml"),
    Path("crates/corelink-container/src/byok_orchestrator.rs"),
    Path("crates/corelink-container/src/routes/byok_admin.rs"),
    Path("crates/corelink-container/tests/byok_orchestrator.rs"),
    Path("evidence/owner-actions/B-110/ci-capacity-decision.json"),
    Path("evidence/owner-actions/B-054/keyed-audit-epoch-rollout.json"),
    Path("evidence/owner-actions/B-083/byok-real-kms-lifecycle.json"),
    Path("evidence/owner-actions/B-086/d1-residency-resolution.json"),
    Path("evidence/owner-actions/B-097/cloudflare-vcpu-quota-case.json"),
    Path("evidence/owner-actions/B-154/executed-instrument-resolution.json"),
    Path("legal/dpa/v1.0.0.en-US.md"),
    Path("legal/sla/v1.0.0.md"),
    Path("marketing/launch/CASE-STUDIES/enterprise-byok.md"),
)

OWNER_GATE = "python3 scripts/verify_owner_action_packets.py --id B-083"
SHELL_GATE = "bash -c '"


def _assert_b083_command_shape(script: str) -> None:
    """Require the owner packet gate to precede exactly one source gate."""
    packet_at = script.find(OWNER_GATE)
    shell_at = script.find(SHELL_GATE)
    if packet_at != 0 or shell_at < 0 or packet_at > shell_at:
        raise AssertionError("B083 verify must run the owner packet before its shell gate")
    if script.count(OWNER_GATE) != 1 or script.count(SHELL_GATE) != 1:
        raise AssertionError("B083 verify must have exactly one ordered packet/shell gate")
    between = script[len(OWNER_GATE):shell_at]
    if not between.strip().startswith("&&"):
        raise AssertionError("B083 owner packet must be an && predecessor of shell gate")


def _b083_shell() -> str:
    text = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
    block = text.split("id: B-083\nrepo: corelink-server", 1)[1]
    verify = block.split("verify: |\n", 1)[1].split("verify-means: |\n", 1)[0]
    script = textwrap.dedent(verify).strip()
    if not script.endswith("'"):
        raise AssertionError("B083 verify must remain a bash -c contract")
    _assert_b083_command_shape(script)
    return script


def _copy_inputs(destination: Path) -> None:
    for relative in INPUTS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def _run(script: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", "-c", script],
        cwd=cwd,
        env={**os.environ, "GIT_DIR": GIT_DIR},
        text=True,
        capture_output=True,
        check=False,
    )


def test_b083_verifier_green_then_named_red_feature_mutation() -> None:
    script = _b083_shell()
    # These two mutations are command-integrity failures, independently of
    # whether the source-level shell gate still happens to pass.
    without_owner = script.replace(OWNER_GATE + " && \\\n", "", 1)
    try:
        _assert_b083_command_shape(without_owner)
    except AssertionError:
        pass
    else:
        raise AssertionError("removing the B083 owner gate was accepted")
    shell_at = script.find(SHELL_GATE)
    reordered = script[shell_at:] + " && " + OWNER_GATE
    try:
        _assert_b083_command_shape(reordered)
    except AssertionError:
        pass
    else:
        raise AssertionError("reordering the B083 owner gate was accepted")

    with tempfile.TemporaryDirectory(prefix="b083-verify-") as raw:
        tree = Path(raw)
        _copy_inputs(tree)

        green = _run(script, tree)
        assert green.returncode == 0, green.stdout + green.stderr
        assert "shipped image links no KMS provider by default" in green.stdout

        # #1648: re-arming the shipped image by flipping the one default is
        # the regression that made every production container exit with 1.
        dockerfile = tree / "Dockerfile"
        pristine = dockerfile.read_text(encoding="utf-8")
        armed = pristine.replace(
            "ARG CORELINK_BYOK_PROVIDER_FEATURE=\n",
            "ARG CORELINK_BYOK_PROVIDER_FEATURE=byok-aws-real\n",
            1,
        )
        assert armed != pristine, "armed-default mutation did not apply"
        dockerfile.write_text(armed, encoding="utf-8")

        red = _run(script, tree)
        output = red.stdout + red.stderr
        assert red.returncode != 0, output
        assert "FALHA: shipped image links a KMS provider by default" in output

        literal = pristine.replace(
            "--bin corelink-server \\\n",
            "--bin corelink-server --features byok-aws-real \\\n",
            1,
        )
        assert literal != pristine, "literal-feature mutation did not apply"
        dockerfile.write_text(literal, encoding="utf-8")

        red = _run(script, tree)
        output = red.stdout + red.stderr
        assert red.returncode != 0, output
        assert "FALHA: shipped corelink-server build does not take its provider" in output


if __name__ == "__main__":
    test_b083_verifier_green_then_named_red_feature_mutation()
    print("B083 verifier mutation: green baseline and named red mutant")
