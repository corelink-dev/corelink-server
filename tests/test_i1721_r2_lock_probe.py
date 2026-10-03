from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/issue-1721-r2-lock-proof.yml"
PROBE = ROOT / "scripts/probe_i1721_r2_lock.sh"
PREFLIGHT = ROOT / "scripts/validate_i1721_r2_dispatch.sh"
RESOLVER = ROOT / "scripts/server_repository.py"
IDENTITY = ROOT / "config/github-identity.json"


def _read_back_fixture_document() -> dict:
    # The committed identity may still hold the unread ID 0, which the resolver
    # refuses. Keep its owner and names; fill synthetic IDs only.
    document = json.loads(IDENTITY.read_text(encoding="utf-8"))
    document["current"]["owner_id"] = 987650000
    for offset, key in enumerate(("server", "runners", "workspaces"), start=1):
        document["current"]["repos"][key]["id"] = 987650000 + offset
    return document


FIXTURE_DOCUMENT = _read_back_fixture_document()
FIXTURE_SERVER = (
    f'{FIXTURE_DOCUMENT["current"]["owner"]}/{FIXTURE_DOCUMENT["current"]["repos"]["server"]["name"]}'
)
FIXTURE_SERVER_ID = str(FIXTURE_DOCUMENT["current"]["repos"]["server"]["id"])


def preflight_with_fixture_identity(directory: Path) -> Path:
    """Copy the preflight and its resolver next to a read-back fixture identity."""
    (directory / "scripts").mkdir()
    (directory / "config").mkdir()
    shutil.copy2(PREFLIGHT, directory / "scripts" / PREFLIGHT.name)
    shutil.copy2(RESOLVER, directory / "scripts" / RESOLVER.name)
    (directory / "config" / IDENTITY.name).write_text(json.dumps(FIXTURE_DOCUMENT), encoding="utf-8")
    return directory / "scripts" / PREFLIGHT.name

FAKE_CLI = r'''
import json, os, shutil, sys, time
from pathlib import Path

kind, *args = sys.argv[1:]
root = Path(os.environ["FAKE_R2_ROOT"])
run = f'{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}'
state = root / f"corelink/issue-1721/{run}/terraform.tfstate"
lock = Path(str(state) + ".tflock")
if kind == "aws":
    op = args[1]
    key = args[args.index("--key") + 1]
    obj = root / key
    if op == "head-object":
        if obj.exists(): sys.exit(0)
        print("Not Found", file=sys.stderr); sys.exit(1)
    if op == "get-object":
        shutil.copyfile(obj, args[-1]); sys.exit(0)
    if op == "delete-object":
        obj.unlink(missing_ok=True); sys.exit(0)
    raise SystemExit("unexpected aws operation")

chdir = next(a.split("=", 1)[1] for a in args if a.startswith("-chdir="))
tf = [a for a in args if not a.startswith("-chdir=")]
if tf[0] == "init": sys.exit(0)
if tf[:2] == ["state", "push"]:
    state.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(tf[2], state); sys.exit(0)
if tf[:2] == ["state", "pull"]:
    print(state.read_text()); sys.exit(0)
if tf[0] == "plan" and "first.tfplan" in " ".join(tf):
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps({"ID":"LOCK-TEST-ID"}))
    time.sleep(3)
    if os.environ.get("FAKE_PLAN_FAIL") == "1":
        print("SENSITIVE_RAW_PLAN_SENTINEL", file=sys.stderr); lock.unlink(); sys.exit(1)
    lock.unlink(); sys.exit(0)
if tf[0] == "plan":
    if lock.exists():
        print("Error acquiring the state lock: ID LOCK-TEST-ID", file=sys.stderr); sys.exit(1)
    sys.exit(0)
raise SystemExit("unexpected terraform operation")
'''


def base_env(**updates: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        GITHUB_REPOSITORY=FIXTURE_SERVER,
        GITHUB_REPOSITORY_ID=FIXTURE_SERVER_ID,
        GITHUB_REF="refs/heads/main",
        REF_PROTECTED="true",
        CONFIRM="i1721-r2-lock-proof",
        GITHUB_SHA="a" * 40,
        EXPECTED_SHA="a" * 40,
    )
    env.update(updates)
    return env


class I1721R2LockProbeTests(unittest.TestCase):
    def test_hosted_contract_remains_staging_only_and_pinned(self) -> None:
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        probe = PROBE.read_text(encoding="utf-8")
        self.assertEqual(workflow["on"]["pull_request"]["paths"], [
            ".github/workflows/issue-1721-r2-lock-proof.yml",
            "scripts/probe_i1721_r2_lock.sh",
            "scripts/validate_i1721_r2_dispatch.sh",
            "tests/test_i1721_r2_lock_probe.py",
        ])
        self.assertIn("workflow_dispatch", workflow["on"])
        self.assertEqual(workflow["permissions"]["contents"], "read")
        self.assertEqual(workflow["jobs"]["proof"]["environment"], "staging")
        self.assertEqual(workflow["jobs"]["preflight"]["runs-on"], "ubuntu-24.04")
        self.assertEqual(workflow["jobs"]["proof"]["runs-on"], "ubuntu-24.04")
        self.assertEqual(workflow["jobs"]["proof"]["timeout-minutes"], "12")
        contract_steps = workflow["jobs"]["contract"]["steps"]
        contract_checkout_index = next(i for i, step in enumerate(contract_steps) if step.get("uses", "").startswith("actions/checkout@"))
        contract_receipt_index = next(i for i, step in enumerate(contract_steps) if step.get("name") == "Bind contract pack to exact PR head and record receipt")
        contract_tests_index = next(i for i, step in enumerate(contract_steps) if "unittest discover" in step.get("run", ""))
        self.assertEqual(contract_steps[contract_checkout_index]["with"]["ref"], "${{ github.event.pull_request.head.sha }}")
        contract_receipt = contract_steps[contract_receipt_index]
        self.assertIn('"$(git rev-parse HEAD)" == "$CANDIDATE_SHA"', contract_receipt["run"])
        self.assertIn("CANDIDATE_SHA", contract_receipt["env"])
        self.assertIn("TARGET_BASE_SHA", contract_receipt["env"])
        self.assertIn("$GITHUB_STEP_SUMMARY", contract_receipt["run"])
        self.assertLess(contract_checkout_index, contract_receipt_index)
        self.assertLess(contract_receipt_index, contract_tests_index)
        proof_steps = workflow["jobs"]["proof"]["steps"]
        terraform_setup = next(step for step in proof_steps if step.get("uses", "").startswith("hashicorp/setup-terraform@"))
        self.assertEqual(terraform_setup["with"]["terraform_version"], "1.11.4")
        self.assertEqual(proof_steps[-1]["with"]["if-no-files-found"], "error")

        checkout_action = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(step["uses"], checkout_action)
                    self.assertEqual(step["with"].get("persist-credentials"), "false")

        preflight_steps = workflow["jobs"]["preflight"]["steps"]
        checkout_index = next(i for i, step in enumerate(preflight_steps) if step.get("uses", "").startswith("actions/checkout@"))
        credentials_index = next(i for i, step in enumerate(preflight_steps) if step.get("name") == "Assert checkout left no repository credentials")
        sha_index = next(i for i, step in enumerate(preflight_steps) if step.get("name") == "Verify exact requested checkout before validation")
        validator_index = next(i for i, step in enumerate(preflight_steps) if "validate_i1721_r2_dispatch.sh" in step.get("run", ""))
        checkout = preflight_steps[checkout_index]
        self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
        self.assertEqual(checkout["with"]["token"], "${{ github.token }}")
        self.assertIn("git config --local --get-regexp", preflight_steps[credentials_index]["run"])
        self.assertIn("http\\..*\\.extraheader|credential\\..*\\.helper", preflight_steps[credentials_index]["run"])
        sha_check = preflight_steps[sha_index]
        self.assertEqual(sha_check["env"]["EXPECTED_SHA"], "${{ inputs.expected_sha }}")
        self.assertIn('"$(git rev-parse HEAD)" == "$EXPECTED_SHA"', sha_check["run"])
        self.assertLess(checkout_index, sha_index)
        self.assertLess(checkout_index, credentials_index)
        self.assertLess(credentials_index, sha_index)
        self.assertLess(sha_index, validator_index)

        proof_checkout_index = next(i for i, step in enumerate(proof_steps) if step.get("uses", "").startswith("actions/checkout@"))
        proof_credentials_index = next(i for i, step in enumerate(proof_steps) if step.get("name") == "Assert checkout left no repository credentials")
        proof_sha_index = next(i for i, step in enumerate(proof_steps) if step.get("name") == "Verify exact requested checkout before Terraform")
        terraform_setup_index = next(i for i, step in enumerate(proof_steps) if step.get("uses", "").startswith("hashicorp/setup-terraform@"))
        self.assertEqual(proof_steps[proof_checkout_index]["with"]["ref"], "${{ inputs.expected_sha }}")
        self.assertIn("git config --local --get-regexp", proof_steps[proof_credentials_index]["run"])
        self.assertIn('"$(git rev-parse HEAD)" == "$EXPECTED_SHA"', proof_steps[proof_sha_index]["run"])
        self.assertLess(proof_checkout_index, proof_sha_index)
        self.assertLess(proof_checkout_index, proof_credentials_index)
        self.assertLess(proof_credentials_index, proof_sha_index)
        self.assertLess(proof_sha_index, terraform_setup_index)
        self.assertIn("needs.preflight.result == 'success'", workflow["jobs"]["proof"]["if"])
        self.assertEqual(workflow["jobs"]["proof"]["needs"], "preflight")
        self.assertIn("corelink-terraform-staging-state", probe)
        self.assertIn("corelink/issue-1721/$run/terraform.tfstate", probe)
        self.assertIn("use_lockfile=true", probe)
        self.assertNotIn("terraform apply", probe.lower())
        self.assertNotIn("-lock=false", probe)

    def test_dispatch_rejects_wrong_branch_and_wrong_sha(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            preflight = preflight_with_fixture_identity(Path(directory))
            # Positive control: with the configured repository, only the
            # branch/SHA mutation below can be what rejects.
            accepted = subprocess.run(["bash", str(preflight)], env=base_env(), check=False)
            self.assertEqual(accepted.returncode, 0)
            for changes in ({"GITHUB_REF": "refs/heads/feature"}, {"EXPECTED_SHA": "b" * 40}):
                with self.subTest(changes=changes):
                    result = subprocess.run(["bash", str(preflight)], env=base_env(**changes), check=False)
                    self.assertNotEqual(result.returncode, 0)

    def test_dispatch_accepts_only_the_configured_repository_id_and_name(self) -> None:
        retired_id = "1232040291"
        runners = FIXTURE_DOCUMENT["current"]["repos"]["runners"]
        with tempfile.TemporaryDirectory() as directory:
            preflight = preflight_with_fixture_identity(Path(directory))
            accepted = subprocess.run(["bash", str(preflight)], env=base_env(), check=False)
            self.assertEqual(accepted.returncode, 0)
            for label, changes in (
                ("retired destination owner and ID", {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "GITHUB_REPOSITORY_ID": retired_id}),
                ("retired destination owner, current ID", {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server"}),
                ("current name, retired ID", {"GITHUB_REPOSITORY_ID": retired_id}),
                ("peer repository ID", {"GITHUB_REPOSITORY_ID": str(runners["id"])}),
                ("missing repository ID", {"GITHUB_REPOSITORY_ID": ""}),
                ("caller override cannot replace the context", {"GITHUB_REPOSITORY": "HuGR-dev/corelink-server", "CORELINK_SERVER_REPOSITORY": FIXTURE_SERVER}),
            ):
                with self.subTest(label=label):
                    result = subprocess.run(
                        ["bash", str(preflight)], env=base_env(**changes), check=False, capture_output=True, text=True
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("not the configured CoreLink server repository", result.stderr)

        # The real preflight reads the committed identity as-is: while its IDs
        # are unread (0) it must refuse even a correct-looking context.
        committed = json.loads(IDENTITY.read_text(encoding="utf-8"))
        if committed["current"]["repos"]["server"]["id"] == 0:
            result = subprocess.run(["bash", str(PREFLIGHT)], env=base_env(), check=False, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not read back yet", result.stderr)

    def test_staging_credentials_have_no_production_secret_fallback(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        proof = text.split("  proof:", 1)[1]
        self.assertIn("secrets.STAGING_TF_BACKEND_ACCESS_KEY_ID", proof)
        self.assertIn("secrets.STAGING_TF_BACKEND_SECRET_ACCESS_KEY", proof)
        self.assertNotIn("secrets.TF_BACKEND_ACCESS_KEY_ID", proof)
        self.assertNotIn("secrets.TF_BACKEND_SECRET_ACCESS_KEY", proof)

    def test_probe_fails_before_network_when_credentials_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "network-called"
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            for command in ("aws", "terraform"):
                executable = bin_dir / command
                executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
                executable.chmod(0o755)
            env = {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "RUNNER_TEMP": tmp,
                "GITHUB_RUN_ID": "1",
                "GITHUB_RUN_ATTEMPT": "1",
                "TF_BACKEND_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
                "TF_BACKEND_BUCKET": "corelink-terraform-staging-state",
            }
            result = subprocess.run(["bash", str(PROBE)], env=env, check=False, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def run_fake_probe(self, fail_plan: bool) -> tuple[subprocess.CompletedProcess[bytes], dict, str]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        fake = root / "fake_cli.py"
        fake.write_text(textwrap.dedent(FAKE_CLI), encoding="utf-8")
        for command, kind in (("aws", "aws"), ("terraform", "terraform")):
            executable = bin_dir / command
            executable.write_text(f"#!/bin/sh\nexec python3 '{fake}' {kind} \"$@\"\n", encoding="utf-8")
            executable.chmod(0o755)
        run_temp = root / "runner-temp"
        run_temp.mkdir()
        env = base_env(
            PATH=f"{bin_dir}:{os.environ['PATH']}",
            RUNNER_TEMP=str(run_temp),
            GITHUB_RUN_ID="123",
            GITHUB_RUN_ATTEMPT="1",
            TF_BACKEND_ENDPOINT="https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            TF_BACKEND_BUCKET="corelink-terraform-staging-state",
            AWS_ACCESS_KEY_ID="TEST_ONLY_ACCESS_KEY_SENTINEL",
            AWS_SECRET_ACCESS_KEY="TEST_ONLY_SECRET_SENTINEL",
            FAKE_R2_ROOT=str(root / "objects"),
        )
        if fail_plan:
            env["FAKE_PLAN_FAIL"] = "1"
        result = subprocess.run(["bash", str(PROBE)], env=env, check=False, capture_output=True)
        receipt_path = run_temp / "issue-1721-r2-lock-receipt.json"
        return result, json.loads(receipt_path.read_text()), root.name

    def test_successful_probe_proves_contention_release_cleanup_and_redaction(self) -> None:
        result, receipt, _ = self.run_fake_probe(fail_plan=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(receipt["remote_state_written"])
        self.assertTrue(receipt["remote_state_readback"])
        self.assertTrue(receipt["native_lock_observed"])
        self.assertTrue(receipt["same_lock_contention_rejected"])
        self.assertTrue(receipt["normal_exit_released_lock"])
        self.assertTrue(receipt["exact_probe_objects_cleaned"])
        self.assertNotIn("TEST_ONLY_", json.dumps(receipt))
        self.assertNotIn("SENSITIVE_", json.dumps(receipt))

    def test_false_success_stays_failed_and_still_cleans_only_run_objects(self) -> None:
        result, receipt, _ = self.run_fake_probe(fail_plan=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(receipt["exit_status"], 0)
        self.assertTrue(receipt["exact_probe_objects_cleaned"])
        self.assertNotIn("TEST_ONLY_", json.dumps(receipt))
        self.assertNotIn("SENSITIVE_RAW_PLAN_SENTINEL", json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
