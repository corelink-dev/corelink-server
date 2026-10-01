from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("staging_target", ROOT / "scripts/verify_staging_target.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StagingTargetContractTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for path in (module.CONTRACT, *module.RUNNER_WORKFLOWS, Path("wrangler.toml")):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / path).read_text(encoding="utf-8"), encoding="utf-8")
        return temp, root

    def mutate(self, key: str, value: object) -> list[str]:
        temp, root = self.fixture()
        with temp:
            path = root / module.CONTRACT
            data = json.loads(path.read_text())
            data[key] = value
            path.write_text(json.dumps(data), encoding="utf-8")
            return module.assess(root)

    def test_repository_contract_is_ready_to_provision(self) -> None:
        self.assertEqual(module.assess(ROOT), [])

    def test_fail_closed_boundaries(self) -> None:
        self.assertIn("deployment-must-remain-unprovisioned", self.mutate("deployment_state", "ready"))
        self.assertIn("budget", self.mutate("budget", {"enforce_before_apply": False}))
        self.assertIn("lifecycle-or-teardown", self.mutate("lifecycle", {"lease_ttl_hours": 48}))
        self.assertIn("validated-inputs", self.mutate("validated_inputs", {"runner_label": "ubuntu-latest"}))

    def test_request_signal_flags_are_required_for_staging_root(self) -> None:
        temp, root = self.fixture()
        with temp:
            path = root / module.CONTRACT
            data = json.loads(path.read_text())
            data["cloudflare"]["root_worker_settings"]["compatibility_flags"] = ["nodejs_compat"]
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertIn("root-request-signal-compatibility", module.assess(root))

    def test_canonical_runner_rejects_obsolete_and_floating_labels(self) -> None:
        for runner in ("corelink", "ubuntu-latest", "self-hosted", None):
            with self.subTest(runner=runner):
                temp, root = self.fixture()
                with temp:
                    path = root / module.CONTRACT
                    data = json.loads(path.read_text())
                    data["validated_inputs"]["runner_label"] = runner
                    path.write_text(json.dumps(data), encoding="utf-8")
                    self.assertIn("validated-inputs", module.assess(root))

    def test_each_actual_job_rejects_runner_drift(self) -> None:
        for workflow, jobs in module.RUNNER_WORKFLOWS.items():
            for job in jobs:
                for runner in ("corelink", "ubuntu-latest", "[self-hosted, corelink]", "${{ vars.RUNNER }}"):
                    with self.subTest(workflow=workflow, job=job, runner=runner):
                        temp, root = self.fixture()
                        with temp:
                            path = root / workflow
                            source = path.read_text()
                            start = source.index(f"  {job}:\n")
                            position = source.index("    runs-on: ubuntu-24.04\n", start)
                            body_start = start + len(f"  {job}:\n")
                            following_job = re.search(r"(?m)^  [^\s#]", source[body_start:])
                            if following_job:
                                self.assertLess(position, body_start + following_job.start())
                            path.write_text(source[:position] + source[position:].replace(
                                "    runs-on: ubuntu-24.04\n", f"    runs-on: {runner}\n", 1,
                            ))
                            self.assertIn(f"workflow-runner:{workflow.name}", module.assess(root))

    def test_runner_check_rejects_missing_duplicate_and_ambiguous_jobs(self) -> None:
        workflow = Path(".github/workflows/i1675-live-probe.yml")
        cases = {
            "missing runner": ("    runs-on: ubuntu-24.04\n", ""),
            "duplicate runner": ("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    runs-on: corelink\n"),
            "quoted override": ("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    'runs-on': corelink\n"),
            "explicit runner override": ("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    ? runs-on\n    : corelink\n"),
            "missing job": ("  probe:\n", "  other:\n"),
            "duplicate job": ("  probe:\n", "  probe:\n    runs-on: ubuntu-24.04\n  probe:\n"),
            "extra job": ("  probe:\n", "  extra:\n    runs-on: corelink\n  probe:\n"),
            "inline extra job": ("  probe:\n", "  extra: {runs-on: corelink}\n  probe:\n"),
            "explicit extra reusable job": ("  probe:\n", "  ? extra\n  :\n    uses: owner/repository/.github/workflows/reusable.yml@main\n  probe:\n"),
            "duplicate section": ("jobs:\n", "jobs:\n  probe:\n    runs-on: corelink\njobs:\n"),
            "quoted duplicate section": ("jobs:\n", "'jobs': {probe: {runs-on: corelink}}\njobs:\n"),
            "explicit duplicate section": ("jobs:\n", "? jobs\n:\n  probe:\n    runs-on: corelink\njobs:\n"),
            "merge key": ("    runs-on: ubuntu-24.04\n", "    <<: *runner\n    runs-on: ubuntu-24.04\n"),
        }
        for label, (old, new) in cases.items():
            with self.subTest(case=label):
                temp, root = self.fixture()
                with temp:
                    path = root / workflow
                    source = path.read_text()
                    self.assertEqual(source.count(old), 1)
                    path.write_text(source.replace(old, new, 1))
                    self.assertIn(f"workflow-runner:{workflow.name}", module.assess(root))

    def test_workflows_reject_host_and_duration_drift(self) -> None:
        temp, root = self.fixture()
        with temp:
            endurance = root / module.WORKFLOWS[1]
            source = endurance.read_text()
            self.assertIn("DURATION=30s", source)
            invalid = source.replace(
                "          - '2h'\n        default: '2h'",
                "          - '2h'\n          - '24h'\n        default: '2h'",
            )
            self.assertNotEqual(invalid, source)
            endurance.write_text(invalid)
            self.assertIn("workflow-duration-budget", module.assess(root))

    def test_bounded_k6_probe_cannot_hide_overbudget_dispatch_choice(self) -> None:
        temp, root = self.fixture()
        with temp:
            endurance = root / module.WORKFLOWS[1]
            source = endurance.read_text()
            self.assertIn("DURATION=30s", source)
            invalid = source.replace(
                "          - '2h'\n        default: '2h'",
                "          - '24h'\n        default: '24h'",
            )
            self.assertNotEqual(invalid, source)
            endurance.write_text(invalid)
            self.assertIn("workflow-duration-budget", module.assess(root))


if __name__ == "__main__":
    unittest.main()
