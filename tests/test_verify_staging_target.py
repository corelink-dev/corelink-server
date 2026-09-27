from __future__ import annotations

import importlib.util
import json
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
        for path in (module.CONTRACT, *module.WORKFLOWS, Path("wrangler.toml")):
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
