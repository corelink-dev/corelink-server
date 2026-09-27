from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/load-test-baseline-check.py"
SANITIZER = ROOT / "scripts/sanitize_k6_summary.py"
VERIFIER = ROOT / "scripts/verify_b029_load_gate.py"
FULL_SCENARIOS = ("signup", "webhook", "dsr", "cas", "byok")
FULL_EXPECTED_SCENARIOS = ",".join(FULL_SCENARIOS)
TARGET = "https://staging.corelink.humangr.com"
TENANT_ID = "019e7109-e514-72b2-ac5b-607d97ea64a1"
DEPLOYMENT_SHA = "a" * 40


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


comparator = load_module(SCRIPT, "b029_load_test_baseline_check")
sanitizer = load_module(SANITIZER, "b029_sanitize_k6_summary")
verifier = load_module(VERIFIER, "b029_load_gate_verifier")


class B029LoadGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.results = self.root / "results"
        self.baseline = self.root / "baseline.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_summary(
        self,
        scenario: str,
        median: object,
        p99: object = 20,
        *,
        status: str | None = "success",
    ) -> None:
        path = self.results / scenario / "summary.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "suite_version": "r3-prep-v2",
                    "scenario": scenario,
                    "target": TARGET,
                    "tenant_id": TENANT_ID,
                    "deployment_sha": DEPLOYMENT_SHA,
                    "metrics": {"http_req_duration": {"med": median, "p(99)": p99}},
                }
            )
        )
        if status is not None:
            (path.parent / "status.json").write_text(
                json.dumps({"scenario": scenario, "outcome": status})
            )

    def write_baseline(self, median: object = 100) -> None:
        self.baseline.write_text(
            json.dumps(
                {
                    "schema": 2,
                    "baseline_version": "k6-baseline-v2",
                    "suite_version": "r3-prep-v2",
                    "captured_at": "2026-09-06T00:00:00Z",
                    "commit": "base-commit",
                    "metric": "http_req_duration.med (ms)",
                    "threshold_multiplier": 1.20,
                    "identity": {
                        "target": TARGET,
                        "tenant_id": TENANT_ID,
                        "deployment_sha": DEPLOYMENT_SHA,
                    },
                    "scenarios": {
                        scenario: {"median_ms": median, "p99_ms": 20}
                        for scenario in FULL_SCENARIOS
                    },
                }
            )
        )

    def write_full_matrix(
        self,
        *,
        cas_median: object = 100,
        cas_status: str | None = "success",
        medians: dict[str, object] | None = None,
        statuses: dict[str, str | None] | None = None,
    ) -> None:
        """Write the complete matrix required for baseline publication."""
        selected_medians = {"cas": cas_median}
        selected_medians.update(medians or {})
        selected_statuses: dict[str, str | None] = {"cas": cas_status}
        selected_statuses.update(statuses or {})
        for scenario in FULL_SCENARIOS:
            median = selected_medians.get(scenario, 100)
            status = selected_statuses.get(scenario, "success")
            self.write_summary(scenario, median, status=status)

    def run_full_gate(self, *extra: str) -> int:
        return comparator.main(
            [
                "--results-dir",
                str(self.results),
                "--baseline",
                str(self.baseline),
                "--expected-scenarios",
                FULL_EXPECTED_SCENARIOS,
                *extra,
            ]
        )

    def _assess_workflow(self, workflow: str) -> list[str]:
        contract = self.root / "workflow-contract"
        (contract / ".github/workflows").mkdir(parents=True, exist_ok=True)
        (contract / "scripts").mkdir()
        (contract / "tests/load").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/load-test-baseline-check.py", contract / "scripts")
        shutil.copy(ROOT / "scripts/sanitize_k6_summary.py", contract / "scripts")
        shutil.copy(ROOT / "tests/load/README.md", contract / "tests/load/README.md")
        self._copy_hostname_sources(contract)
        shutil.copy(ROOT / verifier.FOCUSED_PACK, contract / verifier.FOCUSED_PACK)
        (contract / ".github/workflows/load-test-nightly.yml").write_text(workflow)
        return verifier.assess(contract, expect="open")

    def _copy_hostname_sources(self, contract: Path) -> None:
        for relative in verifier.HOSTNAME_SOURCES:
            destination = contract / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, destination)

    def _workflow_and_invocation(self) -> tuple[str, str]:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        start = workflow.index("          python3 scripts/load-test-baseline-check.py")
        end = workflow.index("\n\n", start)
        invocation = workflow[start:end]
        self.assertEqual(len(invocation.splitlines()), 5)
        return workflow, invocation

    def test_missing_baseline_is_unknown_and_never_seeds(self) -> None:
        self.write_full_matrix()
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)
        self.assertFalse(self.baseline.exists())

    def test_within_threshold_updates_baseline(self) -> None:
        self.write_baseline(100)
        self.write_full_matrix(cas_median=119)
        self.assertEqual(self.run_full_gate(), 0)
        self.assertEqual(comparator.load_baseline(self.baseline)["cas"]["median_ms"], 119)

    def test_each_scenario_regression_fails_and_does_not_ratchet(self) -> None:
        for scenario in FULL_SCENARIOS:
            with self.subTest(scenario=scenario):
                self.write_baseline(100)
                self.write_full_matrix(medians={scenario: 121})
                before = self.baseline.read_bytes()
                self.assertEqual(self.run_full_gate(), comparator.EXIT_REGRESSION)
                self.assertEqual(self.baseline.read_bytes(), before)

    def test_empty_or_partial_artifacts_fail_closed(self) -> None:
        self.write_baseline(100)
        before = self.baseline.read_bytes()
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)
        self.write_full_matrix()
        (self.results / "cas" / "summary.json").unlink()
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)
        self.assertEqual(self.baseline.read_bytes(), before)

    def test_missing_or_failed_status_is_unknown(self) -> None:
        self.write_baseline(100)
        self.write_full_matrix(cas_status=None)
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)
        self.write_full_matrix(cas_status="failure")
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)

    def test_status_population_must_match_summaries_exactly(self) -> None:
        self.write_baseline(100)
        self.write_full_matrix()
        (self.results / "extra" / "status.json").parent.mkdir(parents=True)
        (self.results / "extra" / "status.json").write_text(
            json.dumps({"scenario": "extra", "outcome": "success"})
        )
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)

    def test_corrupt_baseline_is_not_treated_as_first_run(self) -> None:
        self.write_full_matrix()
        self.baseline.write_text("{not-json")
        before = self.baseline.read_bytes()
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)
        self.assertEqual(self.baseline.read_bytes(), before)

    def test_baseline_metadata_is_required(self) -> None:
        self.write_full_matrix()
        for missing in ("captured_at", "commit"):
            data = {
                "schema": 1,
                "captured_at": "2026-09-06T00:00:00Z",
                "commit": "base-commit",
                "metric": "http_req_duration.med (ms)",
                "scenarios": {
                    scenario: {"median_ms": 100, "p99_ms": 20}
                    for scenario in FULL_SCENARIOS
                },
            }
            del data[missing]
            self.baseline.write_text(json.dumps(data))
            before = self.baseline.read_bytes()
            self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)
            self.assertEqual(self.baseline.read_bytes(), before)

    def test_non_finite_measurement_is_rejected(self) -> None:
        self.write_baseline(100)
        self.write_full_matrix(cas_median="NaN")
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)

    def test_boolean_measurement_mutations_fail_closed(self) -> None:
        receipt = {
            "schema": 1,
            "environment": "staging",
            "target": TARGET,
            "tenant_id": TENANT_ID,
            "deployment_sha": DEPLOYMENT_SHA,
            "issued_at": "2026-09-06T00:00:00Z",
            "expires_at": "2026-09-06T01:00:00Z",
        }
        raw = {"metrics": {"http_req_duration": {"med": True, "p(99)": 20}}}
        with self.assertRaises(sanitizer.SummaryError):
            sanitizer.sanitize(raw, receipt, "cas")

        self.write_baseline(100)
        self.write_full_matrix(medians={"cas": True})
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)

        self.write_full_matrix()
        baseline = json.loads(self.baseline.read_text())
        baseline["scenarios"]["cas"]["median_ms"] = False
        self.baseline.write_text(json.dumps(baseline))
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)

    def test_duplicate_summaries_are_ambiguous(self) -> None:
        self.write_full_matrix()
        duplicate = self.results / "second" / "cas" / "summary.json"
        duplicate.parent.mkdir(parents=True)
        duplicate.write_text(
            json.dumps({"metrics": {"http_req_duration": {"med": 100, "p(99)": 20}}})
        )
        self.assertEqual(self.run_full_gate(), comparator.EXIT_USAGE)

    def test_active_workflow_invocation_is_exact(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        steps = verifier._yaml_steps(workflow)
        compare = next(step for step in steps if step.name == verifier.COMPARE_STEP)
        self.assertEqual(
            verifier._active_shell_commands(compare.runs[0])[-1],
            verifier.EXPECTED_COMPARATOR,
        )
        self.assertEqual(self._assess_workflow(workflow), [])

    def test_five_lines_commented_reproducer_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        commented = "\n".join("#" + line for line in invocation.splitlines())
        gaps = self._assess_workflow(workflow.replace(invocation, commented, 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_all_echo_comparator_variant_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        echo = '          echo "python3 scripts/load-test-baseline-check.py --results-dir tests/load/results/current"'
        gaps = self._assess_workflow(workflow.replace(invocation, echo, 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_string_only_comparator_variant_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        string = (
            "          COMMAND='python3 scripts/load-test-baseline-check.py --results-dir "
            "tests/load/results/current'\n"
            "          printf '%s\\n' \"$COMMAND\""
        )
        gaps = self._assess_workflow(workflow.replace(invocation, string, 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_heredoc_comparator_variant_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        heredoc = (
            "          cat <<'EOF'\n"
            "          python3 scripts/load-test-baseline-check.py\n"
            "          EOF"
        )
        gaps = self._assess_workflow(workflow.replace(invocation, heredoc, 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_noop_branch_comparator_variant_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        noop = (
            "          if false; then\n"
            "            python3 scripts/load-test-baseline-check.py\n"
            "          fi"
        )
        gaps = self._assess_workflow(workflow.replace(invocation, noop, 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_missing_comparator_command_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        gaps = self._assess_workflow(workflow.replace(invocation, "          true", 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_reordered_comparator_arguments_are_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        reordered = invocation.replace(
            "            --results-dir tests/load/results/current \\\n"
            "            --baseline tests/load/baseline/k6-baseline.json \\\n",
            "            --baseline tests/load/baseline/k6-baseline.json \\\n"
            "            --results-dir tests/load/results/current \\\n",
            1,
        )
        gaps = self._assess_workflow(workflow.replace(invocation, reordered, 1))
        self.assertIn("comparator invocation flags or values are not exact", gaps)

    def test_duplicate_comparator_commands_are_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        duplicate = invocation + "\n" + invocation
        gaps = self._assess_workflow(workflow.replace(invocation, duplicate, 1))
        self.assertIn(
            "comparison run block must contain exactly one active comparator invocation",
            gaps,
        )

    def test_wrong_comparator_value_is_red(self) -> None:
        workflow, invocation = self._workflow_and_invocation()
        wrong = invocation.replace(
            "tests/load/baseline/k6-baseline.json",
            "tests/load/baseline/other.json",
            1,
        )
        gaps = self._assess_workflow(workflow.replace(invocation, wrong, 1))
        self.assertIn("comparator invocation flags or values are not exact", gaps)

    def test_static_workflow_contract_and_open_polarity(self) -> None:
        self.assertEqual(verifier.assess(ROOT, expect="open"), [])
        result = subprocess.run(
            [sys.executable, str(VERIFIER), "--expect", "open"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_request_admission_census_rejects_static_or_missing_fresh_auth(self) -> None:
        self.assertEqual(verifier.admission_client_gaps(ROOT), [])
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory)
            for relative in (verifier.ADMISSION_HELPER, verifier.LIFECYCLE_AUTH, *verifier.ADMISSION_CALLS):
                destination = contract / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / relative, destination)
            helper = contract / verifier.ADMISSION_HELPER
            helper.write_text(helper.read_text().replace("crypto.randomBytes(32)", "crypto.randomBytes(16)", 1))
            self.assertTrue(verifier.admission_client_gaps(contract))

    def test_focused_pack_covers_comparator_inputs(self) -> None:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        self.assertEqual(self._assess_workflow(workflow), [])
        contract = self.root / "workflow-contract"
        for relative in verifier.FOCUSED_PACK_REQUIRED_PATHS:
            with self.subTest(path=relative):
                shutil.rmtree(contract, ignore_errors=True)
                gaps = self._assess_workflow(workflow)
                self.assertEqual(gaps, [])
                pack = contract / verifier.FOCUSED_PACK
                pack.write_text(
                    pack.read_text().replace(f'      - "{relative}"\n', "", 1)
                )
                gaps = verifier.assess(contract, expect="open")
                self.assertTrue(
                    any(
                        gap.startswith("focused B-029 CI pack does not trigger")
                        and relative in gap
                        for gap in gaps
                    ),
                    gaps,
                )

    def test_focused_pack_paths_must_be_pull_request_filters(self) -> None:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        self.assertEqual(self._assess_workflow(workflow), [])
        contract = self.root / "workflow-contract"
        pack = contract / verifier.FOCUSED_PACK
        pack.write_text(pack.read_text().replace("    paths:\n", "    paths-ignore:\n", 1))
        gaps = verifier.assess(contract, expect="open")
        self.assertTrue(
            any(
                gap.startswith("focused B-029 CI pack does not trigger")
                for gap in gaps
            ),
            gaps,
        )

    def test_baseline_job_guard_mutation_is_rejected(self) -> None:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        guard = verifier.PROTECTED_DISPATCH_GUARD
        parts = workflow.split(guard)
        self.assertEqual(len(parts), 3)
        for occurrence in (0, 1):
            with self.subTest(occurrence=occurrence):
                shutil.rmtree(self.root / "workflow-contract", ignore_errors=True)
                mutated = "".join(
                    segment + ("" if index == occurrence else guard)
                    for index, segment in enumerate(parts[:-1])
                ) + parts[-1]
                gaps = self._assess_workflow(mutated)
                self.assertIn(
                    "both load jobs must require the canonical protected manual dispatch",
                    gaps,
                )

    def test_corelink_runner_mutation_is_rejected(self) -> None:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        self.assertEqual(self._assess_workflow(workflow), [])
        parts = workflow.split("runs-on: ubuntu-24.04")
        self.assertEqual(len(parts), 3)
        for occurrence in (0, 1):
            with self.subTest(occurrence=occurrence):
                shutil.rmtree(self.root / "workflow-contract", ignore_errors=True)
                mutated = "".join(
                    segment + ("runs-on: ubuntu-24.04" if index != occurrence else "runs-on: corelink")
                    for index, segment in enumerate(parts[:-1])
                ) + parts[-1]
                gaps = self._assess_workflow(mutated)
                self.assertIn("both load jobs must run on ubuntu-24.04", gaps)

    def test_mutation_of_checklist_hostname_is_rejected(self) -> None:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        self.assertEqual(self._assess_workflow(workflow), [])
        contract = self.root / "workflow-contract"
        checklist = contract / "docs/internal/secrets-checklist.md"
        source = checklist.read_text()
        self.assertIn(verifier.CANONICAL_STAGING_HOST, source)
        checklist.write_text(
            source.replace(
                verifier.CANONICAL_STAGING_HOST,
                verifier.STALE_STAGING_HOST,
                1,
            )
        )
        gaps = verifier.assess(contract, expect="open")
        self.assertTrue(
            any(
                gap.startswith("B-029 hostname drift in docs/internal/secrets-checklist.md")
                for gap in gaps
            )
        )

    def test_target_source_mutations_are_rejected(self) -> None:
        workflow = (ROOT / ".github/workflows/load-test-nightly.yml").read_text()
        self.assertEqual(self._assess_workflow(workflow), [])
        contract = self.root / "workflow-contract"
        for relative in verifier.HOSTNAME_SOURCES:
            path = contract / relative
            original = path.read_text()
            for variant in verifier.STAGING_HOST_VARIANTS:
                with self.subTest(source=relative, variant=variant):
                    mutated = original.replace(
                        verifier.CANONICAL_STAGING_HOST,
                        variant,
                        1,
                    )
                    self.assertNotEqual(mutated, original)
                    path.write_text(mutated)
                    gaps = verifier.assess(contract, expect="open")
                    self.assertTrue(
                        any("B-029" in gap for gap in gaps),
                        f"{relative} mutation {variant} was not rejected: {gaps}",
                    )
            path.write_text(original)

    def test_mutation_disabling_comparison_is_killed(self) -> None:
        self.write_baseline(100)
        self.write_full_matrix(cas_median=121)
        before = self.baseline.read_bytes()
        mutated = self.root / "mutated.py"
        source = SCRIPT.read_text()
        mutated.write_text(source.replace("if cur_med > limit:", "if False:", 1))
        result = subprocess.run(
            [
                sys.executable,
                str(mutated),
                "--results-dir",
                str(self.results),
                "--baseline",
                str(self.baseline),
                "--expected-scenarios",
                FULL_EXPECTED_SCENARIOS,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, comparator.EXIT_OK)
        self.assertNotEqual(self.baseline.read_bytes(), before)

    def test_mutation_removing_status_gate_is_killed(self) -> None:
        self.write_baseline(100)
        self.write_full_matrix(cas_status=None)
        mutated = self.root / "mutated-status.py"
        source = SCRIPT.read_text()
        needle = "        collect_statuses(results_dir, expected_set)\n"
        self.assertIn(needle, source)
        mutated.write_text(source.replace(needle, "        # status gate removed\n", 1))
        result = subprocess.run(
            [
                sys.executable,
                str(mutated),
                "--results-dir",
                str(self.results),
                "--baseline",
                str(self.baseline),
                "--expected-scenarios",
                FULL_EXPECTED_SCENARIOS,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            comparator.EXIT_OK,
            "the status-less mutant must go green so this test proves the gate matters",
        )

    def test_verifier_rejects_two_cold_comparator_mutants(self) -> None:
        contract = self.root / "contract"
        (contract / ".github/workflows").mkdir(parents=True)
        (contract / "tests/load").mkdir(parents=True)
        shutil.copy(
            ROOT / ".github/workflows/load-test-nightly.yml",
            contract / ".github/workflows/load-test-nightly.yml",
        )
        shutil.copy(ROOT / verifier.FOCUSED_PACK, contract / verifier.FOCUSED_PACK)
        shutil.copy(ROOT / "tests/load/README.md", contract / "tests/load/README.md")
        self._copy_hostname_sources(contract)
        (contract / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/sanitize_k6_summary.py", contract / "scripts")

        source = SCRIPT.read_text()
        current_start = source.index("def collect_current(")
        current_end = source.index("\ndef load_baseline", current_start)
        current_mutant = (
            source[:current_start]
            + '''def collect_current(results_dir, expected=None):
    """summary.json http_req_duration p(99) expected set(out)"""
    return {}
'''
            + source[current_end + 1 :]
        )
        (contract / "scripts/load-test-baseline-check.py").write_text(current_mutant)
        current_gaps = verifier.assess(contract, expect="open")
        self.assertIn("collect_current does not enumerate k6 summary artifacts", current_gaps)
        self.assertIn("collect_current does not enforce the exact scenario population", current_gaps)
        self.assertIn("collect_current does not validate the k6 duration metrics", current_gaps)

        statuses_start = source.index("def collect_statuses(")
        statuses_end = source.index("\ndef parse_expected_scenarios", statuses_start)
        statuses_mutant = (
            source[:statuses_start]
            + '''def collect_statuses(results_dir, expected):
    """status.json success set(statuses) expected"""
    return None
'''
            + source[statuses_end + 1 :]
        )
        (contract / "scripts/load-test-baseline-check.py").write_text(statuses_mutant)
        status_gaps = verifier.assess(contract, expect="open")
        self.assertIn("collect_statuses does not enumerate matrix status artifacts", status_gaps)
        self.assertIn(
            "collect_statuses does not require an exact successful population",
            status_gaps,
        )

    def test_verifier_rejects_unreachable_required_nodes(self) -> None:
        contract = self.root / "reachable-contract"
        (contract / ".github/workflows").mkdir(parents=True)
        (contract / "tests/load").mkdir(parents=True)
        shutil.copy(
            ROOT / ".github/workflows/load-test-nightly.yml",
            contract / ".github/workflows/load-test-nightly.yml",
        )
        shutil.copy(ROOT / verifier.FOCUSED_PACK, contract / verifier.FOCUSED_PACK)
        shutil.copy(ROOT / "tests/load/README.md", contract / "tests/load/README.md")
        self._copy_hostname_sources(contract)
        (contract / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/sanitize_k6_summary.py", contract / "scripts")
        source = SCRIPT.read_text()

        current_start = source.index("def collect_current(")
        current_end = source.index("\ndef load_baseline", current_start)
        current_dead = (
            source[:current_start]
            + '''def collect_current(results_dir, expected=None):
    if 0:
        for summary in results_dir.rglob("summary.json"):
            out = {summary.parent.name: {}}
        if set(out) != expected:
            raise InputError("http_req_duration p(99)")
    return {}
'''
            + source[current_end + 1 :]
        )
        (contract / "scripts/load-test-baseline-check.py").write_text(current_dead)
        current_gaps = verifier.assess(contract, expect="open")
        self.assertIn("collect_current does not enumerate k6 summary artifacts", current_gaps)
        self.assertIn("collect_current does not enforce the exact scenario population", current_gaps)
        self.assertIn("collect_current does not validate the k6 duration metrics", current_gaps)

        statuses_start = source.index("def collect_statuses(")
        statuses_end = source.index("\ndef parse_expected_scenarios", statuses_start)
        statuses_dead = (
            source[:statuses_start]
            + '''def collect_statuses(results_dir, expected):
    if 1 == 2:
        for status_file in results_dir.rglob("status.json"):
            statuses = {status_file.parent.name: "success"}
        if set(statuses) != expected:
            raise InputError("success")
    return None
'''
            + source[statuses_end + 1 :]
        )
        (contract / "scripts/load-test-baseline-check.py").write_text(statuses_dead)
        status_gaps = verifier.assess(contract, expect="open")
        self.assertIn("collect_statuses does not enumerate matrix status artifacts", status_gaps)
        self.assertIn(
            "collect_statuses does not require an exact successful population",
            status_gaps,
        )

        early_return = source.replace(
            "        current = collect_current(results_dir, expected_set, current_identity)\n",
            "        return EXIT_OK  # all required collection code below is unreachable\n"
            "        current = collect_current(results_dir, expected_set)\n",
            1,
        )
        (contract / "scripts/load-test-baseline-check.py").write_text(early_return)
        early_gaps = verifier.assess(contract, expect="open")
        self.assertIn("main does not execute collect_current", early_gaps)


if __name__ == "__main__":
    unittest.main()
