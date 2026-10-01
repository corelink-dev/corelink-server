"""Synthetic acceptance cases for CodeQL SARIF rule-component references."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from codeql_severity_gate import SarifSeverityError, high_findings  # noqa: E402


def _rule(rule_id: str, score: str | float | None, *, security: bool = True) -> dict[str, Any]:
    tags = ["security"] if security else ["quality", "maintainability"]
    properties: dict[str, Any] = {"tags": tags}
    if score is not None:
        properties["security-severity"] = score
    return {"id": rule_id, "properties": properties}


def _sarif(
    rule: dict[str, Any],
    *,
    component_index: int | None,
    result_rule_id: str | None = None,
    component: str = "extension",
) -> dict[str, Any]:
    rule_id = rule["id"]
    driver_rules = [rule] if component == "driver" else []
    extensions = [] if component == "driver" else [{"name": "codeql/language-queries", "rules": [rule]}]
    result_id = result_rule_id or rule_id
    rule_ref: dict[str, Any] = {"id": result_id, "index": 0}
    if component_index is not None:
        rule_ref["toolComponent"] = {"index": component_index}
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": driver_rules}, "extensions": extensions},
            "results": [{"ruleId": result_id, "rule": rule_ref,
                         "message": {"text": "synthetic finding"}, "locations": []}],
        }],
    }


class CodeQLSeverityGateTests(unittest.TestCase):
    def test_extension_rules_fail_gate_for_each_codeql_language(self) -> None:
        fixtures = [
            ("rust", "rust/cleartext-logging", "9.8"),
            ("javascript-typescript", "js/file-system-race", "7.7"),
            ("python", "py/command-line-injection", "7.5"),
        ]
        for language, rule_id, severity in fixtures:
            with self.subTest(language=language):
                findings = high_findings(_sarif(_rule(rule_id, severity), component_index=0))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["rule"], rule_id)
                self.assertEqual(findings[0]["severity"], float(severity))

    def test_driver_rule_metadata_is_supported(self) -> None:
        fixture = _sarif(_rule("custom/high", "8.1"), component_index=None, component="driver")
        self.assertEqual([item["rule"] for item in high_findings(fixture)], ["custom/high"])

    def test_component_name_only_reference_does_not_resolve_another_extension(self) -> None:
        fixture = _sarif(_rule("shared/rule", "1.0"), component_index=None)
        run = fixture["runs"][0]
        run["tool"]["extensions"][0]["name"] = "ext-low"
        run["results"][0]["rule"]["toolComponent"] = {"name": "ext-high"}
        with self.assertRaisesRegex(SarifSeverityError, "does not match driver name"):
            high_findings(fixture)

    def test_name_only_reference_defaults_to_driver_before_name_validation(self) -> None:
        fixture = _sarif(_rule("shared/rule", "8.0"), component_index=None)
        fixture["runs"][0]["tool"]["driver"]["rules"].append(
            _rule("shared/rule", "9.0")
        )
        fixture["runs"][0]["results"][0]["rule"]["toolComponent"] = {"name": "CodeQL"}
        self.assertEqual(
            [item["severity"] for item in high_findings(fixture)],
            [9.0],
        )

    def test_name_only_extension_reference_cannot_hide_duplicate_driver_rule(self) -> None:
        fixture = _sarif(_rule("shared/rule", "1.0"), component_index=None)
        run = fixture["runs"][0]
        run["tool"]["driver"]["rules"].append(_rule("shared/rule", "9.0"))
        run["results"][0]["rule"]["toolComponent"] = {
            "name": "codeql/language-queries"
        }
        with self.assertRaisesRegex(SarifSeverityError, "does not match driver name"):
            high_findings(fixture)

    def test_component_guid_reference_resolves_extension(self) -> None:
        fixture = _sarif(_rule("shared/rule", "8.0"), component_index=None)
        extension = fixture["runs"][0]["tool"]["extensions"][0]
        extension["guid"] = "ext-guid"
        fixture["runs"][0]["results"][0]["rule"]["toolComponent"] = {"guid": "ext-guid"}
        self.assertEqual([item["rule"] for item in high_findings(fixture)], ["shared/rule"])

    def test_component_name_must_match_its_index(self) -> None:
        fixture = _sarif(_rule("shared/rule", "8.0"), component_index=0)
        fixture["runs"][0]["results"][0]["rule"]["toolComponent"]["name"] = "ext-other"
        with self.assertRaisesRegex(SarifSeverityError, "does not match"):
            high_findings(fixture)

    def test_non_security_rules_without_security_score_are_below_threshold(self) -> None:
        fixture = _sarif(_rule("py/unused-import", None, security=False), component_index=0)
        self.assertEqual(high_findings(fixture), [])

    def test_threshold_boundary_is_inclusive_at_high(self) -> None:
        for score, expected in [("6.9", 0), (6.99, 0), ("7.0", 1), (9.0, 1)]:
            with self.subTest(score=score):
                fixture = _sarif(_rule("codeql/threshold", score), component_index=0)
                self.assertEqual(len(high_findings(fixture)), expected)

    def test_unresolved_result_rule_fails_closed(self) -> None:
        fixture = _sarif(_rule("js/known", "8.0"), component_index=0, result_rule_id="js/missing")
        with self.assertRaisesRegex(SarifSeverityError, "unresolved SARIF metadata"):
            high_findings(fixture)

    def test_unqualified_duplicate_rule_id_defaults_to_driver(self) -> None:
        fixture = _sarif(_rule("rust/high", "1.0"), component_index=None)
        run = fixture["runs"][0]
        run["tool"]["driver"]["rules"].append(_rule("rust/high", "9.0"))
        run["results"][0]["rule"].pop("index")
        self.assertEqual(
            [item["severity"] for item in high_findings(fixture)],
            [9.0],
        )

    def test_missing_security_severity_fails_closed(self) -> None:
        fixture = _sarif(_rule("py/security-rule", None), component_index=0)
        with self.assertRaisesRegex(SarifSeverityError, "no security-severity"):
            high_findings(fixture)

    def test_invalid_security_severity_fails_closed(self) -> None:
        for score in ["NaN", "inf", "10.1", "unknown"]:
            with self.subTest(score=score):
                fixture = _sarif(_rule("rust/bad-score", score), component_index=0)
                with self.assertRaisesRegex(SarifSeverityError, "invalid|out-of-range"):
                    high_findings(fixture)

    def test_codeql_workflow_uses_the_shared_fail_closed_gate(self) -> None:
        workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        gate_step = workflow.split("- name: Strict severity gate (fail PR on HIGH/CRITICAL)", 1)[1]
        parser = (ROOT / "scripts/codeql_severity_gate.py").read_text(encoding="utf-8")
        self.assertIn('python3 scripts/codeql_severity_gate.py "${sarif_files[@]}"', gate_step)
        self.assertIn("github.event_name == 'pull_request'", gate_step)
        self.assertIn("Reviewed severity gate (trusted main only)", workflow)
        self.assertIn("python3 scripts/codeql_reviewed_dispositions.py", workflow)
        self.assertIn("THRESHOLD = 7.0", parser)
        self.assertIn('tool.get("extensions", [])', parser)
        self.assertNotIn("rules.get(rule_id, 0.0)", gate_step)

    def test_issue_workflow_is_exact_head_bounded_and_narrow(self) -> None:
        workflow = (ROOT / ".github/workflows/issue-2628-codeql-severity.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("timeout-minutes: 5", workflow)
        self.assertIn("github.event.pull_request.head.sha || github.sha", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "${EXPECTED_HEAD}"', workflow)
        self.assertIn("python3 -m unittest -q tests/test_codeql_severity_gate.py", workflow)
        self.assertNotIn("workflow_run:", workflow)


if __name__ == "__main__":
    unittest.main()
