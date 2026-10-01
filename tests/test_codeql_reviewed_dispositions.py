"""Adversarial tests for the exact issue-1674 trusted-main CodeQL gate."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import codeql_reviewed_dispositions as gate  # noqa: E402


def _sarif(case: dict, *, uploaded: bool, score: str = "7.5", alert_number: int | None = None,
           results: bool = True, extra: dict | None = None,
           uploaded_column_fingerprint: str | None = None) -> dict:
    rule = case["rule"]
    rule_info = {
        "id": rule,
        "properties": {"security-severity": score, "tags": ["security"]},
    }
    items = []
    if results:
        result = {
            "ruleId": rule,
            "rule": {"id": rule, "index": 0},
            "message": {"text": "fixture"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": case["path"]},
                    "region": {"startLine": case["line"], "startColumn": case["start_column"]},
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": case["primaryLocationLineHash"]
            },
        }
        if not uploaded:
            result["partialFingerprints"]["primaryLocationStartColumnFingerprint"] = (
                case["primaryLocationStartColumnFingerprint"]
            )
            # The reviewed gate deliberately never consults baselineState.
            result["baselineState"] = "new"
        else:
            result["properties"] = {"github/alertNumber": alert_number}
            if uploaded_column_fingerprint is not None:
                result["partialFingerprints"]["primaryLocationStartColumnFingerprint"] = (
                    uploaded_column_fingerprint
                )
        if extra:
            result.update(extra)
        items.append(result)
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "semanticVersion": gate.CODEQL_VERSION,
                    "rules": [rule_info],
                },
                "extensions": [],
            },
            "results": items,
        }],
    }


def _analysis(sha: str, category: str, sarif_id: str, *, count: int = 1) -> dict:
    return {
        "id": 987654,
        "sarif_id": sarif_id,
        "commit_sha": sha,
        "ref": "refs/heads/main",
        "category": category,
        "tool": {"name": "CodeQL", "version": gate.CODEQL_VERSION},
        "error": "",
        "results_count": count,
    }


def _live_alert(case: dict, *, state: str = "dismissed", reason: str | None = None) -> dict:
    return {
        "number": case["alert_number"],
        "state": state,
        "dismissed_reason": reason or case["expected_dismissed_reason"],
        "rule": {"id": case["rule"], "security_severity_level": "high"},
        "tool": {"name": "CodeQL", "version": gate.CODEQL_VERSION},
        "most_recent_instance": {
            "category": case["category"],
            "ref": "refs/heads/main",
            "location": {
                "path": case["path"],
                "start_line": case["line"],
                "start_column": case["start_column"],
            },
            # The dismissed alert may legitimately retain an older analysis SHA.
            "commit_sha": gate.REVIEWED_ANALYSIS_COMMIT,
        },
    }


class ReviewedDispositionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(gate.MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.case = next(case for case in cls.manifest["approved_alerts"] if case["alert_number"] == 3564)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sarif_path = Path(self.temp.name) / "python.sarif"
        self.current_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        self.sarif_id = "fixture-sarif-id"

    def _args(self) -> Namespace:
        return Namespace(
            repository=gate.REPOSITORY,
            repository_id=gate.REPOSITORY_ID,
            event="workflow_dispatch",
            ref="refs/heads/main",
            sha=self.current_sha,
            language="python",
            sarif_id=self.sarif_id,
            sarif=[self.sarif_path],
            apply_approved_dispositions=False,
            receipt=None,
        )

    def _run(self, *, local=None, uploaded=None, analysis=None, alert=None, analyses=None,
             apply=False, receipt=None, readback_alert=None, readback_error=False) -> tuple[int, list[str], list[tuple[str, dict]]]:
        local = local if local is not None else _sarif(self.case, uploaded=False)
        uploaded = uploaded if uploaded is not None else _sarif(
            self.case, uploaded=True, alert_number=self.case["alert_number"]
        )
        self.sarif_path.write_text(json.dumps(local), encoding="utf-8")
        analysis = analysis if analysis is not None else _analysis(
            self.current_sha, self.case["category"], self.sarif_id
        )
        alert = alert if alert is not None else _live_alert(self.case)
        calls: list[str] = []
        patches: list[tuple[str, dict]] = []

        def fake_get(_api, endpoint, accept="application/vnd.github+json"):
            calls.append(endpoint)
            if "/code-scanning/analyses?" in endpoint:
                return analyses if analyses is not None else [analysis]
            if endpoint.endswith("/analyses/987654"):
                return uploaded
            if endpoint.endswith(f"/alerts/{self.case['alert_number']}"):
                if patches:
                    if readback_error:
                        raise gate.ReviewedGateError("simulated alert readback failure")
                    if readback_alert is not None:
                        return readback_alert
                    updated = dict(alert)
                    updated["state"] = "dismissed"
                    updated["dismissed_reason"] = self.case["expected_dismissed_reason"]
                    return updated
                return alert
            raise AssertionError("unexpected API request")

        def fake_patch(_api, endpoint, payload):
            patches.append((endpoint, payload))
            return {
                "number": self.case["alert_number"],
                "state": "dismissed",
                "dismissed_reason": payload["dismissed_reason"],
            }

        args = self._args()
        args.apply_approved_dispositions = apply
        args.receipt = receipt
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"GH_TOKEN": "test-token", "GITHUB_API_URL": "https://api.example"}), \
             patch.object(gate.GitHubApi, "get", fake_get), \
             patch.object(gate.GitHubApi, "patch", fake_patch), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = gate.verify(args)
            except gate.ReviewedGateError:
                code = 2
        return code, calls, patches

    def test_manifest_is_narrowly_bound_to_reviewed_source_and_alerts(self) -> None:
        raw = gate.MANIFEST_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), gate.MANIFEST_SHA256)
        self.assertEqual(len(self.manifest["approved_alerts"]), 303)
        self.assertEqual(len(self.manifest["source_file_blobs"]), 132)
        self.assertEqual(set(self.manifest["retained_sarif_evidence"]), set(gate.LANGUAGE_CATEGORIES))
        self.assertTrue(all(
            case.get("primaryLocationLineHash")
            and case.get("primaryLocationStartColumnFingerprint")
            for case in self.manifest["approved_alerts"]
        ))
        self.assertEqual({c["expected_dismissed_reason"] for c in self.manifest["approved_alerts"]},
                         {"false positive", "used in tests"})

    def test_action_pin_census_and_mode_boundary_are_preserved(self) -> None:
        workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)
        self.assertEqual(len(uses), 6)
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", ref) for ref in uses))
        self.assertIn("max-parallel: 3", workflow)
        self.assertIn("github.event_name == 'pull_request'", workflow)
        self.assertIn("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("SARIF_ID: ${{ steps.upload.outputs.sarif-id }}", workflow)
        campaign = (ROOT / ".github/workflows/campaign-ci.yml").read_text(encoding="utf-8")
        campaign_uses = re.findall(r"^\s*uses:\s*([^\s#]+)", campaign, re.MULTILINE)
        external = [ref for ref in campaign_uses if not ref.startswith("./")]
        self.assertEqual(len(external), 13)
        self.assertTrue(all(re.search(r"@[0-9a-f]{40}$", ref) for ref in external))

    def test_exact_uploaded_analysis_and_live_dismissal_pass(self) -> None:
        code, calls, patches = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(patches, [])

    def test_clean_scan_can_pass_when_reviewed_findings_are_absent(self) -> None:
        empty = _sarif(self.case, uploaded=False, results=False)
        uploaded_empty = _sarif(self.case, uploaded=True, results=False)
        code, calls, _patches = self._run(
            local=empty,
            uploaded=uploaded_empty,
            analysis=_analysis(self.current_sha, self.case["category"], self.sarif_id, count=0),
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)  # analyses + uploaded SARIF; no absent alert is queried

    def test_local_fingerprint_is_unique_and_upload_join_is_exact(self) -> None:
        changed_local = _sarif(self.case, uploaded=False)
        changed_local["runs"][0]["results"][0]["partialFingerprints"][
            "primaryLocationLineHash"] = "different-line-hash"
        code, _, _ = self._run(local=changed_local)
        self.assertEqual(code, 2)

        duplicate = _sarif(self.case, uploaded=False)
        duplicate["runs"][0]["results"].append(dict(duplicate["runs"][0]["results"][0]))
        duplicate_upload = _sarif(self.case, uploaded=True, alert_number=self.case["alert_number"])
        duplicate_upload["runs"][0]["results"].append(dict(duplicate_upload["runs"][0]["results"][0]))
        code, _, _ = self._run(
            local=duplicate,
            uploaded=duplicate_upload,
            analysis=_analysis(self.current_sha, self.case["category"], self.sarif_id, count=2),
        )
        self.assertEqual(code, 2)

        lower_api_score = _sarif(self.case, uploaded=True, score="7.4", alert_number=self.case["alert_number"])
        code, _, _ = self._run(uploaded=lower_api_score)
        self.assertEqual(code, 2)

        # GitHub's current SARIF API view may omit this secondary fingerprint;
        # if present, a changed value must fail closed.
        bad_uploaded_fingerprint = _sarif(
            self.case,
            uploaded=True,
            alert_number=self.case["alert_number"],
            uploaded_column_fingerprint="different",
        )
        self.assertEqual(self._run(uploaded=bad_uploaded_fingerprint)[0], 2)

        changed_case = dict(self.case)
        changed_case["primaryLocationStartColumnFingerprint"] = "unreviewed-fingerprint"
        with patch.object(gate, "_manifest_cases", return_value={changed_case["alert_number"]: changed_case}):
            self.assertEqual(self._run()[0], 2)

    def test_new_or_duplicate_uploaded_results_fail_closed(self) -> None:
        unknown = _sarif(self.case, uploaded=False)
        unknown["runs"][0]["results"][0]["ruleId"] = "py/unknown-high"
        code, _, patches = self._run(local=unknown, apply=True)
        self.assertEqual(code, 2)
        self.assertEqual(patches, [])

        duplicate = _sarif(self.case, uploaded=False)
        duplicate["runs"][0]["results"].append(dict(duplicate["runs"][0]["results"][0]))
        upload_duplicate = _sarif(
            self.case,
            uploaded=True,
            alert_number=self.case["alert_number"],
        )
        upload_duplicate["runs"][0]["results"].append(dict(upload_duplicate["runs"][0]["results"][0]))
        code, _, _ = self._run(local=duplicate, uploaded=upload_duplicate,
                            analysis=_analysis(self.current_sha, self.case["category"], self.sarif_id, count=2))
        self.assertEqual(code, 2)

    def test_analysis_sha_category_upload_id_and_tool_are_exact(self) -> None:
        bad = _analysis("0" * 40, self.case["category"], self.sarif_id)
        self.assertEqual(self._run(analysis=bad)[0], 2)
        bad_category = _analysis(self.current_sha, "/language:rust", self.sarif_id)
        self.assertEqual(self._run(analysis=bad_category)[0], 2)
        bad_tool = _analysis(self.current_sha, self.case["category"], self.sarif_id)
        bad_tool["tool"]["version"] = "other"
        self.assertEqual(self._run(analysis=bad_tool)[0], 2)
        self.assertEqual(self._run(analyses=[])[0], 2)

    def test_alert_id_reason_state_and_location_are_rechecked_live(self) -> None:
        self.assertEqual(self._run(alert=_live_alert(self.case, state="open"))[0], 2)
        self.assertEqual(self._run(alert=_live_alert(self.case, reason="used in tests"))[0], 2)
        wrong_location = _live_alert(self.case)
        wrong_location["most_recent_instance"]["location"]["start_line"] += 1
        code, _calls, patches = self._run(alert=wrong_location, apply=True)
        self.assertEqual(code, 2)
        self.assertEqual(patches, [])

    def test_open_exact_alert_requires_opt_in_then_patches_and_reads_back(self) -> None:
        open_alert = _live_alert(self.case, state="open")
        code, _calls, patches = self._run(alert=open_alert)
        self.assertEqual(code, 2)
        self.assertEqual(patches, [])

        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            code, calls, patches = self._run(alert=open_alert, apply=True, receipt=receipt)
            self.assertEqual(code, 0)
            self.assertEqual(len(patches), 1)
            self.assertEqual(patches[0][1], {
                "state": "dismissed",
                "dismissed_reason": self.case["expected_dismissed_reason"],
            })
            self.assertEqual(len(calls), 4)  # includes independent post-PATCH GET
            evidence = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(evidence["result"], "pass")
            self.assertEqual(evidence["updated_alert_numbers"], [self.case["alert_number"]])
            self.assertNotIn("message", json.dumps(evidence))

            readback_receipt = Path(directory) / "readback-failure.json"
            code, _calls, _patches = self._run(
                alert=open_alert,
                apply=True,
                receipt=readback_receipt,
                readback_error=True,
            )
            self.assertEqual(code, 2)
            failed = json.loads(readback_receipt.read_text(encoding="utf-8"))
            self.assertEqual(failed["result"], "readback_failed")
            self.assertEqual(failed["updated_alert_numbers"], [self.case["alert_number"]])

            moved_readback = _live_alert(self.case)
            moved_readback["most_recent_instance"]["location"]["start_line"] += 1
            code, _calls, _patches = self._run(
                alert=open_alert,
                apply=True,
                readback_alert=moved_readback,
            )
            self.assertEqual(code, 2)

    def test_live_alert_id_must_be_the_upload_correlated_number(self) -> None:
        wrong_number = _sarif(
            self.case,
            uploaded=True,
            alert_number=self.case["alert_number"] + 1,
        )
        self.assertEqual(self._run(uploaded=wrong_number)[0], 2)

    def test_matching_moved_local_and_live_positions_do_not_reuse_reviewed_id(self) -> None:
        local = _sarif(self.case, uploaded=False)
        uploaded = _sarif(self.case, uploaded=True, alert_number=self.case["alert_number"])
        for payload in (local, uploaded):
            payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] += 1
        moved_alert = _live_alert(self.case)
        moved_alert["most_recent_instance"]["location"]["start_line"] += 1
        code, _calls, patches = self._run(local=local, uploaded=uploaded, alert=moved_alert, apply=True)
        self.assertEqual(code, 2)
        self.assertEqual(patches, [])

    def test_changed_reviewed_file_blob_is_rejected(self) -> None:
        with patch.object(gate, "_working_tree_blob", return_value="0" * 40):
            with self.assertRaises(gate.ReviewedGateError):
                gate._manifest_cases(self.manifest, self.current_sha)

    def test_untrusted_branch_or_event_cannot_use_review_manifest(self) -> None:
        args = self._args()
        args.sha = "0" * 40
        with self.assertRaises(gate.ReviewedGateError):
            gate._validate_context(args)

        args = self._args()
        args.ref = "refs/heads/feature"
        with self.assertRaises(gate.ReviewedGateError):
            gate._validate_context(args)
        args.ref = "refs/heads/main"
        args.event = "pull_request"
        with self.assertRaises(gate.ReviewedGateError):
            gate._validate_context(args)


if __name__ == "__main__":
    unittest.main()
