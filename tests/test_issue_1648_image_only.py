"""Negative controls for the bounded #1648 production image-only route."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "issue_1648_image_only.py"
WORKFLOW = SCRIPT.parents[1] / ".github" / "workflows" / "cf-deploy-prod.yml"
spec = importlib.util.spec_from_file_location("issue_1648_image_only", SCRIPT)
assert spec and spec.loader
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)
APPROVED = {"I1648_AUTHORITY_REF": "issue-1648-comment-123456",
            "I1648_SCOPE_RECEIPT_SHA256": "a" * 64}


def arguments(mode: str, image: str, config_hash: str, receipt: str = "") -> argparse.Namespace:
    return argparse.Namespace(
        mode=mode, expected_app_version="181", expected_config_sha256=config_hash,
        confirm=f"{mode}-iad-b063", timeout_seconds=30, receipt=receipt,
    )


class FakeAPI:
    def __init__(self, image: str = operator.OLD_TAG):
        self.config = {"image": image, "instance_type": "basic", "disk": {"size_mb": 2000}}
        self.version = 181
        self.worker = operator.OLD_WORKER
        self.calls: list[tuple[str, str, object]] = []
        self.rollout = False
        self.ambiguous_patch = False
        self.patch_drift = False
        self.old_tag_digest = operator.OLD_DIGEST
        self.transitional_polls = 0

    def verify_old_tag_manifest(self) -> str:
        self.calls.append(("REGISTRY_GET", operator.OLD_MANIFEST_URL, None))
        return self.old_tag_digest

    def request(self, method: str, path: str, body: object = None) -> object:
        self.calls.append((method, path, body))
        if method == "GET" and path == operator.APP_PATH:
            config = dict(self.config)
            if self.patch_drift and self.version > 181:
                config["instance_type"] = "standard"
            transitioning = self.rollout and self.transitional_polls > 0
            return {
                "id": operator.APP, "name": "corelink-prod-corelinkserver-prod",
                "version": self.version, "configuration": config,
                "durable_objects": {"namespace_id": operator.EXPECTED_DO_NAMESPACE},
                "health": {"errors": [], "instances": {"healthy": 14 if transitioning else 15,
                    "active": 1, "failed": 0, "assigned": 0, "stopped": 0,
                    "scheduling": 0, "starting": 1 if transitioning else 0}},
                "instances": 16, "active_rollout_id": None,
            }
        if method == "GET" and path == operator.DEPLOYMENTS_PATH:
            return [{"versions": [{"version_id": self.worker, "percentage": 100}]}]
        if method == "GET" and path == operator.ROLLOUTS_PATH:
            return []
        if method == "PATCH" and path == operator.APP_PATH:
            if self.ambiguous_patch:
                raise operator.GateError("provider_result_unknown")
            self.config = dict(body["configuration"])
            self.version += 1
            return {"id": operator.APP}
        if method == "POST" and path == operator.ROLLOUTS_PATH:
            self.rollout = True
            return {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
        if method == "GET" and path.endswith("/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"):
            if self.transitional_polls > 0:
                self.transitional_polls -= 1
                return {"status": "progressing"}
            return {"status": "completed"}
        raise AssertionError((method, path))


class OperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.silent = contextlib.redirect_stdout(io.StringIO())
        self.silent.__enter__()

    def tearDown(self) -> None:
        self.silent.__exit__(None, None, None)

    def test_plan_has_no_mutation_and_does_not_claim_write_scope(self) -> None:
        api = FakeAPI()
        result = operator.run(arguments("plan", operator.OLD_TAG, ""), api)
        self.assertEqual(result["state"], "READ_ONLY")
        self.assertEqual(result["write_scope"], "NOT_PROVEN_BY_READ")
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_apply_requires_protected_approval_before_first_write(self) -> None:
        api = FakeAPI()
        args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), "receipt.json")
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(operator.GateError, "production_approval_unbound"):
                operator.run(args, api)
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_version_and_full_config_drift_reject_before_write(self) -> None:
        for value in ("180", "181"):
            api = FakeAPI()
            args = arguments("apply", api.config["image"], "0" * 64, "receipt.json")
            args.expected_app_version = value
            with self.subTest(version=value), patch.dict(os.environ, APPROVED):
                with self.assertRaises(operator.GateError):
                    operator.run(args, api)
            self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_worker_drift_rejects_before_write(self) -> None:
        api = FakeAPI()
        api.worker = "wrong-version"
        args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), "receipt.json")
        with patch.dict(os.environ, APPROVED):
            with self.assertRaisesRegex(operator.GateError, "worker_version_drift"):
                operator.run(args, api)
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_forward_and_rollback_patch_only_image_and_keep_worker(self) -> None:
        for mode, source, target in (("apply", operator.OLD_TAG, operator.NEW_REF),
                                     ("rollback", operator.NEW_REF, operator.OLD_REF)):
            api = FakeAPI(source)
            with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, APPROVED), \
                    patch.object(operator.time, "sleep", return_value=None):
                args = arguments(mode, source, operator.canonical_hash(api.config), str(Path(temp) / "receipt.json"))
                result = operator.run(args, api)
                self.assertEqual(result["state"], "ROLLOUT_COMPLETE")
                self.assertTrue(Path(args.receipt + ".journal").exists())
            patch_calls = [body for method, _, body in api.calls if method == "PATCH"]
            self.assertEqual(len(patch_calls), 1)
            self.assertEqual(patch_calls[0], {"configuration": {
                "image": target, "instance_type": "basic", "disk": {"size_mb": 2000}
            }})
            rollout_calls = [body for method, _, body in api.calls if method == "POST"]
            self.assertEqual(len(rollout_calls), 1)
            self.assertEqual(rollout_calls[0]["target_configuration"]["image"], target)
            self.assertEqual(api.worker, operator.OLD_WORKER)

    def test_ambiguous_patch_stops_without_retry_or_rollout(self) -> None:
        api = FakeAPI()
        api.ambiguous_patch = True
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, APPROVED):
            args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), str(Path(temp) / "receipt.json"))
            with self.assertRaisesRegex(operator.GateError, "provider_result_unknown"):
                operator.run(args, api)
            self.assertIn("PREPARED_BEFORE_PATCH", Path(args.receipt + ".journal").read_text())
        self.assertEqual(sum(method == "PATCH" for method, _, _ in api.calls), 1)
        self.assertEqual(sum(method == "POST" for method, _, _ in api.calls), 0)

    def test_non_image_provider_drift_stops_before_rollout(self) -> None:
        api = FakeAPI()
        api.patch_drift = True
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, APPROVED):
            args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), str(Path(temp) / "receipt.json"))
            with self.assertRaisesRegex(operator.GateError, "patch_non_image_drift"):
                operator.run(args, api)
        self.assertEqual(sum(method == "POST" for method, _, _ in api.calls), 0)

    def test_old_tag_digest_drift_rejects_before_app_mutation(self) -> None:
        api = FakeAPI()
        api.old_tag_digest = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, APPROVED):
            args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), str(Path(temp) / "receipt.json"))
            with self.assertRaisesRegex(operator.GateError, "old_tag_digest_drift"):
                operator.run(args, api)
        self.assertEqual(sum(method == "PATCH" for method, _, _ in api.calls), 0)

    def test_malformed_authority_and_scope_inputs_reject_before_app_mutation(self) -> None:
        for field, value, error in (("I1648_AUTHORITY_REF", "unbound", "production_approval_unbound"),
                                    ("I1648_SCOPE_RECEIPT_SHA256", "not-a-sha", "scope_receipt_hash_invalid")):
            api = FakeAPI()
            env = dict(APPROVED)
            env[field] = value
            with self.subTest(field=field), patch.dict(os.environ, env, clear=True):
                args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), "receipt.json")
                with self.assertRaisesRegex(operator.GateError, error):
                    operator.run(args, api)
            self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_scope_receipt_is_optional_when_live_token_scope_is_unproven(self) -> None:
        api = FakeAPI()
        env = dict(APPROVED)
        env["I1648_SCOPE_RECEIPT_SHA256"] = ""
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, env, clear=True), \
                patch.object(operator.time, "sleep", return_value=None):
            args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), str(Path(temp) / "receipt.json"))
            result = operator.run(args, api)
        self.assertEqual(result["state"], "ROLLOUT_COMPLETE")

    def test_transitional_rollout_health_is_polled_until_terminal_ready(self) -> None:
        api = FakeAPI()
        api.transitional_polls = 2
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, APPROVED), \
                patch.object(operator.time, "sleep", return_value=None):
            args = arguments("apply", api.config["image"], operator.canonical_hash(api.config), str(Path(temp) / "receipt.json"))
            result = operator.run(args, api)
        self.assertEqual(result["state"], "ROLLOUT_COMPLETE")
        self.assertEqual(sum(method == "POST" for method, _, _ in api.calls), 1)

    def test_existing_full_and_release_routes_remain_separate_from_image_only(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn('workflows: ["release-cli"]', source)
        self.assertIn('[[ "$OPERATION" == full && "$CONFIRM" == deploy-prod ]]', source)
        self.assertIn('if [ "$OPERATION" = image-only ]; then\n            echo \'matrix={"env":["prod"]}\'', source)
        self.assertIn("if: inputs.operation != 'image-only'\n        env:\n          CLOUDFLARE_API_TOKEN:", source)
        self.assertIn("if: inputs.operation == 'image-only'\n        env:\n          CF_API_TOKEN:", source)

    def test_image_only_rejects_unprotected_or_shared_d1_mutation_path(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn('[[ "$TARGET_ENV" == prod && "$SKIP_PIN_FRESHNESS" != true ]]', source)
        self.assertIn('[[ "$GITHUB_REF" == refs/heads/main && "$GITHUB_REF_PROTECTED" == true ]]', source)
        self.assertIn('[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ && "$EXPECTED_SHA" == "$GITHUB_SHA" ]]', source)
        self.assertIn("&& inputs.operation != 'image-only'\n      && inputs.env == ''", source)
        self.assertIn("if: success() && inputs.operation != 'image-only'", source)


if __name__ == "__main__":
    unittest.main()
