#!/usr/bin/env python3
"""Focused API, scope, and secret-handoff tests for the R2 bootstrap."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "issue_2564_r2_temp_credentials.py"
SPEC = importlib.util.spec_from_file_location("r2_temp_credentials", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ACCOUNT = MODULE.EXPECTED_ACCOUNT
BUCKET = MODULE.EXPECTED_BUCKET
TOKEN_ID = "abcdef0123456789abcdef0123456789"
PARENT_ID = "parent-access-key-sentinel"
BEARER = "bearer-token-sentinel"
TRIO = {
    "accessKeyId": "temporary-key-id",
    "secretAccessKey": "temporary-secret",
    "sessionToken": "temporary-session",
}


def success(result: dict) -> tuple[int, dict]:
    return 200, {"success": True, "result": result}


def token_metadata(*, status: str = "active", policies: list[dict] | None = None):
    return {
        "verify": success({"id": TOKEN_ID, "status": status}),
        "detail": success(
            {
                "id": TOKEN_ID,
                "policies": policies
                if policies is not None
                else [
                    {
                        "effect": "allow",
                        "resources": {MODULE.ACCOUNT_SCOPE: ACCOUNT},
                        "permission_groups": [{"id": "r2-write", "name": MODULE.R2_WRITE_GROUP}],
                    }
                ],
            }
        ),
    }


def baseline_env() -> dict[str, str]:
    return {
        "REAL_HARNESS_PROFILE": "r2",
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
        "CF_API_TOKEN": BEARER,
        "D1_DATABASE_ID": "test",
        "R2_S3_ENDPOINT": f"https://{ACCOUNT}.r2.cloudflarestorage.com",
        "R2_S3_ACCESS_KEY_ID": PARENT_ID,
        "R2_S3_SECRET_ACCESS_KEY": "",
        "R2_S3_SESSION_TOKEN": "",
        "R2_TEST_BUCKET": BUCKET,
        "R2_PARENT_SCOPE_CONFIRMED_ACCESS_KEY_ID": PARENT_ID,
        "R2_PARENT_SCOPE_CONFIRMED_BUCKET": BUCKET,
        "R2_PARENT_SCOPE_RECEIPT_SHA256": "a" * 64,
    }


class TemporaryCredentialTests(unittest.TestCase):
    def test_read_only_classifier_requires_active_exact_account_r2_write(self) -> None:
        calls: list[tuple[str, str]] = []
        metadata = token_metadata()

        def fetch(method, path, _token, **_kwargs):
            calls.append((method, path))
            if path == "/user/tokens/verify":
                return metadata["verify"]
            if path == f"/user/tokens/{TOKEN_ID}":
                return metadata["detail"]
            raise AssertionError("unexpected provider call")

        MODULE.classify_bearer_r2_write(account_id=ACCOUNT, bearer=BEARER, fetch=fetch)
        self.assertEqual(
            calls,
            [("GET", "/user/tokens/verify"), ("GET", f"/user/tokens/{TOKEN_ID}")],
        )
        for bad_metadata in (
            token_metadata(status="expired"),
            token_metadata(policies=[]),
            token_metadata(
                policies=[
                    {
                        "effect": "allow",
                        "resources": {MODULE.ACCOUNT_SCOPE: "*"},
                        "permission_groups": [{"id": "r2-write", "name": MODULE.R2_WRITE_GROUP}],
                    }
                ]
            ),
            token_metadata(
                policies=[
                    {
                        "effect": "allow",
                        "resources": {MODULE.ACCOUNT_SCOPE: ACCOUNT},
                        "permission_groups": [{"id": "d1-write", "name": "D1 Database Write"}],
                    }
                ]
            ),
        ):
            def bad_fetch(method, path, _token, **_kwargs):
                return bad_metadata["verify"] if path.endswith("/verify") else bad_metadata["detail"]

            with self.subTest(metadata=bad_metadata), self.assertRaises(MODULE.BootstrapError):
                MODULE.classify_bearer_r2_write(account_id=ACCOUNT, bearer=BEARER, fetch=bad_fetch)

    def test_temp_request_is_exact_bucket_object_rw_ttl_and_maps_return_trio(self) -> None:
        observed: dict[str, object] = {}

        def fetch(method, path, bearer, *, body=None):
            observed.update(method=method, path=path, bearer=bearer, body=body)
            return success(TRIO)

        credentials = MODULE.request_temporary_credentials(
            account_id=ACCOUNT,
            bucket=BUCKET,
            parent_access_key_id=PARENT_ID,
            bearer=BEARER,
            fetch=fetch,
        )
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], f"/accounts/{ACCOUNT}/r2/temp-access-credentials")
        self.assertEqual(observed["bearer"], BEARER)
        self.assertEqual(
            observed["body"],
            {
                "bucket": BUCKET,
                "parentAccessKeyId": PARENT_ID,
                "permission": "object-read-write",
                "ttlSeconds": 7200,
            },
        )
        self.assertEqual(
            (credentials.access_key_id, credentials.secret_access_key, credentials.session_token),
            (TRIO["accessKeyId"], TRIO["secretAccessKey"], TRIO["sessionToken"]),
        )

    def test_request_rejects_wrong_target_and_incomplete_provider_response(self) -> None:
        def fetch(_method, _path, _bearer, **_kwargs):
            return success({"accessKeyId": "one-field-only"})

        with self.assertRaises(MODULE.BootstrapError):
            MODULE.request_temporary_credentials(
                account_id=ACCOUNT,
                bucket="production-bucket",
                parent_access_key_id=PARENT_ID,
                bearer=BEARER,
                fetch=fetch,
            )
        with self.assertRaises(MODULE.BootstrapError):
            MODULE.request_temporary_credentials(
                account_id=ACCOUNT,
                bucket=BUCKET,
                parent_access_key_id=PARENT_ID,
                bearer=BEARER,
                fetch=fetch,
            )

    def test_runner_gets_only_trio_with_inert_d1_values_and_masks(self) -> None:
        env = baseline_env()
        metadata = token_metadata()
        masks: list[str] = []
        observed: dict[str, object] = {}
        calls: list[tuple[str, str]] = []

        def fetch(method, path, _token, *, body=None):
            calls.append((method, path))
            if path == "/user/tokens/verify":
                return metadata["verify"]
            if path == f"/user/tokens/{TOKEN_ID}":
                return metadata["detail"]
            observed["body"] = body
            return success(TRIO)

        def fake_run(command, *, cwd, env, check, text):
            observed.update(command=command, cwd=cwd, env=env.copy(), child_ref=env, check=check, text=text)
            return subprocess.CompletedProcess(command, 17)

        result = MODULE.run_r2_profile(
            env, emit=masks.append, run=fake_run, fetch=fetch, cwd=ROOT
        )
        self.assertEqual(result, 17)
        self.assertEqual(calls[-1], ("POST", f"/accounts/{ACCOUNT}/r2/temp-access-credentials"))
        self.assertEqual(observed["command"], list(MODULE.RUNNER))
        self.assertEqual(observed["check"], False)
        child_env = observed["env"]
        self.assertEqual(child_env["R2_S3_ACCESS_KEY_ID"], TRIO["accessKeyId"])
        self.assertEqual(child_env["R2_S3_SECRET_ACCESS_KEY"], TRIO["secretAccessKey"])
        self.assertEqual(child_env["R2_S3_SESSION_TOKEN"], TRIO["sessionToken"])
        self.assertEqual(child_env["CF_API_TOKEN"], "test")
        self.assertEqual(child_env["D1_DATABASE_ID"], "test")
        self.assertEqual(env["CF_API_TOKEN"], BEARER)
        self.assertEqual(env["R2_S3_ACCESS_KEY_ID"], PARENT_ID)
        self.assertEqual(observed["child_ref"], {})
        self.assertEqual(len(masks), 5)
        self.assertNotIn(BEARER, repr(observed["env"]))
        self.assertNotIn(PARENT_ID, repr(observed["env"]))
        self.assertNotIn("temporary-secret", repr(MODULE.TemporaryCredentials("a", "temporary-secret", "s")))

    def test_token_detail_403_does_not_block_exact_scoped_temporary_request(self) -> None:
        env = baseline_env()
        calls: list[tuple[str, str]] = []
        masks: list[str] = []

        def fetch(method, path, _token, *, body=None):
            calls.append((method, path))
            if path == "/user/tokens/verify":
                return success({"id": TOKEN_ID, "status": "active"})
            if path == f"/user/tokens/{TOKEN_ID}":
                return 403, None
            self.assertEqual(method, "POST")
            self.assertEqual(path, f"/accounts/{ACCOUNT}/r2/temp-access-credentials")
            self.assertEqual(
                body,
                {
                    "bucket": BUCKET,
                    "parentAccessKeyId": PARENT_ID,
                    "permission": "object-read-write",
                    "ttlSeconds": 7200,
                },
            )
            return success(TRIO)

        result = MODULE.run_r2_profile(
            env,
            emit=masks.append,
            run=lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
            fetch=fetch,
            cwd=ROOT,
        )
        self.assertEqual(result, 0)
        self.assertEqual(calls, [
            ("GET", "/user/tokens/verify"),
            ("GET", f"/user/tokens/{TOKEN_ID}"),
            ("POST", f"/accounts/{ACCOUNT}/r2/temp-access-credentials"),
        ])
        self.assertEqual(len(masks), 5)

    def test_bootstrap_missing_parent_or_bad_scope_stops_before_post_and_runner(self) -> None:
        for key in (
            "R2_S3_ACCESS_KEY_ID",
            "CF_API_TOKEN",
            "R2_PARENT_SCOPE_CONFIRMED_ACCESS_KEY_ID",
            "R2_PARENT_SCOPE_CONFIRMED_BUCKET",
            "R2_PARENT_SCOPE_RECEIPT_SHA256",
        ):
            env = baseline_env()
            env[key] = ""
            calls: list[tuple[str, str]] = []

            def fetch(method, path, _token, **_kwargs):
                calls.append((method, path))
                return 403, None

            with self.subTest(key=key), self.assertRaises(MODULE.BootstrapError):
                MODULE.run_r2_profile(
                    env,
                    emit=lambda _line: None,
                    run=lambda *_args, **_kwargs: self.fail("runner called"),
                    fetch=fetch,
                    cwd=ROOT,
                )
            self.assertNotIn(("POST", f"/accounts/{ACCOUNT}/r2/temp-access-credentials"), calls)

        for key, wrong_value in (
            ("R2_PARENT_SCOPE_CONFIRMED_ACCESS_KEY_ID", "another-parent-id"),
            ("R2_PARENT_SCOPE_CONFIRMED_BUCKET", "shared-bucket-staging"),
            ("R2_PARENT_SCOPE_RECEIPT_SHA256", "not-a-receipt"),
        ):
            env = baseline_env()
            env[key] = wrong_value
            calls = []

            def should_not_call(method, path, _token, **_kwargs):
                calls.append((method, path))
                raise AssertionError("provider call before scope readback gate")

            with self.subTest(tampered=key), self.assertRaises(MODULE.BootstrapError):
                MODULE.run_r2_profile(
                    env,
                    emit=lambda _line: None,
                    run=lambda *_args, **_kwargs: self.fail("runner called"),
                    fetch=should_not_call,
                    cwd=ROOT,
                )
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
