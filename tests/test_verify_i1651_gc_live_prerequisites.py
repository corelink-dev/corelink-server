from __future__ import annotations

import sys
import unittest
from unittest import mock
from pathlib import Path
import base64
import json
import os
import stat
import subprocess
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_i1651_gc_live_prerequisites import Blocked, _verify_observation_workflow
import run_b071_gc_observation_from_image as wrapper
from run_b071_gc_observation_from_image import GateError, _require_repo_digest, _validate_inputs, run


class StagingObservationWorkflowTest(unittest.TestCase):
    def test_image_build_reference_is_not_a_staging_observation(self) -> None:
        with self.assertRaisesRegex(Blocked, "missing dedicated staging observation workflow"):
            _verify_observation_workflow(
                {
                    "container-build-push-prod.yml": (
                        "verify /usr/local/bin/corelink-gc-sweep-production is in the image"
                    )
                }
            )

    def test_requires_manual_bounded_read_only_staging_lane(self) -> None:
        valid = (Path(__file__).resolve().parents[1] / ".github/workflows/issue-1651-gc-staging-observation.yml").read_text()
        _verify_observation_workflow({"issue-1651-gc-staging-observation.yml": valid})

        for mutant in (
            valid.replace("workflow_dispatch:", "workflow_dispatch:\n  push:"),
            valid.replace("environment: staging", "environment: production"),
            valid.replace("timeout-minutes: 5", "timeout-minutes: 15"),
            valid.replace("contents: read", "contents: write"),
            valid.replace(
                "          B071_GC_OBSERVATION_SCOPE_JSON: ${{ secrets.B071_GC_OBSERVATION_SCOPE_JSON }}\n",
                "",
            ).replace(
                "          if-no-files-found: error",
                "          if-no-files-found: error\n"
                "          B071_GC_OBSERVATION_SCOPE_JSON: ${{ secrets.B071_GC_OBSERVATION_SCOPE_JSON }}",
            ),
            valid.replace(
                "          R2_TDK_HEX: ${{ secrets.R2_TDK_HEX }}",
                "          R2_TDK_HEX: ${{ secrets.R2_TDK_HEX }}\n"
                "          UNEXPECTED: value",
            ),
            valid.replace("run: python3 scripts/run_b071_gc_observation_from_image.py", "run: /bin/true"),
            valid.replace("    environment: staging", "    if: false\n    environment: staging"),
            valid
            + "      - name: mutate\n"
            + "        run: curl -X DELETE https://provider.example/objects\n",
            valid.replace(
                "        run: python3 scripts/run_b071_gc_observation_from_image.py",
                "        shell: bash -c 'source {0}; curl -X DELETE https://provider.example/objects'\n"
                "        run: python3 scripts/run_b071_gc_observation_from_image.py",
            ),
            valid.replace(
                "        run: python3 scripts/run_b071_gc_observation_from_image.py",
                "        run: python3 scripts/run_b071_gc_observation_from_image.py\n"
                "          && curl -X DELETE https://provider.example/objects",
            ),
            valid.replace(
                "permissions:\n",
                "defaults:\n  run:\n    shell: bash -c 'source {0}; curl -X DELETE https://provider.example/objects'\n"
                "permissions:\n",
            ),
        ):
            with self.subTest(mutant=mutant):
                with self.assertRaises(Blocked):
                    _verify_observation_workflow(
                        {"issue-1651-gc-staging-observation.yml": mutant}
                    )

    def test_runtime_bindings_fail_before_docker(self) -> None:
        source_sha = wrapper._git_head()
        account = "6a1fc1c626fc2628823e60b9db01f5cd"
        base = {
            "B071_GC_OBSERVATION_IMAGE_REF": f"registry.cloudflare.com/{account}/corelink-prod-sam-corelinkserver-prod@sha256:" + "a" * 64,
            "B071_GC_OBSERVATION_SCOPE_JSON": '{"schema_version":1,"scopes":[{"tenant_id":"123e4567-e89b-12d3-a456-426614174000","region":"sam","run_id":"123e4567-e89b-12d3-a456-426614174001","bucket":"gc"}]}',
            "B071_CF_REGISTRY_READ_TOKEN": "registry-read-token",
            "CLOUDFLARE_ACCOUNT_ID": account, "D1_DATABASE_ID": "x", "CF_API_TOKEN": "d1-read-token",
            "R2_TDK_HEX": "x", "GITHUB_ACTOR": "operator",
            "B071_SOURCE_REF": "refs/heads/main", "B071_SOURCE_SHA": source_sha,
        }
        self.assertEqual(_validate_inputs(base)[0], base["B071_GC_OBSERVATION_IMAGE_REF"])
        for key, value in (("CF_API_TOKEN", ""),
                           ("CF_API_TOKEN", "registry-read-token"),
                           ("B071_CF_REGISTRY_READ_TOKEN", ""),
                           ("B071_GC_OBSERVATION_IMAGE_REF", "latest"),
                           ("B071_GC_OBSERVATION_IMAGE_REF", f"registry.cloudflare.com/{'b' * 32}/corelink-prod-sam-corelinkserver-prod@sha256:" + "a" * 64),
                           ("B071_GC_OBSERVATION_IMAGE_REF", f"registry.cloudflare.com/{account}/unrelated@sha256:" + "a" * 64),
                           ("B071_GC_OBSERVATION_SCOPE_JSON", '{"schema_version":1,"scopes":[]}'),
                           ("B071_SOURCE_REF", "refs/heads/feature/test"),
                           ("B071_SOURCE_SHA", "f" * 40)):
            mutant = dict(base)
            mutant[key] = value
            with self.subTest(key=key), self.assertRaises(GateError):
                _validate_inputs(mutant)
        with mock.patch.object(wrapper, "_run") as docker_or_collector, \
             mock.patch.object(wrapper, "_mint_pull_credentials") as mint:
            with self.assertRaises(GateError):
                run({**base, "CF_API_TOKEN": ""})
            docker_or_collector.assert_not_called()
            mint.assert_not_called()

    def test_extraction_image_digest_must_match_the_requested_ref(self) -> None:
        image = "registry.example/b071@sha256:" + "a" * 64
        _require_repo_digest(image, f'["{image}"]')
        with self.assertRaisesRegex(GateError, "not bound"):
            _require_repo_digest(image, '["registry.example/b071@sha256:' + "b" * 64 + '"]')

    def test_registry_credential_request_is_pull_only_and_strictly_bound(self) -> None:
        account = "6a1fc1c626fc2628823e60b9db01f5cd"
        response_body = json.dumps({
            "success": True,
            "errors": [],
            "messages": [],
            "result": {
                "account_id": account,
                "password": "temporary-password",
                "registry_host": "registry.cloudflare.com",
                "username": "temporary-user",
            },
        }).encode()

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                return response_body

        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()

        opener = Opener()
        with mock.patch.object(wrapper.urllib.request, "build_opener", return_value=opener):
            username, password, deadline = wrapper._mint_pull_credentials(account, "do-not-print")
        self.assertEqual((username, password), ("temporary-user", "temporary-password"))
        self.assertEqual(opener.request.full_url,
                         wrapper.REGISTRY_CREDENTIAL_URL.format(account_id=account))
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.timeout, 10)
        self.assertEqual(json.loads(opener.request.data), {
            "permissions": ["pull"],
            "expiration_minutes": wrapper.REGISTRY_CREDENTIAL_EXPIRY_MINUTES,
        })
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer do-not-print")
        self.assertGreater(deadline, wrapper.time.monotonic())

    def test_registry_credential_mismatch_and_api_error_are_redacted(self) -> None:
        response_body = json.dumps({
            "success": True,
            "errors": [],
            "messages": [],
            "result": {
                "account_id": "b" * 32,
                "password": "do-not-print",
                "registry_host": "registry.cloudflare.com",
                "username": "temporary-user",
            },
        }).encode()

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                return response_body

        class Opener:
            def open(self, _request, timeout):
                return Response()

        with mock.patch.object(wrapper.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(GateError, "did not match") as mismatch:
                wrapper._mint_pull_credentials("a" * 32, "token")
        self.assertNotIn("do-not-print", str(mismatch.exception))

        class FailingOpener:
            def open(self, _request, timeout):
                raise wrapper.urllib.error.HTTPError(
                    "https://api.cloudflare.com/", 403, "forbidden", {},
                    __import__("io").BytesIO(b"secret response body"),
                )

        with mock.patch.object(wrapper.urllib.request, "build_opener", return_value=FailingOpener()):
            with self.assertRaisesRegex(GateError, "HTTP 403") as failure:
                wrapper._mint_pull_credentials("a" * 32, "token")
        self.assertNotIn("secret response body", str(failure.exception))

        for invalid in (
            {"success": False, "errors": [{"message": "private token text"}], "messages": [], "result": {}},
            {"success": True, "errors": [], "messages": [], "result": {}, "unexpected": "value"},
        ):
            class InvalidResponse(Response):
                def read(self, limit):
                    return json.dumps(invalid).encode()

            class InvalidOpener:
                def open(self, _request, timeout):
                    return InvalidResponse()

            with mock.patch.object(wrapper.urllib.request, "build_opener", return_value=InvalidOpener()):
                with self.assertRaisesRegex(GateError, "was not successful") as invalid_error:
                    wrapper._mint_pull_credentials("a" * 32, "token")
            self.assertNotIn("private token text", str(invalid_error.exception))

    def test_private_registry_config_is_exact_and_mode_restricted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            docker_config = Path(directory) / "docker"
            path = wrapper._write_registry_docker_config(docker_config, "pull-user", "pull-password")
            self.assertEqual(stat.S_IMODE(docker_config.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            data = json.loads(path.read_text())
            self.assertEqual(set(data), {"auths"})
            self.assertEqual(set(data["auths"]), {"registry.cloudflare.com"})
            decoded = base64.b64decode(data["auths"]["registry.cloudflare.com"]["auth"])
            self.assertEqual(decoded, b"pull-user:pull-password")

    def test_pull_cleanup_runs_for_digest_mismatch(self) -> None:
        image = "registry.cloudflare.com/" + "a" * 32 + "/corelink-prod-sam-corelinkserver-prod@sha256:" + "a" * 64
        deadline = wrapper.time.monotonic() + 900
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if command[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(command, 0, stdout='["' + image.replace("a" * 64, "b" * 64) + '"]')
            return subprocess.CompletedProcess(command, 0, stdout="container-id\n")

        with mock.patch.object(wrapper, "_run", side_effect=fake_run):
            with self.assertRaisesRegex(GateError, "not bound"):
                wrapper._pull_and_verify_image(image, "user", "password", deadline)
        self.assertEqual([call[1:3] for call in calls], [["pull", image], ["image", "inspect"], ["logout", "registry.cloudflare.com"]])

    def test_pull_cleanup_runs_on_failure_and_expired_lease_fails_before_pull(self) -> None:
        image = "registry.cloudflare.com/" + "a" * 32 + "/corelink-prod-sam-corelinkserver-prod@sha256:" + "a" * 64
        calls = []

        def failing_run(command, **kwargs):
            calls.append(command)
            if command[1:2] == ["pull"]:
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0, stdout="")

        with mock.patch.object(wrapper, "_run", side_effect=failing_run):
            with self.assertRaises(subprocess.CalledProcessError):
                wrapper._pull_and_verify_image(image, "user", "password", wrapper.time.monotonic() + 900)
        self.assertEqual([call[1:2] for call in calls], [["pull"], ["logout"]])

        calls.clear()
        with mock.patch.object(wrapper, "_run", side_effect=failing_run):
            with self.assertRaisesRegex(GateError, "close to expiry"):
                wrapper._pull_and_verify_image(image, "user", "password", wrapper.time.monotonic() - 1)
        self.assertEqual([call[1:2] for call in calls], [["logout"]])


if __name__ == "__main__":
    unittest.main()
