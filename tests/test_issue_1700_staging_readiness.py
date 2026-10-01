from __future__ import annotations

import contextlib
import base64
import datetime as dt
import io
import json
import os
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts import issue_1700_staging_readiness as readiness


NOW = dt.datetime(2026, 10, 1, 12, tzinfo=dt.UTC)
RELEASE = "a" * 40
SOURCE = "b" * 40
TENANT = "019e7109-e514-72b2-ac5b-607d97ea64a1"
CURRENT = "current-secret-sentinel-" + "a" * 64
PREVIOUS = "previous-secret-sentinel-" + "b" * 64
PREFIX = "private-prefix-sentinel"


def identity_receipt() -> dict:
    return {"schema": 1, "environment": "staging", "target": readiness.ORIGIN,
            "tenant_id": TENANT, "deployment_sha": RELEASE,
            "issued_at": "2026-10-01T11:00:00Z", "expires_at": "2026-10-01T13:00:00Z"}


def environment(previous: bool = False) -> dict:
    result = {"K6_STAGING_PAT": CURRENT, "K6_TARGET_IDENTITY_RECEIPT": json.dumps(identity_receipt())}
    if previous:
        result["K6_STAGING_PREVIOUS_PAT"] = PREVIOUS
    return result


def identity_body(**changes) -> bytes:
    return json.dumps({"tenant_id": TENANT, "token_prefix": PREFIX, "route_kind": "reapi_v1", **changes}).encode()


def run(transport, *, mode="readiness", environ=None, **changes) -> dict:
    arguments = {"mode": mode, "expected_release": RELEASE, "source_sha": SOURCE,
                 "run_id": "123456789", "job_id": "987654321", "clock": lambda: NOW,
                 "environ": environment() if environ is None else environ, "transport": transport, **changes}
    return readiness.run_checks(**arguments)


def scripted(*responses):
    pending = list(responses)
    calls = []

    def request(token):
        calls.append(token)
        response = pending.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    return request, calls


class StagingReadinessTests(unittest.TestCase):
    def assert_redacted(self, value) -> None:
        rendered = json.dumps(value)
        for private in (TENANT, PREFIX, CURRENT, PREVIOUS, "secret-sentinel", "malicious-provider-body"):
            self.assertNotIn(private, rendered)

    def test_readiness_rotation_and_teardown_have_exact_order_and_bounded_receipts(self) -> None:
        for mode, previous in (("readiness", False), ("rotation", True), ("teardown", False), ("teardown", True)):
            with self.subTest(mode=mode, previous=previous):
                valid = mode != "teardown"
                responses = [(401, b"ignored"), (401, b"ignored"), (200, identity_body()) if valid else (401, b"ignored")]
                if previous:
                    responses.append((401, b"ignored"))
                transport, calls = scripted(*responses)
                receipt = run(transport, mode=mode, environ=environment(previous))
                self.assertTrue(receipt["success"])
                self.assertEqual(receipt["error"], "none")
                self.assertEqual(calls, [None, readiness.INVALID_PAT, CURRENT] + ([PREVIOUS] if previous else []))
                self.assertEqual(receipt["deployment_release"], RELEASE)
                self.assertEqual(receipt["release_attribution"], "protected_identity_receipt")
                self.assertTrue(receipt["identity_receipt_valid"])
                self.assertEqual(receipt["previous_bound"], previous)
                self.assertEqual(set(receipt), {
                    "contract", "mode", "source_sha", "deployment_release", "release_attribution",
                    "run_id", "job_id", "identity_receipt_valid", "previous_bound", "checks", "success", "error", "completed_at",
                })
                self.assertEqual(set(receipt["checks"]), {"missing", "invalid", "current", "previous"})
                for arm in receipt["checks"].values():
                    self.assertEqual(set(arm), {"attempted", "http_status", "expected_status", "passed"})
                    self.assertIs(type(arm["attempted"]), bool)
                    self.assertIs(type(arm["passed"]), bool)
                self.assertLess(len(json.dumps(receipt)), 2048)
                self.assert_redacted(receipt)

    def test_missing_invalid_revoked_current_or_unrevoked_previous_fail_closed(self) -> None:
        cases = (
            ("readiness", [(200, identity_body())], 1),
            ("readiness", [(401, b""), (200, identity_body())], 2),
            ("readiness", [(401, b""), (401, b""), (401, b"malicious-provider-body")], 3),
            ("rotation", [(401, b""), (401, b""), (401, b"malicious-provider-body")], 3),
            ("rotation", [(401, b""), (401, b""), (200, identity_body()), (200, identity_body())], 4),
            ("teardown", [(401, b""), (401, b""), (200, identity_body())], 3),
            ("teardown", [(401, b""), (401, b""), (401, b""), (200, identity_body())], 4),
        )
        for mode, responses, count in cases:
            with self.subTest(mode=mode, count=count):
                transport, calls = scripted(*responses)
                receipt = run(transport, mode=mode, environ=environment(True))
                self.assertFalse(receipt["success"])
                self.assertEqual(receipt["error"], "unexpected_http_status")
                self.assertEqual(len(calls), count)
                self.assert_redacted(receipt)

    def test_redirects_never_produce_a_second_request(self) -> None:
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                transport, calls = scripted((status, b"malicious-provider-body"))
                receipt = run(transport)
                self.assertEqual(receipt["error"], "redirect_rejected")
                self.assertEqual(calls, [None])
                self.assertFalse(receipt["checks"]["invalid"]["attempted"])
                self.assert_redacted(receipt)

    def test_success_body_requires_exact_private_pat_identity(self) -> None:
        bodies = (
            (b"malicious-provider-body", "identity_response_invalid"),
            (b"\xff", "identity_response_invalid"),
            (b"[]", "identity_response_invalid"),
            (identity_body(extra="secret-sentinel"), "identity_response_invalid"),
            (identity_body(tenant_id="wrong-tenant-sentinel"), "identity_tenant_mismatch"),
            (identity_body(tenant_id="_unknown"), "identity_tenant_mismatch"),
            (identity_body(route_kind="clerk"), "identity_route_mismatch"),
            (identity_body(token_prefix="clerk"), "identity_token_prefix_invalid"),
            (identity_body(token_prefix="Clerk"), "identity_token_prefix_invalid"),
            (identity_body(token_prefix="_unknown"), "identity_token_prefix_invalid"),
            (identity_body(token_prefix=""), "identity_token_prefix_invalid"),
            (identity_body(token_prefix=" \r\nsecret-sentinel"), "identity_token_prefix_invalid"),
            (identity_body(token_prefix=True), "identity_token_prefix_invalid"),
            (identity_body().replace(b'"route_kind":', b'"route_kind":"other","route_kind":'), "identity_response_invalid"),
            (identity_body().replace(json.dumps(TENANT).encode(), b"NaN"), "identity_response_invalid"),
        )
        for body, error in bodies:
            with self.subTest(error=error, body_length=len(body)):
                transport, calls = scripted((401, b""), (401, b""), (200, body))
                receipt = run(transport)
                self.assertEqual(receipt["error"], error)
                self.assertFalse(receipt["checks"]["current"]["passed"])
                self.assertEqual(len(calls), 3)
                self.assert_redacted(receipt)

    def test_overflow_timeout_and_malicious_errors_are_fixed_and_redacted(self) -> None:
        for response, error in (
            ((401, b"malicious-provider-body" + b"x" * 4096), "response_oversized"),
            (TimeoutError("secret-sentinel"), "transport_timeout"),
            (RuntimeError("malicious-provider-body"), "transport_error"),
            ((True, b""), "transport_error"),
        ):
            with self.subTest(error=error):
                transport, calls = scripted(response)
                receipt = run(transport)
                self.assertFalse(receipt["success"])
                self.assertEqual(receipt["error"], error)
                self.assertEqual(len(calls), 1)
                self.assert_redacted(receipt)

    def test_invalid_arguments_and_credentials_are_rejected_before_network(self) -> None:
        for overrides in (dict(mode="url-secret-sentinel"), dict(expected_release="HEAD"), dict(source_sha="A" * 40),
                          dict(run_id="0"), dict(job_id="-1"), dict(job_id="1\nsecret-sentinel")):
            with self.subTest(overrides=overrides):
                transport = mock.Mock()
                receipt = run(transport, **overrides)
                self.assertEqual(receipt["error"], "invalid_arguments")
                transport.assert_not_called()
                self.assert_redacted(receipt)
        for field in ("K6_STAGING_PAT", "K6_STAGING_PREVIOUS_PAT"):
            for value in (" leading", "trailing ", "embedded space", "line\r\nbreak", "tab\t", "\u00a0", "x" * 257):
                with self.subTest(field=field, length=len(value)):
                    env = environment(True)
                    env[field] = value
                    transport = mock.Mock()
                    self.assertEqual(run(transport, environ=env)["error"], "credentials_malformed")
                    transport.assert_not_called()
        for mode, field in (("readiness", "K6_STAGING_PAT"), ("rotation", "K6_STAGING_PREVIOUS_PAT")):
            for value in (None, ""):
                env = environment(True)
                if value is None:
                    del env[field]
                else:
                    env[field] = value
                transport = mock.Mock()
                self.assertEqual(run(transport, mode=mode, environ=env)["error"], "credentials_missing")
                transport.assert_not_called()
        env = environment(True)
        env["K6_STAGING_PREVIOUS_PAT"] = CURRENT
        transport = mock.Mock()
        self.assertEqual(run(transport, mode="rotation", environ=env)["error"], "rotation_credentials_equal")
        transport.assert_not_called()

    def test_private_receipt_errors_reject_before_network(self) -> None:
        cases = (
            ({"schema": True}, "identity_receipt_invalid"),
            ({"deployment_sha": "c" * 40}, "identity_release_mismatch"),
            ({"issued_at": "2026-10-01T12:00:01Z"}, "identity_issued_in_future"),
            ({"expires_at": "2026-10-01T12:00:00Z"}, "identity_receipt_invalid"),
            ({"target": "https://other.invalid"}, "identity_receipt_invalid"),
            ({"extra": "secret-sentinel"}, "identity_receipt_invalid"),
        )
        for changes, error in cases:
            with self.subTest(error=error):
                env = environment()
                env["K6_TARGET_IDENTITY_RECEIPT"] = json.dumps({**identity_receipt(), **changes})
                transport = mock.Mock()
                receipt = run(transport, environ=env)
                self.assertEqual(receipt["error"], error)
                self.assertFalse(receipt["identity_receipt_valid"])
                self.assert_redacted(receipt)
                transport.assert_not_called()
        for raw in ("", "secret-sentinel", "x" * 8193,
                    json.dumps(identity_receipt()).replace('"schema": 1', '"schema": 1, "schema": 1')):
            env = environment()
            env["K6_TARGET_IDENTITY_RECEIPT"] = raw
            transport = mock.Mock()
            self.assertEqual(run(transport, environ=env)["error"], "identity_receipt_invalid")
            transport.assert_not_called()

    def test_real_client_constructs_only_canonical_verified_https_gets_without_proxy(self) -> None:
        connections = []
        responses = [(401, b"malicious-provider-body"), (401, b""), (200, identity_body())]

        def connect(host, **kwargs):
            self.assertEqual(host, "staging.corelink.humangr.com")
            self.assertEqual(kwargs["port"], 443)
            self.assertEqual(kwargs["timeout"], 10)
            self.assertEqual(kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(kwargs["context"].check_hostname)
            status, body = responses.pop(0)
            response = mock.Mock(status=status)
            response.read.return_value = body
            connection = mock.Mock()
            connection.getresponse.return_value = response
            connections.append(connection)
            return connection

        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "https://proxy.invalid", "HTTP_PROXY": "http://proxy.invalid"}), \
                mock.patch.object(readiness.http.client, "HTTPSConnection", side_effect=connect):
            receipt = run(readiness._https_get_direct)
        self.assertTrue(receipt["success"])
        self.assertEqual(len(connections), 3)
        for connection, token in zip(connections, (None, readiness.INVALID_PAT, CURRENT)):
            headers = {"Accept": "application/json", "Connection": "close"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            connection.request.assert_called_once_with("GET", "/v1/users/me", body=None, headers=headers)
            connection.getresponse.return_value.read.assert_called_once_with(4097)
            connection.close.assert_called_once()
        self.assert_redacted(receipt)

    def test_actual_transport_redirect_timeout_and_error_body_bound_close_once(self) -> None:
        for status, body, exception, error in (
            (302, b"malicious-provider-body", None, "redirect_rejected"),
            (401, b"x" * 4097, None, "response_oversized"),
            (401, b"", TimeoutError("secret-sentinel"), "transport_timeout"),
            (401, b"", RuntimeError("secret-sentinel"), "transport_error"),
        ):
            with self.subTest(error=error):
                connection = mock.Mock()
                response = mock.Mock(status=status)
                response.read.return_value = body
                response.read.side_effect = exception
                connection.getresponse.return_value = response
                with mock.patch.object(readiness.http.client, "HTTPSConnection", return_value=connection) as connect:
                    receipt = run(readiness._https_get_direct)
                self.assertEqual(receipt["error"], error)
                connect.assert_called_once()
                connection.request.assert_called_once()
                connection.close.assert_called_once()
                self.assert_redacted(receipt)

    def assert_child_reaped_and_closed(self, process) -> None:
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                self.assertTrue(stream.closed)

    def test_child_deadline_kills_native_libc_poll_reaps_and_stops_later_arms(self) -> None:
        code = """import ctypes,json,sys
json.load(sys.stdin)
libc=ctypes.CDLL(None)
libc.poll.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_int]
libc.poll.restype=ctypes.c_int
sys.stdout.write(' ');sys.stdout.flush()
libc.poll(None,0,10000)
sys.stdout.write('{"status":401,"body":""}');sys.stdout.flush()
"""
        command = [str(Path(sys.executable).resolve()), "-B", "-S", "-c", code]
        children, native_ready = [], []
        popen, read = subprocess.Popen, os.read

        def create(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        def observe(fd, size):
            chunk = read(fd, size)
            if chunk == b" ":
                native_ready.append(True)
            return chunk

        fd_directory = "/proc/self/fd" if Path("/proc/self/fd").exists() else "/dev/fd"
        descriptors_before = len(os.listdir(fd_directory))
        started = time.monotonic()
        # Allow interpreter/ctypes startup before the required native-entry
        # marker; the production helper reserves half this budget for cleanup.
        with mock.patch.object(readiness, "TIMEOUT_SECONDS", 2), \
                mock.patch.object(readiness.subprocess, "Popen", side_effect=create), \
                mock.patch.object(readiness.os, "read", side_effect=observe):
            receipt = run(lambda token: readiness._run_get_child(token, command=command))
        elapsed = time.monotonic() - started
        diagnostic = {"elapsed": elapsed, "error": receipt["error"],
                      "returncodes": [child.returncode for child in children]}
        self.assertLess(elapsed, 2, diagnostic)
        self.assertEqual(native_ready, [True], diagnostic)
        self.assertEqual(receipt["error"], "transport_timeout", diagnostic)
        self.assertFalse(receipt["checks"]["invalid"]["attempted"])
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        self.assert_child_reaped_and_closed(children[0])
        self.assertEqual(len(os.listdir(fd_directory)), descriptors_before)
        self.assert_redacted(receipt)

    def test_child_uses_private_stdin_minimal_environment_and_fixed_argv(self) -> None:
        code = """import base64,json,os,sys
request=json.load(sys.stdin)
assert set(request)=={'token'} and isinstance(request['token'],str)
assert not any(key.startswith('K6_') or key in ('HOME','PRIVATE_SENTINEL','HTTP_PROXY','HTTPS_PROXY') for key in os.environ)
sys.stdout.write(json.dumps({'status':401,'body':base64.b64encode(b'ok').decode()}))
"""
        children, invocations = [], []
        popen = subprocess.Popen

        def create(command, **kwargs):
            invocations.append((command, kwargs))
            child = popen([str(Path(sys.executable).resolve()), "-B", "-S", "-c", code], **kwargs)
            children.append(child)
            return child

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {**environment(True), "PRIVATE_SENTINEL": CURRENT, "HTTPS_PROXY": CURRENT}), \
                mock.patch.object(readiness.subprocess, "Popen", side_effect=create), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(readiness.https_get(CURRENT), (401, b"ok"))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertEqual(len(invocations), 1)
        command, kwargs = invocations[0]
        self.assertEqual(command, readiness._child_command())
        self.assertEqual(command[1:3], ["-B", "-S"])
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertTrue(Path(command[3]).is_absolute())
        self.assertEqual(kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
        self.assertIs(kwargs["start_new_session"], True)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn(CURRENT, repr(invocations))
        self.assertNotIn(PREVIOUS, repr(invocations))
        self.assert_child_reaped_and_closed(children[0])

    def test_child_overflow_malformed_duplicate_ipc_and_crash_are_redacted_and_reaped(self) -> None:
        cases = (
            ("sys.stdout.write('x'*9000)", "response_oversized"),
            ("sys.stdout.write('malicious-provider-body')", "transport_error"),
            ("sys.stdout.write('{\"status\":401,\"status\":200,\"body\":\"\"}')", "transport_error"),
            ("sys.stdout.write('{\"status\":401,\"body\":\"\",\"extra\":true}')", "transport_error"),
            ("sys.stdout.write('{\"status\":401,\"body\":\"%%%\"}')", "transport_error"),
            ("sys.stdout.write(json.dumps({'status':401,'body':base64.b64encode(b'x'*4097).decode()}))", "response_oversized"),
            ("sys.stderr.write(str(request['token']));sys.exit(7)", "transport_error"),
        )
        for action, error in cases:
            with self.subTest(error=error):
                code = "import base64,json,sys\nrequest=json.load(sys.stdin)\n" + action
                command = [str(Path(sys.executable).resolve()), "-B", "-S", "-c", code]
                children = []
                popen = subprocess.Popen

                def create(*args, **kwargs):
                    child = popen(*args, **kwargs)
                    children.append(child)
                    return child

                with mock.patch.object(readiness.subprocess, "Popen", side_effect=create):
                    receipt = run(lambda token: readiness._run_get_child(token, command=command))
                self.assertEqual(receipt["error"], error)
                self.assertFalse(receipt["checks"]["invalid"]["attempted"])
                self.assertEqual(len(children), 1)
                self.assert_child_reaped_and_closed(children[0])
                self.assert_redacted(receipt)

    def test_real_internal_child_rejects_malformed_private_input_without_network(self) -> None:
        for payload in (b"{}", b'{"token":null,"token":null}', b'{"token":"\\r\\n"}', b"x" * 1025):
            with self.subTest(length=len(payload)):
                child = subprocess.run(readiness._child_command(), input=payload, capture_output=True,
                                       env={"LANG": "C", "LC_ALL": "C"}, timeout=2, check=False)
                self.assertEqual(child.returncode, 0)
                self.assertEqual(child.stderr, b"")
                self.assertEqual(json.loads(child.stdout), {"error": "transport_error", "status": None})

    def test_cli_atomically_writes_private_receipt_and_private_new_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "private" / "nested" / "receipt.json"
            args = ["--mode", "readiness", "--expected-release", RELEASE, "--source-sha", SOURCE,
                    "--run-id", "123", "--job-id", "456", "--output", str(output)]
            transport, _calls = scripted((401, b""), (401, b""), (200, identity_body()))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = readiness.main(args, environ=environment(), transport=transport, clock=lambda: NOW)
            self.assertEqual(result, 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(output.parent.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads(stdout.getvalue()), json.loads(output.read_text()))
            self.assert_redacted(json.loads(output.read_text()))
            output.chmod(0o644)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = readiness.main(args, environ={}, transport=mock.Mock(), clock=lambda: NOW)
            self.assertEqual(result, 1)
            self.assertFalse(json.loads(output.read_text())["success"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_cli_rejects_bad_output_or_arbitrary_url_argument_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = ["--mode", "readiness", "--expected-release", RELEASE, "--source-sha", SOURCE,
                    "--run-id", "123", "--job-id", "456", "--output", directory]
            for extra, expected in (([], "output_error"), (["--url", "https://secret-sentinel.invalid"], "invalid_arguments")):
                transport = mock.Mock()
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = readiness.main(args + extra, environ=environment(), transport=transport, clock=lambda: NOW)
                self.assertEqual(code, 1)
                transport.assert_not_called()
                self.assertEqual(json.loads(stdout.getvalue())["error"], expected)
                self.assertEqual(stderr.getvalue(), "")
                self.assert_redacted(json.loads(stdout.getvalue()))

    def test_script_entry_point_has_redacted_failure_receipt_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            env = {key: value for key, value in os.environ.items() if not key.startswith("K6_")}
            result = subprocess.run([
                sys.executable, "-B", str(Path(readiness.__file__)), "--mode", "readiness",
                "--expected-release", RELEASE, "--source-sha", SOURCE, "--run-id", "123", "--job-id", "456", "--output", str(output),
            ], env=env, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["error"], "credentials_missing")
            self.assertFalse(any(arm["attempted"] for arm in receipt["checks"].values()))
            self.assert_redacted(receipt)


if __name__ == "__main__":
    unittest.main()
