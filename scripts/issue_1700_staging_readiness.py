#!/usr/bin/env python3
"""Bounded GET-only staging identity checks; receipts contain no private identity."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import http.client
import json
import os
import re
import selectors
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Mapping

try:
    from . import validate_load_target_receipt as identity_receipt
except ImportError:  # Script entry point.
    import validate_load_target_receipt as identity_receipt


CONTRACT = "issue-1700-staging-readiness-v1"
HOST = "staging.corelink.humangr.com"
PATH = "/v1/users/me"
ORIGIN = f"https://{HOST}"
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 4096
MAX_RECEIPT_BYTES = 8192
MAX_CHILD_INPUT_BYTES = 1024
MAX_CHILD_OUTPUT_BYTES = 8192
CHILD_FLAG = "--_readiness-get-child"
INVALID_PAT = "issue-1700-intentionally-invalid-pat"
MODES = frozenset(("readiness", "rotation", "teardown"))
SHA_RE = re.compile(r"[0-9a-f]{40}")
ID_RE = re.compile(r"[1-9][0-9]{0,19}")
ERRORS = frozenset((
    "invalid_arguments", "credentials_missing", "credentials_malformed",
    "rotation_credentials_equal", "identity_receipt_invalid",
    "identity_release_mismatch", "identity_issued_in_future", "transport_timeout",
    "transport_error", "response_oversized", "redirect_rejected",
    "unexpected_http_status", "identity_response_invalid", "identity_tenant_mismatch",
    "identity_route_mismatch", "identity_token_prefix_invalid", "output_error",
))
Transport = Callable[[str | None], tuple[int, bytes]]
Clock = Callable[[], dt.datetime]


class ProbeError(ValueError):
    def __init__(self, code: str, status: int | None = None):
        self.code = code if code in ERRORS else "transport_error"
        self.status = status if type(status) is int and 100 <= status <= 599 else None
        super().__init__(self.code)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("invalid_json_constant")


def _json(raw: bytes | str) -> object:
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)


def _matches(pattern: re.Pattern, value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _token(value: object) -> str:
    if value in (None, ""):
        raise ProbeError("credentials_missing")
    if not isinstance(value, str) or len(value) > 256 or any(not 0x21 <= ord(char) <= 0x7E for char in value):
        raise ProbeError("credentials_malformed")
    return value


def _inputs(mode: str, expected_release: str, source_sha: str, run_id: str, job_id: str,
            environ: Mapping[str, str], now: dt.datetime) -> tuple[str, str, str | None]:
    if (mode not in MODES or not _matches(SHA_RE, expected_release) or
            not _matches(SHA_RE, source_sha) or not _matches(ID_RE, run_id) or not _matches(ID_RE, job_id)):
        raise ProbeError("invalid_arguments")
    current = _token(environ.get("K6_STAGING_PAT"))
    previous_raw = environ.get("K6_STAGING_PREVIOUS_PAT")
    previous = _token(previous_raw) if previous_raw not in (None, "") else None
    if mode == "rotation":
        if previous is None:
            raise ProbeError("credentials_missing")
        if current == previous:
            raise ProbeError("rotation_credentials_equal")
    raw = environ.get("K6_TARGET_IDENTITY_RECEIPT", "")
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_RECEIPT_BYTES:
            raise ValueError("receipt_bound")
        parsed = _json(raw)
        if not isinstance(parsed, dict) or type(parsed.get("schema")) is not int:
            raise ValueError("receipt_schema")
        private = identity_receipt.validate(parsed, ORIGIN, now=now)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ProbeError("identity_receipt_invalid") from None
    if private["deployment_sha"] != expected_release:
        raise ProbeError("identity_release_mismatch")
    if identity_receipt._timestamp(private["issued_at"], "issued_at") > now:
        raise ProbeError("identity_issued_in_future")
    return str(private["tenant_id"]), current, previous


def _https_get_direct(token: str | None) -> tuple[int, bytes]:
    """Child-only fixed GET; the parent bounds even blocking native resolver I/O."""
    connection = None
    response = None
    status = None
    try:
        connection = http.client.HTTPSConnection(
            HOST, port=443, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context(),
        )
        headers = {"Accept": "application/json", "Connection": "close"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        connection.request("GET", PATH, body=None, headers=headers)
        response = connection.getresponse()
        status = response.status
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProbeError("response_oversized", status)
        return status, body
    except ProbeError:
        raise
    except TimeoutError:
        raise ProbeError("transport_timeout", status) from None
    except Exception:
        raise ProbeError("transport_error", status) from None
    finally:
        # A Connection: close response can own its socket after http.client has
        # detached it from the connection. Close both handles on interruption.
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _child_command() -> list[str]:
    return [str(Path(sys.executable).resolve()), "-B", "-S", str(Path(__file__).resolve()), CHILD_FLAG]


def _child_main() -> int:
    """Private pipe protocol only; never the public CLI receipt/output path."""
    result = {"error": "transport_error", "status": None}
    try:
        raw = sys.stdin.buffer.read(MAX_CHILD_INPUT_BYTES + 1)
        if len(raw) > MAX_CHILD_INPUT_BYTES:
            raise ProbeError("transport_error")
        request = _json(raw)
        if not isinstance(request, dict) or set(request) != {"token"}:
            raise ProbeError("transport_error")
        token = request["token"]
        if token is not None:
            token = _token(token)
        status, body = _https_get_direct(token)
        result = {"status": status, "body": base64.b64encode(body).decode("ascii")}
    except ProbeError as error:
        code = error.code if error.code in ("transport_timeout", "response_oversized") else "transport_error"
        result = {"error": code, "status": error.status}
    except Exception:
        pass
    sys.stdout.buffer.write(json.dumps(result, separators=(",", ":")).encode("ascii"))
    sys.stdout.buffer.flush()
    return 0


def _decode_child(raw: bytes) -> tuple[int, bytes]:
    try:
        result = _json(raw)
        if not isinstance(result, dict):
            raise ValueError("ipc_shape")
        status = result.get("status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError("ipc_status")
        if set(result) == {"error", "status"} and result["error"] in (
                "transport_timeout", "transport_error", "response_oversized"):
            raise ProbeError(result["error"], status)
        if set(result) != {"status", "body"} or status is None or not isinstance(result["body"], str):
            raise ValueError("ipc_shape")
        body = base64.b64decode(result["body"], validate=True)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProbeError("response_oversized", status)
        return status, body
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("transport_error") from None


def _close_child(process: subprocess.Popen, abort: bool, deadline: float) -> None:
    try:
        if abort or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        raise ProbeError("transport_timeout") from None
    except Exception:
        raise ProbeError("transport_error") from None
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _run_get_child(token: str | None, *, command: list[str] | None = None) -> tuple[int, bytes]:
    """One total deadline for child creation, private stdin, stdout and cleanup.

    The command seam is for credentialless local tests, never a CLI option.
    Killing the dedicated process group also stops native calls that defer
    Python signal handlers. No thread or child may continue to the next arm.
    """
    if token is not None:
        _token(token)
    payload = json.dumps({"token": token}, separators=(",", ":")).encode("ascii")
    if len(payload) > MAX_CHILD_INPUT_BYTES:
        raise ProbeError("transport_error")
    total_deadline = time.monotonic() + TIMEOUT_SECONDS
    # Reserve cleanup inside the same total budget, including shortened tests.
    # Production allows nine seconds for the GET and one for kill/reap.
    deadline = total_deadline - min(1.0, TIMEOUT_SECONDS / 2)
    process = None
    selector = selectors.DefaultSelector()
    abort = True
    try:
        process = subprocess.Popen(
            _child_command() if command is None else command,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, env={"LANG": "C", "LC_ALL": "C"},
        )
        for stream, event in ((process.stdin, selectors.EVENT_WRITE), (process.stdout, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        written = 0
        output = bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("transport_timeout")
            for key, _events in selector.select(remaining):
                if time.monotonic() >= deadline:
                    raise ProbeError("transport_timeout")
                if key.fileobj is process.stdin:
                    written += os.write(key.fd, payload[written:])
                    if written == len(payload):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    chunk = os.read(key.fd, min(4096, MAX_CHILD_OUTPUT_BYTES + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_CHILD_OUTPUT_BYTES:
                            raise ProbeError("response_oversized")
        if process.wait(timeout=max(0, deadline - time.monotonic())) != 0:
            raise ProbeError("transport_error")
        if time.monotonic() >= deadline:
            raise ProbeError("transport_timeout")
        result = _decode_child(bytes(output))
        if time.monotonic() >= deadline:
            raise ProbeError("transport_timeout")
        abort = False
        return result
    except ProbeError:
        raise
    except (TimeoutError, subprocess.TimeoutExpired):
        raise ProbeError("transport_timeout") from None
    except Exception:
        raise ProbeError("transport_error") from None
    finally:
        selector.close()
        if process is not None:
            _close_child(process, abort, total_deadline)


def https_get(token: str | None) -> tuple[int, bytes]:
    return _run_get_child(token)


def _identity_body(body: bytes, tenant: str) -> None:
    try:
        result = _json(body)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ProbeError("identity_response_invalid") from None
    if not isinstance(result, dict) or set(result) != {"tenant_id", "token_prefix", "route_kind"}:
        raise ProbeError("identity_response_invalid")
    if result["tenant_id"] != tenant:
        raise ProbeError("identity_tenant_mismatch")
    if result["route_kind"] != "reapi_v1":
        raise ProbeError("identity_route_mismatch")
    prefix = result["token_prefix"]
    if (not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", prefix)
            or prefix.casefold() in ("_unknown", "clerk")):
        raise ProbeError("identity_token_prefix_invalid")


def _receipt(mode: str | None, expected_release: str | None, source_sha: str | None,
             run_id: str | None, job_id: str | None, now: dt.datetime) -> dict:
    return {
        "contract": CONTRACT, "mode": mode if mode in MODES else None,
        "source_sha": source_sha if _matches(SHA_RE, source_sha) else None,
        "deployment_release": expected_release if _matches(SHA_RE, expected_release) else None,
        "release_attribution": "protected_identity_receipt",
        "run_id": run_id if _matches(ID_RE, run_id) else None,
        "job_id": job_id if _matches(ID_RE, job_id) else None,
        "identity_receipt_valid": False, "previous_bound": False,
        "checks": {arm: {"attempted": False, "http_status": None, "expected_status": None, "passed": False}
                   for arm in ("missing", "invalid", "current", "previous")},
        "success": False, "error": "invalid_arguments",
        "completed_at": now.astimezone(dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def run_checks(*, mode: str, expected_release: str, source_sha: str, run_id: str, job_id: str,
               environ: Mapping[str, str] | None = None, transport: Transport | None = None,
               clock: Clock | None = None) -> dict:
    clock = clock or (lambda: dt.datetime.now(dt.UTC))
    receipt = _receipt(mode, expected_release, source_sha, run_id, job_id, clock())
    active = None
    try:
        tenant, current, previous = _inputs(
            mode, expected_release, source_sha, run_id, job_id,
            os.environ if environ is None else environ, clock(),
        )
        receipt["identity_receipt_valid"] = True
        receipt["previous_bound"] = previous is not None
        arms = [("missing", None, 401), ("invalid", INVALID_PAT, 401),
                ("current", current, 401 if mode == "teardown" else 200)]
        if mode == "rotation" or (mode == "teardown" and previous is not None):
            arms.append(("previous", previous, 401))
        for name, _token_value, expected in arms:
            receipt["checks"][name]["expected_status"] = expected
        for name, token, expected in arms:
            active = receipt["checks"][name]
            active["attempted"] = True
            status, body = (transport or https_get)(token)
            if type(status) is not int or not 100 <= status <= 599 or not isinstance(body, bytes):
                raise ProbeError("transport_error")
            active["http_status"] = status
            if len(body) > MAX_RESPONSE_BYTES:
                raise ProbeError("response_oversized")
            if 300 <= status <= 399:
                raise ProbeError("redirect_rejected")
            if status != expected:
                raise ProbeError("unexpected_http_status")
            if expected == 200:
                _identity_body(body, tenant)
            active["passed"] = True
        receipt["success"] = True
        receipt["error"] = "none"
    except ProbeError as error:
        receipt["error"] = error.code
        if active is not None and error.status is not None:
            active["http_status"] = error.status
    except TimeoutError:
        receipt["error"] = "transport_timeout"
    except Exception:
        receipt["error"] = "transport_error"
    receipt["completed_at"] = clock().astimezone(dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return receipt


def write_receipt(output: Path, receipt: dict) -> None:
    missing = []
    parent = output.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".staging-readiness-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(receipt, sort_keys=True) + "\n")
        os.replace(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ProbeError("invalid_arguments")


def main(argv: list[str] | None = None, *, environ: Mapping[str, str] | None = None,
         transport: Transport | None = None, clock: Clock | None = None) -> int:
    clock = clock or (lambda: dt.datetime.now(dt.UTC))
    receipt = _receipt(None, None, None, None, None, clock())
    output = None
    try:
        parser = _Parser(description=__doc__, allow_abbrev=False)
        for name in ("mode", "expected-release", "run-id", "job-id", "source-sha"):
            parser.add_argument(f"--{name}", required=True)
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args(argv)
        output = args.output
        receipt = _receipt(args.mode, args.expected_release, args.source_sha, args.run_id, args.job_id, clock())
        # Establish a private, writable failure artifact before any network call.
        write_receipt(output, receipt)
        receipt = run_checks(mode=args.mode, expected_release=args.expected_release, source_sha=args.source_sha,
                             run_id=args.run_id, job_id=args.job_id, environ=environ, transport=transport, clock=clock)
    except ProbeError as error:
        receipt["error"] = error.code
    except (OSError, ValueError):
        receipt["error"] = "output_error"
    if output is not None:
        try:
            write_receipt(output, receipt)
        except (OSError, ValueError):
            receipt["success"] = False
            receipt["error"] = "output_error"
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["success"] else 1


if __name__ == "__main__":
    raise SystemExit(_child_main() if sys.argv[1:] == [CHILD_FLAG] else main())
