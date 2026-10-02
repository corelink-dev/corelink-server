#!/usr/bin/env python3
"""Bounded standard gRPC client for protected staging issue #2575 proof.

This program makes no cache/service writes. It emits only a redacted receipt;
never include credentials, request bytes, raw metadata values, or response bytes.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HOST = "staging.corelink.humangr.com"
PORT = 443
BASE = "/corelink.staging.v1.TransportProbe/"
PAYLOAD = bytes.fromhex("00017f80ff")
MARKER_KEY = "x-corelink-staging-probe"
MARKER_VALUE = "v1"


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative protobuf integer")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift <= 63:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ValueError("malformed protobuf varint")


def decode_response(data: bytes) -> dict[str, Any]:
    """Strictly decode the two-field response and reject unknown/duplicate fields."""
    result: dict[str, Any] = {}
    offset = 0
    while offset < len(data):
        key, offset = decode_varint(data, offset)
        field, wire = key >> 3, key & 7
        result_key = {1: "sequence", 2: "payload"}.get(field)
        if result_key is None or result_key in result:
            raise ValueError("unknown or duplicate protobuf response field")
        if field == 1 and wire == 0:
            result["sequence"], offset = decode_varint(data, offset)
        elif field == 2 and wire == 2:
            length, offset = decode_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ValueError("truncated protobuf bytes field")
            result["payload"] = data[offset:end]
            offset = end
        else:
            raise ValueError("unexpected protobuf response field")
    if set(result) != {"sequence", "payload"}:
        raise ValueError("incomplete protobuf response")
    return result


def metadata_value(metadata: Any, key: str) -> str | None:
    for item_key, value in metadata or ():
        if item_key.lower() == key:
            return value.decode("ascii", "strict") if isinstance(value, bytes) else str(value)
    return None


def check_binding() -> dict[str, str]:
    expected = os.environ.get("CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA", "")
    expires = os.environ.get("CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS", "")
    token = os.environ.get("CORELINK_STAGING_GRPC_PROBE_TOKEN", "")
    worker = os.environ.get("CORELINK_STAGING_GRPC_PROBE_WORKER_NAME", "")
    worker_version = os.environ.get("CORELINK_STAGING_GRPC_PROBE_WORKER_VERSION_ID", "")
    image = os.environ.get("CORELINK_STAGING_GRPC_PROBE_CONTAINER_IMAGE_DIGEST", "")
    if os.environ.get("CORELINK_ENVIRONMENT") != "staging" or os.environ.get("ENVIRONMENT") != "staging":
        raise RuntimeError("staging environment bindings are absent or inconsistent")
    if worker != "corelink-staging":
        raise RuntimeError("protected Worker binding does not name the canonical staging Worker")
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise RuntimeError("deployment SHA binding is malformed")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", worker_version):
        raise RuntimeError("Worker version binding is malformed")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise RuntimeError("Container image digest binding is malformed")
    if not expires.isascii() or not expires.isdecimal() or str(int(expires)) != expires:
        raise RuntimeError("expiry binding is not a canonical integer")
    now = int(time.time() * 1000)
    expiry = int(expires)
    if not now < expiry <= now + 900_000:
        raise RuntimeError("probe credential is expired or outside its allowed lifetime")
    if len(token.encode("utf-8")) < 32:
        raise RuntimeError("probe credential is absent or too short")
    return {"deployment_sha": expected, "worker": worker, "worker_version_id": worker_version,
            "image_digest": image, "token": token, "expires_at_ms": expires}


def validate_alpn(protocol: str | None) -> None:
    if protocol != "h2":
        raise AssertionError("canonical endpoint did not negotiate HTTP/2 via ALPN")


def validate_response(response: Any, sequence: int) -> None:
    if response != {"sequence": sequence, "payload": PAYLOAD}:
        raise AssertionError("gRPC response did not match the frozen sequence and bytes")


def validate_marker(metadata: Any) -> None:
    if metadata_value(metadata, MARKER_KEY) != MARKER_VALUE:
        raise AssertionError("gRPC response metadata marker was absent or incorrect")


def validate_status(call: Any) -> str:
    code = call.code()
    if code is None or code.name != "OK":
        raise AssertionError("terminal gRPC status was not OK")
    return code.name


def validate_cancel_status(call: Any) -> None:
    code = call.code()
    if code is None or code.name != "CANCELLED":
        raise AssertionError("server did not observe client cancellation as CANCELLED")


def validate_denied_status(name: str | None) -> str:
    if not name or name == "OK" or name == "UNKNOWN":
        raise AssertionError("negative RPC did not complete with a non-OK gRPC status")
    return name


def grpc_status(call: Any) -> str:
    code = call.code()
    return code.name if code is not None else "UNKNOWN"


def expect_denied(call: Any, label: str) -> str:
    import grpc
    try:
        call.result(timeout=8)
    except grpc.FutureTimeoutError as exc:
        raise AssertionError(f"{label} did not complete within its deadline") from exc
    except grpc.RpcError:
        pass
    else:
        raise AssertionError(f"{label} unexpectedly returned a successful response")
    try:
        return validate_denied_status(call.code().name if call.code() is not None else None)
    except AssertionError as exc:
        raise AssertionError(f"{label} had no completed non-OK gRPC status") from exc


def tls_client_context(alpn: str) -> ssl.SSLContext:
    """Return a verified client context that never negotiates below TLS 1.2."""
    context = ssl.create_default_context()
    # Pin the floor here instead of inheriting it from the interpreter or the
    # OpenSSL build, so TLS 1.0/1.1 are refused even where they are allowed.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols([alpn])
    return context


def http_shape_probe(context: ssl.SSLContext, path: str, content_type: str, *, alpn: str) -> dict[str, Any]:
    conn = http.client.HTTPSConnection(HOST, PORT, context=context, timeout=8)
    try:
        conn.request("POST", path, body=b"", headers={"content-type": content_type, "te": "trailers"})
        response = conn.getresponse()
        status = response.status
        response_type = response.getheader("content-type", "").lower()
        location = response.getheader("location")
        if 300 <= status < 400 or location:
            raise AssertionError(f"{alpn} request was redirected")
        if 200 <= status < 300:
            raise AssertionError(f"{alpn} request was accepted")
        return {"status": status, "content_type": response_type or None, "denied": True}
    finally:
        conn.close()


def run() -> dict[str, Any]:
    binding = check_binding()
    started = dt.datetime.now(dt.timezone.utc)
    now = int(time.time() * 1000)
    receipt: dict[str, Any] = {
        "issue": 2575,
        "endpoint": f"https://{HOST}:{PORT}",
        "deployment_sha": binding["deployment_sha"],
        "worker": binding["worker"],
        "worker_version_id": binding["worker_version_id"],
        "image_digest": binding["image_digest"],
        "client": "grpcio",
        "started_at_utc": started.isoformat(),
        "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "payload_length": len(PAYLOAD),
    }
    h2_context = tls_client_context("h2")
    http1_context = tls_client_context("http/1.1")
    with socket.create_connection((HOST, PORT), timeout=8) as raw:
        with h2_context.wrap_socket(raw, server_hostname=HOST) as tls:
            validate_alpn(tls.selected_alpn_protocol())
            cert = tls.getpeercert(binary_form=True)
            receipt["tls"] = {"verified": True, "alpn": "h2", "peer_certificate_sha256": hashlib.sha256(cert).hexdigest()}

    import grpc
    options = (("grpc.enable_retries", 0), ("grpc.max_receive_message_length", 65536), ("grpc.max_send_message_length", 1024))
    channel = grpc.secure_channel(f"{HOST}:{PORT}", grpc.ssl_channel_credentials(), options=options)
    try:
        grpc.channel_ready_future(channel).result(timeout=10)
        md = (("authorization", f"Bearer {binding['token']}"),)
        unary = channel.unary_unary(BASE + "Unary", request_serializer=lambda _request: b"", response_deserializer=decode_response)
        response, call = unary.with_call(object(), metadata=md, timeout=8, wait_for_ready=False)
        validate_response(response, 0)
        validate_status(call)
        initial = call.initial_metadata()
        trailers = call.trailing_metadata()
        validate_marker(initial)
        receipt["unary"] = {"sequence": 0, "status": grpc_status(call), "initial_marker": MARKER_VALUE,
                            "trailer_names": sorted(k.lower() for k, _ in (trailers or ())) }

        stream_rpc = channel.unary_stream(BASE + "Stream", request_serializer=lambda _request: b"", response_deserializer=decode_response)
        stream_call = stream_rpc(object(), metadata=md, timeout=10, wait_for_ready=False)
        frames = list(stream_call)
        if frames != [{"sequence": n, "payload": PAYLOAD} for n in range(3)]:
            raise AssertionError("stream did not return exactly the three frozen frames")
        validate_status(stream_call)
        stream_initial = stream_call.initial_metadata()
        stream_trailers = stream_call.trailing_metadata()
        validate_marker(stream_initial)
        receipt["stream"] = {"sequences": [0, 1, 2], "status": grpc_status(stream_call),
                             "initial_marker": MARKER_VALUE, "trailer_names": sorted(k.lower() for k, _ in (stream_trailers or ())) }

        cancel_call = stream_rpc(object(), metadata=md, timeout=10, wait_for_ready=False)
        iterator = iter(cancel_call)
        first = next(iterator, None)
        if first != {"sequence": 0, "payload": PAYLOAD}:
            raise AssertionError("cancellation stream did not begin with the frozen first frame")
        if not cancel_call.cancel():
            raise AssertionError("client cancellation was not accepted")
        deadline = time.monotonic() + 3
        while cancel_call.code() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        validate_cancel_status(cancel_call)
        receipt["cancellation"] = {"first_sequence": 0, "client_cancelled": True, "status": "CANCELLED"}

        wrong = channel.unary_unary(BASE + "Unary", request_serializer=lambda _request: b"", response_deserializer=decode_response)
        wrong_call = wrong.future(object(), metadata=(("authorization", "Bearer " + "0" * 48),), timeout=8, wait_for_ready=False)
        missing_call = wrong.future(object(), timeout=8, wait_for_ready=False)
        receipt["negative"] = {
            "wrong_authorization": expect_denied(wrong_call, "wrong authorization"),
            "missing_authorization": expect_denied(missing_call, "missing authorization"),
        }
        unsupported = channel.unary_unary(BASE + "Unsupported", request_serializer=lambda _request: b"", response_deserializer=decode_response)
        unsupported_call = unsupported.future(object(), metadata=md, timeout=8, wait_for_ready=False)
        receipt["negative"]["unsupported_method"] = expect_denied(unsupported_call, "unsupported method")
    finally:
        channel.close()

    receipt["negative"]["http1_grpc"] = http_shape_probe(http1_context, BASE + "Unary", "application/grpc", alpn="HTTP/1.1")
    receipt["negative"]["grpc_web"] = http_shape_probe(http1_context, BASE + "Unary", "application/grpc-web+proto", alpn="gRPC-Web over HTTP/1.1")
    receipt["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    receipt["elapsed_ms"] = int(time.time() * 1000) - now
    return receipt


def main() -> int:
    try:
        receipt = run()
        output = Path(os.environ.get("GITHUB_STEP_SUMMARY", "/dev/stdout"))
        summary = "## #2575 staging gRPC diagnostic\n\n```json\n" + json.dumps(receipt, sort_keys=True, indent=2) + "\n```\n"
        with output.open("a", encoding="utf-8") as stream:
            stream.write(summary)
        receipt_file = os.environ.get("I2575_RECEIPT_PATH")
        if receipt_file:
            Path(receipt_file).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return 0
    except Exception as exc:
        # Error classes only: exceptions can contain metadata or provider text.
        print(f"#2575 probe failed: {type(exc).__name__}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
