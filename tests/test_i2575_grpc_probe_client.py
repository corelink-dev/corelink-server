import os
import unittest
import time
from types import SimpleNamespace
from unittest.mock import patch

from scripts import i2575_grpc_probe_client as client


class WireContractTests(unittest.TestCase):
    def test_decodes_exact_response_with_arbitrary_binary_payload(self):
        wire = b"\x08\x02\x12\x05" + bytes.fromhex("00017f80ff")
        self.assertEqual(client.decode_response(wire), {"sequence": 2, "payload": bytes.fromhex("00017f80ff")})

    def test_rejects_empty_truncated_duplicate_and_unknown_fields(self):
        for wire in (b"", b"\x08", b"\x08\x00\x08\x01", b"\x08\x00\x12\x00\x12\x00", b"\x18\x00", b"\x12\x05\x00"):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                client.decode_response(wire)

    def test_varint_round_trip(self):
        for value in (0, 1, 127, 128, 16384, 2**32 - 1):
            encoded = client.encode_varint(value)
            self.assertEqual(client.decode_varint(encoded, 0), (value, len(encoded)))

    def test_binding_fails_closed_without_credentials_or_expiry(self):
        env = {
            "CORELINK_ENVIRONMENT": "staging", "ENVIRONMENT": "staging",
            "CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA": "a" * 40,
            "CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS": "4000000000000",
            "CORELINK_STAGING_GRPC_PROBE_WORKER_NAME": "corelink-staging",
            "CORELINK_STAGING_GRPC_PROBE_WORKER_VERSION_ID": "ver_123",
            "CORELINK_STAGING_GRPC_PROBE_CONTAINER_IMAGE_DIGEST": "sha256:" + "b" * 64,
        }
        with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError):
            client.check_binding()

    def test_binding_rejects_noncanonical_expiry(self):
        env = {
            "CORELINK_ENVIRONMENT": "staging", "ENVIRONMENT": "staging",
            "CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA": "a" * 40,
            "CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS": "0001",
            "CORELINK_STAGING_GRPC_PROBE_TOKEN": "x" * 48,
            "CORELINK_STAGING_GRPC_PROBE_WORKER_NAME": "corelink-staging",
            "CORELINK_STAGING_GRPC_PROBE_WORKER_VERSION_ID": "ver_123",
            "CORELINK_STAGING_GRPC_PROBE_CONTAINER_IMAGE_DIGEST": "sha256:" + "b" * 64,
        }
        with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError):
            client.check_binding()


    def test_alpn_requires_native_http2(self):
        client.validate_alpn("h2")
        for protocol in (None, "http/1.1", "h3"):
            with self.subTest(protocol=protocol), self.assertRaises(AssertionError):
                client.validate_alpn(protocol)

    def test_unary_and_stream_frames_require_exact_sequence_and_binary_bytes(self):
        client.validate_response({"sequence": 0, "payload": client.PAYLOAD}, 0)
        client.validate_response({"sequence": 2, "payload": client.PAYLOAD}, 2)
        for response, sequence in (({"sequence": 1, "payload": client.PAYLOAD}, 0),
                                   ({"sequence": 0, "payload": b"wrong"}, 0)):
            with self.subTest(response=response), self.assertRaises(AssertionError):
                client.validate_response(response, sequence)

    def test_response_marker_and_terminal_status_are_preserved(self):
        marker = ((client.MARKER_KEY, client.MARKER_VALUE), ("content-type", "application/grpc"))
        client.validate_marker(marker)
        with self.assertRaises(AssertionError):
            client.validate_marker(((client.MARKER_KEY, "wrong"),))
        self.assertEqual(client.validate_status(SimpleNamespace(code=lambda: SimpleNamespace(name="OK"))), "OK")
        with self.assertRaises(AssertionError):
            client.validate_status(SimpleNamespace(code=lambda: SimpleNamespace(name="UNAVAILABLE")))

    def test_cancellation_and_negative_statuses_must_be_terminal(self):
        client.validate_cancel_status(SimpleNamespace(code=lambda: SimpleNamespace(name="CANCELLED")))
        with self.assertRaises(AssertionError):
            client.validate_cancel_status(SimpleNamespace(code=lambda: None))
        self.assertEqual(client.validate_denied_status("UNAUTHENTICATED"), "UNAUTHENTICATED")
        for status in (None, "OK", "UNKNOWN"):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                client.validate_denied_status(status)

    def test_binding_rejects_wrong_target_even_with_valid_other_bindings(self):
        env = {
            "CORELINK_ENVIRONMENT": "staging", "ENVIRONMENT": "staging",
            "CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA": "a" * 40,
            "CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS": str(int(time.time() * 1000) + 300_000),
            "CORELINK_STAGING_GRPC_PROBE_TOKEN": "x" * 48,
            "CORELINK_STAGING_GRPC_PROBE_WORKER_NAME": "other-worker",
            "CORELINK_STAGING_GRPC_PROBE_WORKER_VERSION_ID": "ver_123",
            "CORELINK_STAGING_GRPC_PROBE_CONTAINER_IMAGE_DIGEST": "sha256:" + "b" * 64,
        }
        with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError):
            client.check_binding()


if __name__ == "__main__":
    unittest.main()
