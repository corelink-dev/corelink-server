#!/usr/bin/env python3
"""Capture a bounded, read-only TLS handshake matrix for B-035 ingress sources.

The probe reads Cloudflare's zone setting once through the existing verifier,
then performs TLS handshakes only. It sends no HTTP request and has no write
path. A handshake proves TLS negotiation for that client runtime and hostname;
it does not prove application authentication or a cache operation.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import verify_b035_tls_surfaces as b035


ROOT = Path(__file__).resolve().parents[1]
TLS_VERSIONS = (("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3))
TIMEOUT_SECONDS = 5


def _hostname(surface: dict[str, Any]) -> str | None:
    token = str(surface["hostname"]).split("/", 1)[0]
    if "<" in token or ">" in token or "*" in token:
        return None
    return token


def _python_handshake(hostname: str, label: str, version: ssl.TLSVersion) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.minimum_version = version
    context.maximum_version = version
    try:
        with socket.create_connection((hostname, 443), timeout=TIMEOUT_SECONDS) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                cipher = tls.cipher()
                return {
                    "client": f"Python ssl ({ssl.OPENSSL_VERSION})",
                    "requested": label,
                    "status": "success" if tls.version() == label else "unexpected_protocol",
                    "negotiated": tls.version(),
                    "cipher_observed": cipher[0] if cipher else None,
                    "certificate_verified": True,
                }
    except socket.timeout:
        return {"client": f"Python ssl ({ssl.OPENSSL_VERSION})", "requested": label, "status": "timeout"}
    except socket.gaierror:
        return {"client": f"Python ssl ({ssl.OPENSSL_VERSION})", "requested": label, "status": "dns_error"}
    except ssl.SSLCertVerificationError as exc:
        return {
            "client": f"Python ssl ({ssl.OPENSSL_VERSION})",
            "requested": label,
            "status": "certificate_error",
            "error": exc.verify_message[:240],
        }
    except ssl.SSLError as exc:
        return {
            "client": f"Python ssl ({ssl.OPENSSL_VERSION})",
            "requested": label,
            "status": "tls_error",
            "error": str(exc)[:240],
        }
    except OSError as exc:
        return {
            "client": f"Python ssl ({ssl.OPENSSL_VERSION})",
            "requested": label,
            "status": "connect_error",
            "error": type(exc).__name__,
        }


def _securetransport_handshake(hostname: str, label: str) -> dict[str, Any]:
    curl = Path("/usr/bin/curl")
    if platform.system() != "Darwin" or not curl.exists():
        return {"client": "Apple system curl", "requested": label, "status": "not_available"}

    version = subprocess.run(
        [str(curl), "--version"], capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
    )
    first_line = version.stdout.splitlines()[0] if version.stdout.splitlines() else ""
    backend_line = version.stdout.splitlines()[1] if len(version.stdout.splitlines()) > 1 else ""
    client = f"Apple system curl ({backend_line.strip() or first_line.strip()})"
    if "SecureTransport" not in version.stdout:
        return {"client": client, "requested": label, "status": "securetransport_backend_not_confirmed"}

    version_flag = "--tlsv1.2" if label == "TLSv1.2" else "--tlsv1.3"
    max_version = "1.2" if label == "TLSv1.2" else "1.3"
    try:
        result = subprocess.run(
            [
                str(curl), "--connect-only", "--silent", "--show-error", "--verbose",
                "--max-time", str(TIMEOUT_SECONDS), version_flag, "--tls-max", max_version,
                f"https://{hostname}/",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS + 2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"client": client, "requested": label, "status": "timeout", "application_data_sent": False}
    match = re.search(r"SSL connection using ([^\r\n]+)", result.stderr)
    if result.returncode == 0 and match:
        return {
            "client": client,
            "requested": label,
            "status": "success",
            "negotiated": match.group(1).split(" / ", 1)[0],
            "certificate_verified": True,
            "application_data_sent": False,
        }
    return {
        "client": client,
        "requested": label,
        "status": "handshake_error",
        "error": (result.stderr.strip().splitlines()[-1][:240] if result.stderr.strip() else f"exit_{result.returncode}"),
        "application_data_sent": False,
    }


def build_report(*, live: bool, revision: str | None) -> dict[str, Any]:
    inventory = b035.inventory(ROOT)
    source_validation = inventory["external_surface"]["source_validation"]
    source_validation_ok = source_validation.get("status") == "all_markers_match"
    report: dict[str, Any] = {
        "issue": 2163,
        "backlog_id": "B-035",
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_revision": revision or os.environ.get("GITHUB_SHA") or "unknown",
        "hosted_runner": {
            "os": platform.platform(),
            "python_tls_runtime": ssl.OPENSSL_VERSION,
        },
        "zone": b035.ZONE_NAME,
        "zone_id_redacted": f"{b035.ZONE_ID[:8]}…{b035.ZONE_ID[-4:]}",
        "zone_floor": {"status": "not_requested"},
        "legal_claims": inventory["instruments"],
        "source_validation": source_validation,
        "handshake_probe_status": "ready" if source_validation_ok else "blocked_source_validation",
        "handshake_scope": "TLS negotiation only; no HTTP request, authentication attempt, cache read/write, or application contract test",
        "ingress": [],
        "templated_ingress": [],
        "client_compatibility": [
            {
                "client": "sccache (macOS native-tls/SecureTransport)",
                "version_in_source": "sccache >= 0.15; exact production binary version unavailable",
                "source": "specs/03_architecture/adrs/ADR-0072-humangr-zone-min-tls-1.2.md; apps/docs/docs/integrations/sccache-cargo.md",
                "endpoint_source": "https://corelink-api.humangr.com/cargo/<tenant> in apps/docs/docs/integrations/sccache-cargo.md",
                "probe": "Apple SecureTransport handshake to source-bound corelink-api hostname when the runner curl backend identifies SecureTransport; not an sccache operation",
                "historic_source_result": "ADR-0072 records a TLS-1.3-only floor rejected the macOS SecureTransport client; the zone was lowered to 1.2",
                "status": "historical_tls_1_3_only_incompatibility_recorded; current application operation not exercised",
            },
            {
                "client": "Bazel REAPI",
                "source": "apps/docs/docs/integrations/bazel.md",
                "version_in_source": "stock Bazel; exact version unavailable",
                "endpoint_source": "https://corelink-api.humangr.com/bazel/v2/<tenant>/…",
                "probe": "host TLS negotiation only; no REAPI request, PAT, or Bazel binary invocation",
                "status": "application_compatibility_not_exercised",
            },
            {
                "client": "Turborepo",
                "source": "apps/docs/docs/integrations/turborepo.md",
                "version_in_source": "not pinned in source",
                "endpoint_source": "https://corelink-api.humangr.com (TURBO_API)",
                "probe": "host TLS negotiation only; no cache request, PAT, or Turborepo binary invocation",
                "status": "application_compatibility_not_exercised",
            },
        ],
        "cipher_boundary": "Observed negotiated cipher names are per-handshake facts only; no Cloudflare cipher-suite policy is claimed or verified.",
        "mutation": False,
    }

    token, token_source = b035._token()
    report["credential"] = {"available": bool(token), "source": token_source}
    if live:
        report["zone_floor"] = b035.read_live_floor(token) if token else {"status": "credential_unavailable"}

    grouped: dict[str, list[dict[str, Any]]] = {}
    for surface in b035.NAMED_SURFACES:
        if surface["kind"] != "ingress":
            continue
        hostname = _hostname(surface)
        if hostname is None:
            report["templated_ingress"].append(
                {"name": surface["name"], "hostname": surface["hostname"], "source": surface["source"], "status": "not_a_concrete_hostname"}
            )
            continue
        grouped.setdefault(hostname, []).append(surface)

    for hostname, surfaces in sorted(grouped.items()):
        entry = {
            "hostname": hostname,
            "sources": [{"name": s["name"], "source": s["source"], "declared_status": s["status"]} for s in surfaces],
            "handshake_status": "probed" if live and source_validation_ok else (
                "skipped_source_validation" if live else "inventory_only"
            ),
            "python_tls": (
                [_python_handshake(hostname, label, version) for label, version in TLS_VERSIONS]
                if live and source_validation_ok
                else []
            ),
        }
        if live and source_validation_ok and hostname == "corelink-api.humangr.com":
            entry["securetransport_tls"] = [_securetransport_handshake(hostname, label) for label, _ in TLS_VERSIONS]
        report["ingress"].append(entry)

    report["handshake_summary"] = {
        "unique_concrete_ingress_hostnames": len(report["ingress"]),
        "source_bound_ingress_rows": sum(len(row["sources"]) for row in report["ingress"]),
        "successful_python_handshakes": sum(
            handshake["status"] == "success" for row in report["ingress"] for handshake in row["python_tls"]
        ),
        "python_handshake_attempts": sum(len(row["python_tls"]) for row in report["ingress"]),
        "securetransport_probe_rows": sum(len(row.get("securetransport_tls", [])) for row in report["ingress"]),
        "templated_ingress_not_probeable": len(report["templated_ingress"]),
    }
    report["claim_surface_mapping"] = {
        "method": "The eight legal claims name no hostnames. Each is evaluated against the complete source-bound ingress inventory in this report.",
        "claim_paths": [claim["path"] for claim in report["legal_claims"]],
        "source_bound_ingress_names": sorted(
            {source["name"] for row in report["ingress"] for source in row["sources"]}
            | {row["name"] for row in report["templated_ingress"]}
        ),
        "concrete_hostnames": [row["hostname"] for row in report["ingress"]],
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="read Cloudflare setting and perform bounded handshakes")
    parser.add_argument("--revision", help="exact source revision for the receipt")
    parser.add_argument("--inventory-only", action="store_true", help="validate source inventory without network access")
    args = parser.parse_args()
    if args.live and args.inventory_only:
        parser.error("--live and --inventory-only are mutually exclusive")
    report = build_report(live=args.live, revision=args.revision)
    if args.inventory_only:
        summary = {
            "instrument_count": len(report["legal_claims"]),
            "instrument_claims_match": all(
                claim["claim_count"] == 1 and claim["claim_matches_expected"]
                for claim in report["legal_claims"]
            ),
            "source_validation": report["source_validation"]["status"],
            "source_validation_errors": report["source_validation"]["errors"],
            "source_bound_ingress_rows": report["handshake_summary"]["source_bound_ingress_rows"],
            "concrete_hostnames": report["handshake_summary"]["unique_concrete_ingress_hostnames"],
            "templated_ingress_not_probeable": report["handshake_summary"]["templated_ingress_not_probeable"],
            "network_attempts": report["handshake_summary"]["python_handshake_attempts"]
            + report["handshake_summary"]["securetransport_probe_rows"],
            "mutation": report["mutation"],
        }
        print(json.dumps(summary, sort_keys=True))
        return 0 if (
            summary["instrument_count"] == 8
            and summary["instrument_claims_match"]
            and summary["source_validation"] == "all_markers_match"
            and not summary["source_validation_errors"]
            and summary["source_bound_ingress_rows"] == 15
            and summary["concrete_hostnames"] == 12
            and summary["templated_ingress_not_probeable"] == 1
            and summary["network_attempts"] == 0
        ) else 1
    print(json.dumps(report, indent=2, sort_keys=True))
    if not args.live:
        return 0
    return 0 if (
        report["zone_floor"].get("status") in {"match", "drift"}
        and report["source_validation"].get("status") == "all_markers_match"
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
