#!/usr/bin/env python3
"""Capture bounded, read-only TLS and client-operation evidence for B-035.

The probe reads Cloudflare's zone setting once, performs TLS negotiation on
source-bound ingress hosts, and makes three bounded authenticated read-only
client operations. No cache writes or provider writes are performed.
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
                str(curl), "--silent", "--show-error", "--verbose", "--output", "/dev/null",
                "--write-out", "HTTP_STATUS:%{http_code}\\n", "--max-time", str(TIMEOUT_SECONDS),
                version_flag, "--tls-max", max_version, f"https://{hostname}/",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS + 2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"client": client, "requested": label, "status": "timeout", "application_data_sent": False}
    match = re.search(r"(?:SSL connection using|SSL connection:) ([^\r\n]+)", result.stderr)
    http_status = re.search(r"HTTP_STATUS:(\d{3})", result.stdout)
    if result.returncode == 0 and match and http_status:
        return {
            "client": client,
            "requested": label,
            "status": "success",
            "negotiated": match.group(1).split(" / ", 1)[0],
            "certificate_verified": True,
            "http_status": int(http_status.group(1)),
            "application_data_sent": True,
        }
    return {
        "client": client,
        "requested": label,
        "status": "handshake_error",
        "error": _safe_curl_error(result.stderr, result.returncode),
        "application_data_sent": bool(http_status),
    }


def _safe_curl_error(stderr: str, returncode: int) -> str:
    """Return a bounded diagnostic without emitting verbose headers or tokens."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    safe = [line for line in lines if not re.search(r"authorization|bearer|cookie", line, re.I)]
    return (safe[-1][:180] if safe else f"curl_exit_{returncode}")


def _read_only_client_operations() -> list[dict[str, Any]]:
    """Exercise authenticated, source-bound read routes; never write cache data."""
    token_sccache = os.environ.get("CORELINK_SCCACHE_TOKEN")
    token_canary = os.environ.get("CORELINK_CANARY_PAT")
    sccache_tenant = "ee30f7ba-fc25-4d71-939e-ebe130b4c6a3"
    canary_tenant = "93da3f7a-984d-4ef9-86e0-b0bd9fd0252e"
    operations = [
        ("sccache", "PROPFIND", f"https://corelink-api.humangr.com/cargo/{sccache_tenant}/b035-tls-probe-never-written", token_sccache, (200, 404)),
        ("bazel_reapi", "GET", f"https://corelink-api.humangr.com/bazel/v2/{canary_tenant}/blobs/" + "0" * 64 + "/0", token_canary, (200, 404)),
        ("turborepo", "POST", "https://corelink-api.humangr.com/v8/artifacts/status", token_canary, (200,)),
    ]
    results = []
    curl = Path("/usr/bin/curl")
    for client, method, url, token, expected in operations:
        if not token:
            results.append({"client": client, "status": "credential_unavailable", "operation": method, "application_data_sent": False})
            continue
        try:
            result = subprocess.run(
                [str(curl), "--silent", "--show-error", "--verbose", "--output", "/dev/null",
                 "--write-out", "HTTP_STATUS:%{http_code}\\n", "--max-time", str(TIMEOUT_SECONDS),
                 "--request", method, "--config", "-", url],
                input=f'header = "Authorization: Bearer {token}"\n', capture_output=True,
                text=True, timeout=TIMEOUT_SECONDS + 2, check=False,
            )
        except subprocess.TimeoutExpired:
            results.append({"client": client, "operation": method, "status": "timeout", "application_data_sent": True})
            continue
        status_match = re.search(r"HTTP_STATUS:(\d{3})", result.stdout)
        negotiated = re.search(r"(?:SSL connection using|SSL connection:) ([^\r\n]+)", result.stderr)
        status_code = int(status_match.group(1)) if status_match else None
        results.append({
            "client": client, "operation": method,
            "status": "success" if result.returncode == 0 and status_code in expected and negotiated else "operation_error",
            "http_status": status_code,
            "negotiated_tls": negotiated.group(1).split(" / ", 1)[0] if negotiated else None,
            "certificate_verified": bool(negotiated and result.returncode == 0),
            "application_data_sent": bool(status_code),
            **({"error": _safe_curl_error(result.stderr, result.returncode)} if result.returncode else {}),
        })
    return results


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
        "evidence_scope": "TLS negotiation on each concrete hostname; read-only app operations separately exercise sccache PROPFIND, Bazel REAPI GET, and Turborepo status POST",
        "ingress": [],
        "templated_ingress": [],
        "client_operations": [],
        "client_compatibility": [
            {
                "client": "sccache (macOS native-tls/SecureTransport)",
                "version_in_source": "sccache >= 0.15; exact production binary version unavailable",
                "source": "specs/03_architecture/adrs/ADR-0072-humangr-zone-min-tls-1.2.md; apps/docs/docs/integrations/sccache-cargo.md",
                "endpoint_source": "https://corelink-api.humangr.com/cargo/<tenant> in apps/docs/docs/integrations/sccache-cargo.md",
                "probe": "Apple SecureTransport TLS handshake plus authenticated read-only PROPFIND of an absent sentinel key; not an sccache binary invocation",
                "historic_source_result": "ADR-0072 records a TLS-1.3-only floor rejected the macOS SecureTransport client; the zone was lowered to 1.2",
                "status": "historical_tls_1_3_only_incompatibility_recorded; bounded_read_operation_reported_separately",
            },
            {
                "client": "Bazel REAPI",
                "source": "apps/docs/docs/integrations/bazel.md",
                "version_in_source": "stock Bazel; exact version unavailable",
                "endpoint_source": "https://corelink-api.humangr.com/bazel/v2/<tenant>/…",
                "probe": "authenticated read-only REAPI ByteStream GET for an absent SHA-256 sentinel blob; no Bazel binary invocation",
                "status": "bounded_reapi_read_operation_reported_separately",
            },
            {
                "client": "Turborepo",
                "source": "apps/docs/docs/integrations/turborepo.md",
                "version_in_source": "not pinned in source",
                "endpoint_source": "https://corelink-api.humangr.com (TURBO_API)",
                "probe": "authenticated POST to the static /v8/artifacts/status route (no body/storage/billing path); no Turborepo binary invocation",
                "status": "bounded_status_operation_reported_separately",
            },
        ],
        "cipher_boundary": "Observed negotiated cipher names are per-handshake facts only; no Cloudflare cipher-suite policy is claimed or verified.",
        "mutation": False,
    }

    token, token_source = b035._token()
    report["credential"] = {"available": bool(token), "source": token_source}
    if live:
        report["zone_floor"] = b035.read_live_floor(token) if token else {"status": "credential_unavailable"}
        if report["zone_floor"].get("status") == "match" and source_validation_ok:
            report["client_operations"] = _read_only_client_operations()

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
            and summary["source_bound_ingress_rows"] == 14
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
