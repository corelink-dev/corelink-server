#!/usr/bin/env python3
"""Bounded operator for the #2568 real Stripe test credit proof.

The credentialless mode validates the frozen contract without networking.
Provider mode is deliberately narrow: it requires the exact protected branch,
candidate SHA, test account binding and restricted Stripe test key before it
can create a disposable customer, one negative invoice item and one draft
invoice. Every response and exception is kept out of logs and receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ISSUE = 2568
BRANCH = "refs/heads/main"
STRIPE_ACCOUNT_SHA256 = "e9678dceccdaa37a7259379096e82875f6ae0c694f9a461a28691c79eceb33ad"
CF_ACCOUNT = "51284495e71acdb5a7677e7383ab026b"
WORKER_NAME = "corelink-i2568-sla-credit-test-20260928"
SOURCE_SHA = "5fabd93e98d805a39319fcb6a22c9ee5267fafd4"
SOURCE_DIGESTS = {
    "apps/signup-worker/src/webhooks/sla_credit_cron.ts": "e290331915c8f61e3115a9d5b9b1213c4aac97005ade2de98ba79ba866abc3c3",
    "migrations/d1/0055_tenant_billing.sql": "f5420ceac080d92ae5dab05cf6209525d767de3408828bda46134e9323e8d93d",
    "migrations/d1/0117_sla_credit_ledger.sql": "658469f4102b6ef424af7dda29c8febcbf1058a677426be24da9306282c3454e",
}
API_BASE = "https://api.stripe.com"
CONFIRMATION = "run-i2568-sla-credit-test-mode"
TIMEOUT = 20


class OperatorError(RuntimeError):
    """Safe, non-sensitive operator failure."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redacted_id(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return "sha256:" + sha256(value.encode("utf-8"))


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def assert_checkout(expected_sha: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise OperatorError("expected_sha must be a full lowercase commit SHA")
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise OperatorError("cannot establish candidate checkout identity") from exc
    if head != expected_sha:
        raise OperatorError("checked out candidate SHA differs from expected_sha")
    if os.environ.get("GITHUB_REPOSITORY") != "HuGR-dev/corelink-server":
        raise OperatorError("provider operation is restricted to the canonical repository")
    if os.environ.get("GITHUB_SHA") != expected_sha:
        raise OperatorError("GitHub workflow SHA differs from expected_sha")
    if os.environ.get("GITHUB_REF") != BRANCH:
        raise OperatorError("provider operation is restricted to the protected main ref")
    try:
        remote = subprocess.check_output(
            ["git", "ls-remote", "--exit-code", "https://github.com/HuGR-dev/corelink-server.git", "refs/heads/main"],
            text=True, stderr=subprocess.DEVNULL, timeout=15,
        ).strip().split()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise OperatorError("cannot verify the fresh protected-main commit before provider writes") from exc
    if len(remote) != 2 or remote[1] != "refs/heads/main" or remote[0] != expected_sha:
        raise OperatorError("expected_sha is not the fresh protected-main commit")
    return head


def validate_account_binding(value: str) -> None:
    if sha256(value.encode("utf-8")) != STRIPE_ACCOUNT_SHA256:
        raise OperatorError("STRIPE_TEST_ACCOUNT_ID does not match the admitted account binding")


def validate_restricted_key(value: str) -> None:
    if not re.fullmatch(r"rk_test_[A-Za-z0-9]{8,}", value):
        raise OperatorError("STRIPE_SECRET_KEY must be an admitted restricted test key")


def invoice_item_from_line(line: dict[str, Any]) -> tuple[str, str]:
    legacy_id = line.get("invoice_item")
    parent = line.get("parent")
    parent_id = None
    parent_type = None
    if isinstance(parent, dict) and parent.get("type") == "invoice_item_details":
        parent_type = parent.get("type")
        details = parent.get("invoice_item_details")
        if isinstance(details, dict):
            parent_id = details.get("invoice_item")
    if isinstance(parent_id, str):
        if legacy_id is not None and legacy_id != parent_id:
            raise OperatorError("Stripe invoice line had conflicting invoice-item references")
        return parent_id, "parent.invoice_item_details.invoice_item"
    if isinstance(legacy_id, str) and not (isinstance(parent, dict) and parent_type is None):
        return legacy_id, "invoice_item"
    raise OperatorError("Stripe invoice line did not expose an unambiguous invoice-item reference")


@dataclass
class Stripe:
    key: str
    response_api_version: str | None = None

    def request(self, method: str, path: str, form: dict[str, str] | None = None,
                *, idem: str | None = None) -> dict[str, Any]:
        body = urllib.parse.urlencode(form or {}).encode("utf-8") if form is not None else None
        headers = {"Authorization": f"Bearer {self.key}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if idem:
            headers["Idempotency-Key"] = idem
        request = urllib.request.Request(API_BASE + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise OperatorError(f"Stripe {method} target operation exceeded the bounded response size")
                self.response_api_version = response.headers.get("Stripe-Version")
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise OperatorError(f"Stripe {method} target operation returned an invalid object")
                return payload
        except urllib.error.HTTPError as exc:
            resource = path.split("?", 1)[0].split("/")
            safe_resource = "/".join(resource[:3]) if len(resource) >= 3 else "/v1/provider-object"
            raise OperatorError(f"Stripe {method} {safe_resource} returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OperatorError(f"Stripe {method} target operation had an unknown transport/result state") from exc

    def absent(self, path: str) -> bool:
        request = urllib.request.Request(API_BASE + path,
                                         headers={"Authorization": f"Bearer {self.key}"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                response.read(65537)
                return False
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return True
            raise OperatorError(f"Stripe target absence read returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise OperatorError("Stripe target absence read had an unknown result") from exc


class Cloudflare:
    def __init__(self, token: str):
        self.token = token

    def request(self, method: str, path: str, data: dict[str, Any] | None = None) -> tuple[int, dict[str, Any] | None]:
        body = json.dumps(data).encode("utf-8") if data is not None else None
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request("https://api.cloudflare.com/client/v4" + path,
                                         data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise OperatorError("Cloudflare target response exceeded the bounded size")
                if not raw:
                    return response.status, {"success": True, "result": None}
                payload = json.loads(raw)
                if not isinstance(payload, dict) or payload.get("success") is not True:
                    raise OperatorError(f"Cloudflare {method} target operation did not succeed")
                return response.status, payload
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return 404, None
            raise OperatorError(f"Cloudflare {method} target operation returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OperatorError(f"Cloudflare {method} target operation has an unknown result state") from exc

    def create_database(self) -> str:
        status, payload = self.request("POST", f"/accounts/{CF_ACCOUNT}/d1/database", {"name": WORKER_NAME})
        if status not in (200, 201) or not payload:
            raise OperatorError("isolated D1 creation did not return a database")
        result = payload.get("result")
        identifier = result.get("uuid") if isinstance(result, dict) else None
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f-]{36}", identifier):
            raise OperatorError("isolated D1 creation returned an invalid identifier")
        return identifier

    def verify_subdomain(self) -> dict[str, Any]:
        status, payload = self.request("GET", f"/accounts/{CF_ACCOUNT}/workers/subdomain")
        result = payload.get("result") if payload else None
        if (status != 200 or not isinstance(result, dict)
                or not isinstance(result.get("subdomain"), str) or not result["subdomain"].strip()):
            raise OperatorError("existing account Workers subdomain/topology could not be verified")
        return {
            "subdomain_sha256": redacted_id(result["subdomain"]),
            "subdomain_present": True,
            "previews_enabled": result.get("previews_enabled"),
            "unchanged_by_operator": True,
        }

    def query(self, database_id: str, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        status, payload = self.request(
            "POST", f"/accounts/{CF_ACCOUNT}/d1/database/{database_id}/query",
            {"sql": sql, "params": params or []},
        )
        if status != 200 or not payload:
            raise OperatorError("isolated D1 query failed")
        raw = payload.get("result")
        if not isinstance(raw, list) or not raw or not isinstance(raw[0], dict):
            raise OperatorError("isolated D1 query returned an invalid result")
        rows = raw[0].get("results")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise OperatorError("isolated D1 query returned invalid rows")
        return rows


def _private_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise OperatorError("private runtime file path unexpectedly resolves through a symlink")
    previous = os.umask(0o077)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        path.chmod(0o600)
    finally:
        os.umask(previous)


def _safe_wrangler(args: list[str], *, cwd: Path, env: dict[str, str], stdin: str | None = None) -> str:
    command = ["npx", "--yes", "wrangler@4.111.0", *args]
    try:
        result = subprocess.run(command, cwd=cwd, env=env, input=stdin, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OperatorError("pinned Wrangler operation was unavailable or timed out") from exc
    if result.returncode != 0:
        raise OperatorError(f"pinned Wrangler operation failed (exit {result.returncode})")
    return result.stdout


def _ensure_absent_target(cf: Cloudflare) -> dict[str, Any]:
    topology = cf.verify_subdomain()
    status, _ = cf.request("GET", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}")
    if status != 404:
        raise OperatorError("exclusive Worker target already exists or could not be proven absent")
    status, payload = cf.request("GET", f"/accounts/{CF_ACCOUNT}/d1/database?name={urllib.parse.quote(WORKER_NAME)}")
    if status == 200 and payload:
        result = payload.get("result")
        if isinstance(result, list) and any(isinstance(row, dict) and row.get("name") == WORKER_NAME for row in result):
            raise OperatorError("exclusive D1 target already exists; refusing adoption")
    elif status != 404:
        raise OperatorError("exclusive D1 target absence could not be proven")
    return topology


def _apply_exact_migrations(cf: Cloudflare, database_id: str, source_root: Path) -> dict[str, str]:
    names = ("0055_tenant_billing.sql", "0117_sla_credit_ledger.sql")
    cf.query(database_id, "CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)")
    applied = cf.query(database_id, "SELECT name FROM d1_migrations ORDER BY id")
    if applied:
        raise OperatorError("new isolated D1 already contains migration history")
    hashes: dict[str, str] = {}
    for name in names:
        path = source_root / "migrations" / "d1" / name
        content = path.read_text(encoding="utf-8")
        actual = sha256(content.encode("utf-8"))
        if actual != SOURCE_DIGESTS[f"migrations/d1/{name}"]:
            raise OperatorError(f"migration digest drift: {name}")
        statements = [part.strip() for part in re.sub(r"(?m)^\s*--.*(?:\n|$)", "", content).split(";") if part.strip()]
        for statement in statements:
            cf.query(database_id, statement)
        cf.query(database_id, "INSERT INTO d1_migrations(name) VALUES (?)", [name.removesuffix(".sql")])
        hashes[name] = actual
    observed = cf.query(database_id, "SELECT name FROM d1_migrations ORDER BY id")
    if [row.get("name") for row in observed] != [name.removesuffix(".sql") for name in names]:
        raise OperatorError("isolated D1 migration history differs from the exact two migrations")
    return hashes


def _prepare_worker_tree(runtime: Path, candidate_root: Path, source_root: Path, database_id: str) -> None:
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    (runtime / "migrations").mkdir(mode=0o700, exist_ok=True)
    for name in ("0055_tenant_billing.sql", "0117_sla_credit_ledger.sql"):
        shutil.copy2(source_root / "migrations" / "d1" / name, runtime / "migrations" / name)
    (runtime / "scripts").mkdir(mode=0o700, exist_ok=True)
    shutil.copy2(candidate_root / "scripts/issue_2568_sla_credit_worker.ts", runtime / "scripts/issue_2568_sla_credit_worker.ts")
    config = (
        f'name = "{WORKER_NAME}"\n'
        'main = "scripts/issue_2568_sla_credit_worker.ts"\n'
        'compatibility_date = "2026-09-28"\n'
        'workers_dev = false\n'
        'preview_urls = false\n'
        f'account_id = "{CF_ACCOUNT}"\n'
        'migrations_dir = "migrations"\n\n'
        '[vars]\n'
        'SLA_CREDITS_ENABLED = "false"\n'
        'STRIPE_API_BASE = "https://api.stripe.com"\n\n'
        '[[d1_databases]]\n'
        'binding = "BILLING_DB"\n'
        f'database_name = "{WORKER_NAME}"\n'
        f'database_id = "{database_id}"\n'
        'migrations_dir = "migrations"\n'
    )
    _private_write(runtime / "wrangler.toml", config)


def _configure_and_deploy_worker(cf: Cloudflare, runtime: Path, env: dict[str, str], stripe_key: str,
                                database_id: str, mark_upload_attempted: Any) -> tuple[str, dict[str, Any]]:
    mark_upload_attempted()
    _safe_wrangler(["deploy", "--config", str(runtime / "wrangler.toml")], cwd=runtime, env=env)
    _safe_wrangler(["secret", "put", "STRIPE_SECRET_KEY", "--config", str(runtime / "wrangler.toml")],
                   cwd=runtime, env=env, stdin=stripe_key + "\n")
    status, payload = cf.request("GET", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}/settings")
    if status != 200 or not payload or not isinstance(payload.get("result"), dict):
        raise OperatorError("persistent test Worker settings readback failed")
    settings = payload["result"]
    _verify_worker_config(settings, database_id)
    status, subdomain = cf.request("GET", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}/subdomain")
    subdomain_result = subdomain.get("result") if subdomain else None
    if (status != 200 or not isinstance(subdomain_result, dict)
            or subdomain_result.get("enabled") is not False
            or subdomain_result.get("previews_enabled") is not False):
        raise OperatorError("persistent test Worker workers.dev and preview URLs are not disabled")
    status, schedules = cf.request("GET", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}/schedules")
    schedule_result = schedules.get("result") if schedules else None
    if status != 200 or not isinstance(schedule_result, dict) or schedule_result.get("schedules") != []:
        raise OperatorError("persistent test Worker schedules are not empty")
    status, versions = cf.request("GET", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}/versions")
    version_result = versions.get("result") if versions else None
    items = version_result.get("items") if isinstance(version_result, dict) else None
    if status != 200 or not isinstance(items, list):
        raise OperatorError("persistent Worker version readback failed")
    rows = items
    version = (rows[0].get("id") or rows[0].get("version_id")) if rows and isinstance(rows[0], dict) else None
    if not isinstance(version, str) or not version:
        raise OperatorError("persistent Worker version identity is absent")
    return version, {"workers_dev": False, "preview_urls": False, "schedules": [],
                     "route_configuration": "wrangler_config_has_no_routes_or_services",
                     "bindings_verified": True}


def _scheduled_preview(*, runtime: Path, env: dict[str, str], gate: bool,
                       observation: dict[str, Any], customer_id: str, tenant_id: str,
                       preview_states: list[dict[str, Any]]) -> str:
    observation_json = json.dumps(observation, sort_keys=True, separators=(",", ":"))
    devvars = (
        f"I2568_TEST_TENANT_ID={tenant_id}\n"
        f"I2568_TEST_STRIPE_CUSTOMER_ID={customer_id}\n"
        "I2568_TEST_SERVICE_PERIOD=2026-08\n"
        "I2568_TEST_MONTHLY_FEE_MINOR=10000\n"
        "I2568_TEST_AVAILABILITY_PERCENT=99.49\n"
        f"I2568_TEST_OBSERVATION_JSON='{observation_json}'\n"
    )
    _private_write(runtime / ".dev.vars", devvars)
    port = 8788
    local_env = dict(env)
    local_env["NO_COLOR"] = "1"
    log_file = tempfile.TemporaryFile(mode="w+b")
    command = [
        "npx", "--yes", "wrangler@4.111.0", "dev", "--remote", "--test-scheduled",
        "--ip", "127.0.0.1", "--port", str(port), "--config", str(runtime / "wrangler.toml"),
        "--var", f"SLA_CREDITS_ENABLED:{'true' if gate else 'false'}",
    ]
    process: subprocess.Popen[bytes] | None = None
    session_id = ""
    state = {"terminated": False}
    preview_states.append(state)
    try:
        process = subprocess.Popen(command, cwd=runtime, env=local_env, stdout=log_file, stderr=log_file)
        ready = False
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise OperatorError("private Wrangler preview ended before scheduled invocation")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.5)
        if not ready:
            raise OperatorError("private Wrangler preview did not bind its loopback port")
        session_id = hashlib.sha256(
            f"{time.time_ns()}:{tenant_id}:{gate}:{process.pid}".encode()
        ).hexdigest()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/__scheduled?cron=*+*+*+*+*",
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.status != 200:
                raise OperatorError("private scheduled invocation returned non-success status")
            response.read(65537)
        return session_id
    except urllib.error.HTTPError as exc:
            raise OperatorError(f"private scheduled invocation returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise OperatorError("private scheduled invocation transport failed") from exc
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.poll() is None:
                raise OperatorError("private Wrangler preview process termination was not verified")
            state["terminated"] = True
        log_file.close()


def _assert_test_customer(customer: dict[str, Any], *, customer_id: str, run_id: str) -> None:
    if (customer.get("id") != customer_id or customer.get("livemode") is not False
            or customer.get("metadata", {}).get("corelink_issue") != str(ISSUE)
            or customer.get("metadata", {}).get("corelink_run") != run_id):
        raise OperatorError("Stripe customer ownership/mode readback failed")


def _create_synthetic_customer(stripe: Stripe, objects: OwnedStripeObjects) -> dict[str, Any]:
    response = stripe.request("POST", "/v1/customers", {
        "description": f"CoreLink #2568 test {objects.run_id}",
        "metadata[corelink_issue]": str(ISSUE), "metadata[corelink_run]": objects.run_id,
    }, idem=f"corelink-i2568-{objects.run_id}-credit-customer")
    objects.customer_id = response.get("id") if isinstance(response.get("id"), str) else None
    if not objects.customer_id or not objects.customer_id.startswith("cus_"):
        raise OperatorError("Stripe test customer create returned no attributable identifier")
    _assert_test_customer(response, customer_id=objects.customer_id, run_id=objects.run_id)
    return response


def _create_wp2_customer(expected_sha: str, stripe: Stripe, objects: OwnedStripeObjects) -> dict[str, Any]:
    # A stale dispatch must not begin WP2 customer-side effects.
    return _with_fresh_main(expected_sha, _create_synthetic_customer, stripe, objects)


def _with_fresh_main(expected_sha: str, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    assert_checkout(expected_sha)
    return operation(*args, **kwargs)


def _fresh_main_acceptance(receipt: dict[str, Any], expected_sha: str) -> bool:
    try:
        assert_checkout(expected_sha)
    except OperatorError:
        receipt["status"] = "stale_or_unverifiable_main"
        receipt["closure_acceptance"] = "denied_fresh_main_check_failed"
        return False
    return True


def _verify_worker_config(settings: dict[str, Any], database_id: str) -> None:
    bindings = settings.get("bindings")
    if not isinstance(bindings, list):
        raise OperatorError("Worker bindings readback was malformed")
    binding_names = {
        item.get("name"): item.get("type") for item in bindings
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if binding_names != {
        "BILLING_DB": "d1",
        "SLA_CREDITS_ENABLED": "plain_text",
        "STRIPE_API_BASE": "plain_text",
        "STRIPE_SECRET_KEY": "secret_text",
    }:
        raise OperatorError("persistent Worker binding names/types differ from the isolated test contract")
    d1 = [item for item in bindings if isinstance(item, dict) and item.get("type") == "d1" and item.get("name") == "BILLING_DB"]
    if len(d1) != 1 or d1[0].get("id") != database_id:
        raise OperatorError("persistent Worker did not bind one isolated D1 database")
    prohibited_types = {"queue", "r2_bucket", "service", "durable_object_namespace", "kv_namespace"}
    if any(isinstance(item, dict) and item.get("type") in prohibited_types for item in bindings):
        raise OperatorError("persistent Worker has an unapproved external binding")


def _stripe_invoiceitems(stripe: Stripe, customer_id: str) -> list[dict[str, Any]]:
    payload = stripe.request("GET", "/v1/invoiceitems?" + urllib.parse.urlencode({"customer": customer_id, "limit": "100"}))
    rows = payload.get("data")
    if not isinstance(rows, list) or payload.get("has_more") is True or any(not isinstance(row, dict) for row in rows):
        raise OperatorError("customer-scoped Stripe invoice-item readback was ambiguous")
    return rows


def _d1_counts(cf: Cloudflare, database_id: str, tenant_id: str, period: str) -> dict[str, int]:
    result: dict[str, int] = {}
    tables = (
        "sla_monthly_observations", "sla_monthly_measurements", "sla_credit_ledger",
        "sla_credit_outbox", "sla_credit_reconciliation", "sla_credit_audit_events",
    )
    for table in tables:
        if table in ("sla_monthly_observations", "sla_monthly_measurements", "sla_credit_ledger"):
            row = _query_one(cf, database_id,
                             f"SELECT COUNT(*) AS n FROM {table} WHERE tenant_id = ? AND service_period = ?",
                             [tenant_id, period])
        else:
            row = _query_one(cf, database_id,
                             f"SELECT COUNT(*) AS n FROM {table} WHERE credit_id = ?",
                             [f"sla_credit:{tenant_id}:{period}"])
        result[table] = int(row.get("n", 0))
    return result


def _cleanup_cloudflare(cf: Cloudflare, database_id: str | None, *,
                        d1_create_attempted: bool, worker_upload_attempted: bool) -> dict[str, Any]:
    result: dict[str, Any] = {"worker_deleted": False, "database_deleted": False, "worker_absent": False, "database_absent": False, "errors": []}
    if database_id is None and d1_create_attempted:
        try:
            status, payload = cf.request("GET", f"/accounts/{CF_ACCOUNT}/d1/database?name={urllib.parse.quote(WORKER_NAME)}")
            matches = payload.get("result") if status == 200 and payload else []
            matches = [row for row in matches if isinstance(row, dict) and row.get("name") == WORKER_NAME] if isinstance(matches, list) else []
            if len(matches) > 1:
                result["errors"].append("target-only D1 recovery found multiple same-name databases")
            elif matches:
                candidate = matches[0].get("uuid") or matches[0].get("id")
                if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f-]{36}", candidate):
                    database_id = candidate
                else:
                    result["errors"].append("target-only D1 recovery found an invalid identifier")
            elif status in (200, 404):
                # A run-specific create attempt returned without an ID, but an
                # exact-name query proves no target exists to delete.
                result["database_deleted"] = True
                result["database_absent"] = True
            else:
                result["errors"].append("target-only D1 recovery returned an ambiguous result")
        except OperatorError as exc:
            result["errors"].append(str(exc))
    if worker_upload_attempted:
        try:
            status, _ = cf.request("DELETE", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}")
            if status not in (200, 204, 404):
                result["errors"].append("owned Worker deletion did not succeed")
            else:
                result["worker_deleted"] = True
        except OperatorError as exc:
            result["errors"].append(str(exc))
    if database_id:
        database_path = (f"/accounts/{CF_ACCOUNT}/d1/database/{database_id}" if database_id
                         else f"/accounts/{CF_ACCOUNT}/d1/database?name={urllib.parse.quote(WORKER_NAME)}")
        try:
            status, _ = cf.request("DELETE", database_path)
            if status not in (200, 204, 404):
                result["errors"].append("owned D1 deletion did not succeed")
            else:
                result["database_deleted"] = True
        except OperatorError as exc:
            result["errors"].append(str(exc))
    if worker_upload_attempted:
        try:
            status, _ = cf.request("GET", f"/accounts/{CF_ACCOUNT}/workers/scripts/{WORKER_NAME}")
            result["worker_absent"] = status == 404
            if not result["worker_absent"]:
                result["errors"].append("owned Worker absence was not verified")
        except OperatorError as exc:
            result["errors"].append(str(exc))
    if database_id:
        try:
            status, _ = cf.request("GET", f"/accounts/{CF_ACCOUNT}/d1/database/{database_id}")
            result["database_absent"] = status == 404
            if not result["database_absent"]:
                result["errors"].append("owned D1 absence was not verified")
        except OperatorError as exc:
            result["errors"].append(str(exc))
    return result


def run_all(*, expected_sha: str, run_id: str, confirmation: str, source_root: Path, output: Path) -> int:
    receipt: dict[str, Any] = {
        "schema": "corelink.issue-2568.sla-credit-real.v1", "issue": ISSUE, "mode": "test",
        "redacted": True, "status": "running", "candidate_sha": None,
        "canonical_source_sha": SOURCE_SHA, "canonical_source_digests": {},
        "operator": {}, "persistent_worker": {}, "private_invocations": [],
        "stripe_test_account_id_sha256": STRIPE_ACCOUNT_SHA256,
        "d1": {}, "credit": {}, "replay": {}, "invoice": {},
        "cleanup": {"state": "pending", "stripe_objects": {}, "cloudflare_targets": {}},
        "timestamps_utc": {"started": datetime.now(timezone.utc).isoformat()},
    }
    stripe: Stripe | None = None
    owned: OwnedStripeObjects | None = None
    cf: Cloudflare | None = None
    database_id: str | None = None
    d1_create_attempted = False
    worker_upload_attempted = False
    runtime: Path | None = None
    capability_path: Path | None = None
    preview_states: list[dict[str, Any]] = []
    exit_code = 1
    try:
        if confirmation != CONFIRMATION:
            raise OperatorError("explicit #2568 test-mode confirmation is missing")
        if os.environ.get("I2568_PROVIDER_APPROVED") != "true":
            raise OperatorError("root-owned I2568_PROVIDER_APPROVED protected-environment gate is not true")
        head = assert_checkout(expected_sha)
        receipt["candidate_sha"] = head
        receipt["operator"] = {
            "branch": "main", "head_sha": head,
            "workflow_run_id": run_id,
            "operator_file_sha256": sha256(Path(__file__).read_bytes()),
        }
        if not re.fullmatch(r"[A-Za-z0-9-]{1,100}", run_id):
            raise OperatorError("workflow run identifier is missing or malformed")
        source_root = source_root.resolve()
        source_head = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True,
                                              stderr=subprocess.DEVNULL).strip()
        if source_head != SOURCE_SHA:
            raise OperatorError("separate canonical-source checkout is not the frozen baseline")
        source_digests = _check_source(source_root)
        receipt["canonical_source_digests"] = source_digests

        stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
        validate_restricted_key(stripe_key)
        account_binding = os.environ.get("STRIPE_TEST_ACCOUNT_ID", "")
        validate_account_binding(account_binding)
        stripe = Stripe(stripe_key)
        account = stripe.request("GET", "/v1/account")
        if account.get("object") != "account" or account.get("id") != account_binding:
            raise OperatorError("Stripe test account identity differs from the exact protected binding")
        receipt["checks"] = {"restricted_test_key": "pass", "stripe_account_identity": "pass"}
        receipt["stripe_response_api_version"] = stripe.response_api_version

        # CF read-only authority/topology and exclusive-name preflight is first;
        # no Stripe write may precede proof that both provider boundaries are usable.
        cf_token = os.environ.get("CF_I2568_API_TOKEN", "")
        if not cf_token:
            raise OperatorError("dedicated account-5128 Cloudflare test token is missing")
        if os.environ.get("CLOUDFLARE_ACCOUNT_ID") != CF_ACCOUNT:
            raise OperatorError("Cloudflare target account differs from the frozen test account")
        cf = Cloudflare(cf_token)
        receipt["cloudflare_subdomain"] = _ensure_absent_target(cf)
        d1_create_attempted = False
        worker_upload_attempted = False

        # WP1: prove only the bounded create/write/draft/delete capability.
        capability_path = output.with_name(".i2568-capability-private.json")
        probe_code = run_capability_probe(expected_sha=expected_sha, run_id=run_id, confirmation=confirmation,
                                          output=capability_path)
        try:
            capability = json.loads(capability_path.read_text(encoding="utf-8")) if capability_path.exists() else {}
        finally:
            capability_path.unlink(missing_ok=True)
        if probe_code != 0:
            receipt["capability_probe"] = {
                "status": "failed", "required_act": capability.get("required_act"),
                "failure": capability.get("failure", "unclassified_provider_failure"),
                "provider_effects": capability.get("provider_effects", []),
                "created_object_sha256": {
                    key: capability.get(key) for key in ("customer", "invoice_item", "draft_invoice")
                    if capability.get(key)
                },
                "cleanup": capability.get("cleanup", {}),
            }
            raise OperatorError("bounded Stripe capability probe failed; exact cleanup/action receipt retained")
        if capability.get("cleanup", {}).get("succeeded") is not True:
            raise OperatorError("bounded Stripe capability probe cleanup did not verify")
        receipt["capability_probe"] = {
            "checks": capability.get("checks", {}), "cleanup_succeeded": True,
            "provider_effects": capability.get("provider_effects", []),
            "cleanup": {
                "attempted": capability.get("cleanup", {}).get("attempted") is True,
                "succeeded": capability.get("cleanup", {}).get("succeeded") is True,
                "absence_verified": capability.get("cleanup", {}).get("absence_verified") is True,
            },
            "customer_sha256": capability.get("customer"),
            "invoice_item_sha256": capability.get("invoice_item"),
            "draft_invoice_sha256": capability.get("draft_invoice"),
            "invoice_line_shape": capability.get("invoice_line_shape", []),
        }

        # Revalidate main immediately before the first Cloudflare mutation.
        assert_checkout(expected_sha)
        d1_create_attempted = True
        database_id = cf.create_database()
        status, db_payload = cf.request("GET", f"/accounts/{CF_ACCOUNT}/d1/database/{database_id}")
        db_result = db_payload.get("result") if db_payload else None
        if status != 200 or not isinstance(db_result, dict) or db_result.get("uuid") != database_id or db_result.get("name") != WORKER_NAME:
            raise OperatorError("new D1 target name/UUID readback failed")
        receipt["d1"]["uuid_sha256"] = redacted_id(database_id)
        receipt["d1"]["name"] = WORKER_NAME
        receipt["d1"]["account"] = CF_ACCOUNT
        migration_hashes = _apply_exact_migrations(cf, database_id, source_root)
        receipt["d1"]["migration_sha256"] = migration_hashes
        expected_tables = {"tenant_billing", "sla_monthly_observations", "sla_monthly_measurements",
                           "sla_credit_ledger", "sla_credit_outbox", "sla_credit_reconciliation", "sla_credit_audit_events"}
        schema_rows = cf.query(database_id, "SELECT name FROM sqlite_master WHERE type='table'")
        table_names = {row.get("name") for row in schema_rows}
        if not expected_tables.issubset(table_names):
            raise OperatorError("isolated D1 migration schema is incomplete")
        receipt["d1"]["schema_tables"] = sorted(expected_tables)
        receipt["d1"]["migration_history"] = [row.get("name") for row in cf.query(database_id, "SELECT name FROM d1_migrations ORDER BY id")]

        runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
        candidate_root = Path(__file__).resolve().parents[1]
        runtime = Path(tempfile.mkdtemp(prefix=".i2568-private-runtime-", dir=candidate_root))
        runtime.chmod(0o700)
        _prepare_worker_tree(runtime, candidate_root, source_root, database_id)
        cloudflare_env = dict(os.environ)
        cloudflare_env["CLOUDFLARE_API_TOKEN"] = cf_token
        worker_upload_attempted = True
        version, worker_topology = _configure_and_deploy_worker(
            cf, runtime, cloudflare_env, stripe_key, database_id,
            mark_upload_attempted=lambda: None,
        )
        receipt["persistent_worker"] = {
            "name": WORKER_NAME, "version_id_sha256": redacted_id(version),
            "workers_dev": worker_topology["workers_dev"], "preview_urls": worker_topology["preview_urls"],
            "routes": [], "crons": worker_topology["schedules"],
            "gate": False, "source_sha": SOURCE_SHA, "operator_sha": head,
            "route_configuration": worker_topology["route_configuration"],
            "bindings_verified": worker_topology["bindings_verified"],
            "operator_file_sha256": receipt["operator"]["operator_file_sha256"],
        }

        # WP2: new disposable customer and one closed, cutoff-eligible UTC month.
        tenant_id = "i2568_" + re.sub(r"[^A-Za-z0-9-]", "", run_id)[:90]
        owned = OwnedStripeObjects(stripe, run_id)
        customer = _create_wp2_customer(expected_sha, stripe, owned)
        customer_id = owned.customer_id
        if not customer_id:
            raise OperatorError("owned Stripe customer ID is missing")
        observation_time_ms = int(time.time() * 1000)
        observation = {
            "tenant_id": tenant_id, "service_period": "2026-08", "tier": "starter",
            "monthly_fee_minor": 10000, "currency": "USD", "availability_percent": 99.49,
            "force_majeure": False, "observed_at_ms": observation_time_ms,
        }
        period = "2026-08"
        credit_id = f"sla_credit:{tenant_id}:{period}"
        owned.credit_id = credit_id
        gate_false_session = _scheduled_preview(runtime=runtime, env=cloudflare_env, gate=False,
                                                observation=observation, customer_id=customer_id, tenant_id=tenant_id,
                                                preview_states=preview_states)
        receipt["private_invocations"].append({"gate": False, "session_sha256": gate_false_session,
                                                "persistent_worker_version_sha256": redacted_id(version),
                                                "canonical_source_sha": SOURCE_SHA, "operator_sha": head,
                                                "process_terminated": True,
                                                "result": "scheduled_http_200"})
        ledger = _query_one(cf, database_id,
                            "SELECT credit_id, tenant_id, service_period, credit_percent, amount_minor, currency, stripe_customer_id, status, idempotency_key, attempts, created_at_ms FROM sla_credit_ledger WHERE tenant_id = ? AND service_period = ?",
                            [tenant_id, period])
        if ledger.get("status") != "pending" or ledger.get("attempts") != 0 or ledger.get("stripe_customer_id") is not None:
            raise OperatorError("gate-false scheduled sweep did not leave one unapplied local credit")
        measurement = _query_one(cf, database_id,
                                 "SELECT eligible_at_ms, state, decision_reason, credit_percent, amount_minor FROM sla_monthly_measurements WHERE tenant_id = ? AND service_period = ?",
                                 [tenant_id, period])
        observation_row = _query_one(cf, database_id,
                                     "SELECT cutoff_at_ms, observed_at_ms FROM sla_monthly_observations WHERE tenant_id = ? AND service_period = ?",
                                     [tenant_id, period])
        if (measurement.get("state") != "evaluated" or measurement.get("decision_reason") != "eligible"
                or measurement.get("credit_percent") != 5 or measurement.get("amount_minor") != 500
                or int(observation_row.get("cutoff_at_ms", 0)) <= 0
                or int(measurement.get("eligible_at_ms", 0)) != int(observation_row.get("cutoff_at_ms", -1))):
            raise OperatorError("canonical eligibility calculation did not produce the expected eligible test credit")
        if _stripe_invoiceitems(stripe, customer_id):
            raise OperatorError("gate-false sweep caused a Stripe invoice-item effect")
        receipt["credit"] = {
            "tenant_sha256": redacted_id(tenant_id), "customer_sha256": redacted_id(customer_id),
            "service_period": period, "tier": "starter", "monthly_fee_minor": 10000,
            "availability_percent": 99.49, "cutoff_at_ms": observation_row.get("cutoff_at_ms"),
            "observation_observed_at_ms": observation_row.get("observed_at_ms"),
            "sweep_observed_at_ms": observation_time_ms, "credit_percent": 5,
            "amount_minor": 500, "currency": "USD", "gate_false_provider_effects": 0,
        }

        # The only enabled calls are private scheduled previews in the approved
        # protected job; the persistent Worker remains gate-false and unscheduled.
        # Revalidate the exact current main again immediately before Stripe credit effects.
        assert_checkout(expected_sha)
        gate_true_session = _scheduled_preview(runtime=runtime, env=cloudflare_env, gate=True,
                                               observation=observation, customer_id=customer_id, tenant_id=tenant_id,
                                               preview_states=preview_states)
        receipt["private_invocations"].append({"gate": True, "session_sha256": gate_true_session,
                                                "persistent_worker_version_sha256": redacted_id(version),
                                                "canonical_source_sha": SOURCE_SHA, "operator_sha": head,
                                                "process_terminated": True,
                                                "result": "scheduled_http_200"})
        applied_rows = cf.query(database_id,
                                "SELECT credit_id, credit_percent, amount_minor, currency, stripe_customer_id, status, idempotency_key, provider_ref, attempts FROM sla_credit_ledger WHERE tenant_id = ? AND service_period = ?",
                                [tenant_id, period])
        if len(applied_rows) != 1:
            raise OperatorError("canonical sweep did not create exactly one ledger row")
        ledger = applied_rows[0]
        if ledger.get("status") != "applied" or ledger.get("credit_percent") != 5 or ledger.get("amount_minor") != 500 or ledger.get("stripe_customer_id") != customer_id:
            raise OperatorError("canonical Stripe credit did not apply the expected amount/customer")
        provider_ref = ledger.get("provider_ref")
        if not isinstance(provider_ref, str) or not provider_ref.startswith("ii_"):
            raise OperatorError("canonical ledger provider reference is missing")
        outbox = _query_one(cf, database_id,
                            "SELECT idempotency_key, status, provider_ref, payload_json FROM sla_credit_outbox WHERE credit_id = ?",
                            [credit_id])
        reconciliation = _query_one(cf, database_id,
                                    "SELECT provider_ref, status FROM sla_credit_reconciliation WHERE credit_id = ?",
                                    [credit_id])
        audits = cf.query(database_id,
                          "SELECT event_type, detail FROM sla_credit_audit_events WHERE credit_id = ? ORDER BY audit_id",
                          [credit_id])
        if (outbox.get("status") != "sent" or outbox.get("provider_ref") != provider_ref
                or reconciliation.get("provider_ref") != provider_ref or reconciliation.get("status") != "reconciled"
                or [row.get("event_type") for row in audits] != ["created", "applied"]):
            raise OperatorError("D1 outbox, reconciliation or audit history is incomplete")
        if outbox.get("idempotency_key") != ledger.get("idempotency_key"):
            raise OperatorError("canonical stable idempotency key differs between ledger and outbox")
        request_payload = json.loads(str(outbox.get("payload_json")))
        if (request_payload.get("credit_id") != credit_id or request_payload.get("stripe_customer_id") != customer_id
                or request_payload.get("amount_minor") != 500 or request_payload.get("service_period") != period):
            raise OperatorError("canonical outbox request does not match the owned test credit")
        provider_item = stripe.request("GET", f"/v1/invoiceitems/{urllib.parse.quote(provider_ref)}")
        owned.item_id = provider_ref
        item_metadata = provider_item.get("metadata", {})
        if (provider_item.get("id") != provider_ref or provider_item.get("livemode") is not False
                or provider_item.get("customer") != customer_id or provider_item.get("amount") != -500
                or provider_item.get("currency") != "usd" or item_metadata.get("credit_id") != credit_id
                or item_metadata.get("service_period") != period or item_metadata.get("credit_percent") != "5"):
            raise OperatorError("Stripe invoice item does not reconcile to canonical D1 credit")
        matching = [row for row in _stripe_invoiceitems(stripe, customer_id)
                    if row.get("metadata", {}).get("credit_id") == credit_id]
        if len(matching) != 1 or matching[0].get("id") != provider_ref:
            raise OperatorError("customer-scoped provider search did not prove one credit object")

        before_replay = _d1_counts(cf, database_id, tenant_id, period)
        replay_session = _with_fresh_main(expected_sha, _scheduled_preview,
                                          runtime=runtime, env=cloudflare_env, gate=True,
                                          observation=observation, customer_id=customer_id, tenant_id=tenant_id,
                                          preview_states=preview_states)
        receipt["private_invocations"].append({"gate": True, "replay": True, "session_sha256": replay_session,
                                                "persistent_worker_version_sha256": redacted_id(version),
                                                "canonical_source_sha": SOURCE_SHA, "operator_sha": head,
                                                "process_terminated": True,
                                                "result": "scheduled_http_200"})
        after_replay = _d1_counts(cf, database_id, tenant_id, period)
        replay_items = [row for row in _stripe_invoiceitems(stripe, customer_id)
                        if row.get("metadata", {}).get("credit_id") == credit_id]
        if before_replay != after_replay or len(replay_items) != 1:
            raise OperatorError("exact replay changed D1 counts or duplicated Stripe provider effects")
        receipt["replay"] = {"same_observation": True, "same_canonical_sweep": True,
                              "d1_counts_before": before_replay, "d1_counts_after": after_replay,
                              "provider_objects": 1, "stable_idempotency_key_sha256": redacted_id(str(ledger.get("idempotency_key")))}

        invoice = _with_fresh_main(expected_sha, stripe.request, "POST", "/v1/invoices", {
            "customer": customer_id, "currency": "usd", "auto_advance": "false",
            "pending_invoice_items_behavior": "include",
            "metadata[corelink_issue]": str(ISSUE), "metadata[corelink_run]": run_id,
        }, idem=f"corelink-i2568-{run_id}-next-invoice")
        owned.invoice_id = invoice.get("id") if isinstance(invoice.get("id"), str) else None
        if (not owned.invoice_id or invoice.get("customer") != customer_id or invoice.get("status") != "draft"
                or invoice.get("livemode") is not False or invoice.get("auto_advance") is not False
                or invoice.get("metadata", {}).get("corelink_issue") != str(ISSUE)
                or invoice.get("metadata", {}).get("corelink_run") != run_id):
            raise OperatorError("next invoice is not an owned nonadvancing Stripe test draft")
        lines = stripe.request("GET", f"/v1/invoices/{urllib.parse.quote(owned.invoice_id)}/lines?limit=100")
        line_rows = lines.get("data")
        invoice_credit_lines = []
        line_shapes: list[str] = []
        if isinstance(line_rows, list):
            for line in line_rows:
                if isinstance(line, dict):
                    linked_id, shape = invoice_item_from_line(line)
                    line_shapes.append(shape)
                    if linked_id == provider_ref:
                        invoice_credit_lines.append(line)
        if len(invoice_credit_lines) != 1 or invoice_credit_lines[0].get("amount") != -500:
            raise OperatorError("draft next invoice does not reconcile the exact credit once")
        receipt["invoice"] = {"invoice_sha256": redacted_id(owned.invoice_id), "status": "draft",
                               "auto_advance": False, "credit_line_count": 1,
                               "credit_line_amount_minor": -500, "provider_item_sha256": redacted_id(provider_ref),
                               "line_shape": sorted(set(line_shapes)),
                               "stripe_response_api_version": stripe.response_api_version}
        receipt["d1"]["row_counts"] = _d1_counts(cf, database_id, tenant_id, period)
        receipt["checks"].update({"gate_false_no_provider_effect": "pass", "canonical_credit_applied": "pass",
                                  "replay_singular": "pass", "next_invoice_reconciled": "pass"})
        receipt["status"] = "provider_proof_pass_cleanup_pending"
        receipt["timestamps_utc"]["provider_proof_complete"] = datetime.now(timezone.utc).isoformat()
        write_receipt(output, receipt)
        exit_code = 0
    except Exception as exc:
        receipt["status"] = "provider_operation_failed"
        receipt["required_act"] = str(exc) if isinstance(exc, OperatorError) else "inspect the bounded provider operation failure without exposing provider payloads"
    finally:
        # Save a restricted pre-cleanup receipt before deleting owned objects.
        if output.exists() and receipt.get("status") == "provider_proof_pass_cleanup_pending":
            receipt["cleanup"]["pre_cleanup_receipt_written"] = True
            try:
                write_receipt(output, receipt)
            except OSError:
                receipt["cleanup"]["pre_cleanup_receipt_written"] = False
        stripe_cleanup: dict[str, Any] = {"attempted": False, "succeeded": False, "absence_verified": False}
        if stripe is not None and owned is not None:
            stripe_cleanup["attempted"] = True
            all_ids = {"invoice": owned.invoice_id, "invoice_item": owned.item_id,
                       "customer": owned.customer_id}
            try:
                success = owned.cleanup()
            except Exception:
                success = False
                owned.cleanup_errors.append("owned Stripe test-object cleanup raised an unclassified failure")
            stripe_cleanup.update({
                "succeeded": success,
                "remaining_object_hashes": [redacted_id(value) for value in (owned.invoice_id, owned.item_id, owned.customer_id) if value],
                "errors": owned.cleanup_errors,
            })
            if success:
                try:
                    paths = [f"/v1/{kind}/{urllib.parse.quote(identifier)}" for kind, identifier in (
                        ("invoices", all_ids["invoice"]), ("invoiceitems", all_ids["invoice_item"]), ("customers", all_ids["customer"])
                    ) if identifier]
                    stripe_cleanup["absence_verified"] = all(stripe.absent(path) for path in paths)
                    if not stripe_cleanup["absence_verified"]:
                        stripe_cleanup["errors"].append("owned Stripe object absence verification failed")
                except OperatorError as exc:
                    stripe_cleanup["errors"].append(str(exc))
        cf_cleanup: dict[str, Any] = {"worker_deleted": False, "database_deleted": False,
                                      "worker_absent": False, "database_absent": False, "errors": []}
        if cf is not None and (database_id is not None or d1_create_attempted or worker_upload_attempted):
            try:
                cf_cleanup = _cleanup_cloudflare(
                    cf, database_id, d1_create_attempted=d1_create_attempted,
                    worker_upload_attempted=worker_upload_attempted,
                )
            except Exception:
                cf_cleanup["errors"].append("owned Cloudflare target cleanup raised an unclassified failure")
        receipt["cleanup"]["stripe_objects"] = stripe_cleanup
        receipt["cleanup"]["cloudflare_targets"] = cf_cleanup
        receipt["cleanup"]["gate_final"] = False
        receipt["cleanup"]["private_preview_sessions_terminated"] = (
            len(preview_states) == len(receipt["private_invocations"]) == 3
            and all(row.get("terminated") is True for row in preview_states)
            and all(row.get("process_terminated") is True for row in receipt["private_invocations"])
        )
        receipt["cleanup"]["credential_revocation"] = "root_action_required"
        if runtime is not None:
            try:
                shutil.rmtree(runtime, ignore_errors=False)
                receipt["cleanup"]["private_runtime_files_removed"] = not runtime.exists()
            except OSError:
                receipt["cleanup"]["private_runtime_files_removed"] = False
        else:
            receipt["cleanup"]["private_runtime_files_removed"] = True
        if capability_path is not None:
            try:
                capability_path.unlink(missing_ok=True)
            except OSError:
                receipt["cleanup"]["private_runtime_files_removed"] = False
            receipt["cleanup"]["private_runtime_files_removed"] = (
                receipt["cleanup"].get("private_runtime_files_removed") is True
                and not capability_path.exists()
            )
        receipt["cleanup"]["succeeded"] = bool(
            stripe_cleanup.get("attempted") and stripe_cleanup.get("succeeded") and stripe_cleanup.get("absence_verified")
            and cf_cleanup.get("worker_absent") and cf_cleanup.get("database_absent")
            and receipt["cleanup"].get("private_runtime_files_removed") is True
            and receipt["cleanup"].get("private_preview_sessions_terminated") is True
            and not cf_cleanup.get("errors")
        )
        if receipt["cleanup"]["succeeded"] and exit_code == 0:
            if _fresh_main_acceptance(receipt, expected_sha):
                receipt["status"] = "closure_ready_pending_root_credential_revocation"
            else:
                exit_code = 1
        elif receipt.get("status") == "provider_proof_pass_cleanup_pending":
            receipt["status"] = "cleanup_incomplete"
            exit_code = 1
        receipt["timestamps_utc"]["finished"] = datetime.now(timezone.utc).isoformat()
        try:
            write_receipt(output, receipt)
        except Exception:
            exit_code = 1
    return exit_code


class OwnedStripeObjects:
    """Track each created object immediately and reconcile only this run's refs."""

    def __init__(self, stripe: Stripe, run_id: str):
        self.stripe = stripe
        self.run_id = run_id
        self.customer_id: str | None = None
        self.item_id: str | None = None
        self.invoice_id: str | None = None
        self.credit_id: str | None = None
        self.cleanup_errors: list[str] = []

    def _search_owned(self, resource: str) -> list[dict[str, Any]]:
        # A unique metadata predicate restricts recovery to this invocation.
        query = f"metadata['corelink_issue']:'{ISSUE}' AND metadata['corelink_run']:'{self.run_id}'"
        payload = self.stripe.request("GET", f"/v1/{resource}/search?" + urllib.parse.urlencode({"query": query, "limit": "10"}))
        data = payload.get("data")
        if not isinstance(data, list) or payload.get("has_more") is True:
            raise OperatorError(f"Stripe owned-object recovery for {resource} was ambiguous")
        return [row for row in data if isinstance(row, dict)]

    def recover_unknown_ids(self) -> None:
        if self.customer_id is None:
            rows = self._search_owned("customers")
            if len(rows) > 1:
                raise OperatorError("multiple run-owned customers require manual cleanup")
            if rows:
                self.customer_id = rows[0].get("id")
        # Items and invoices are scoped to the exact owned customer. Never scan
        # account-wide objects or delete by an inferred/global result.
        if not self.customer_id:
            return
        for kind in ("invoiceitems", "invoices"):
            if kind == "invoiceitems" and self.item_id is None:
                path = "/v1/invoiceitems?" + urllib.parse.urlencode({"customer": self.customer_id, "limit": "100"})
            elif kind == "invoices" and self.invoice_id is None:
                path = "/v1/invoices?" + urllib.parse.urlencode({"customer": self.customer_id, "status": "draft", "limit": "100"})
            else:
                continue
            payload = self.stripe.request("GET", path)
            rows = payload.get("data")
            if not isinstance(rows, list) or payload.get("has_more") is True:
                raise OperatorError(f"Stripe scoped {kind} cleanup lookup was ambiguous")
            owned = [r for r in rows if isinstance(r, dict) and (
                r.get("metadata", {}).get("corelink_run") == self.run_id
                or (kind == "invoiceitems" and self.credit_id and r.get("metadata", {}).get("credit_id") == self.credit_id)
            )]
            if len(owned) > 1:
                raise OperatorError(f"multiple run-owned {kind} require manual cleanup")
            if owned:
                if kind == "invoiceitems":
                    self.item_id = owned[0].get("id")
                else:
                    self.invoice_id = owned[0].get("id")

    def cleanup(self) -> bool:
        try:
            self.recover_unknown_ids()
        except OperatorError as exc:
            self.cleanup_errors.append(str(exc))
        if self.invoice_id:
            try:
                invoice = self.stripe.request("GET", f"/v1/invoices/{urllib.parse.quote(self.invoice_id)}")
                metadata = invoice.get("metadata", {})
                if (invoice.get("status") != "draft" or invoice.get("livemode") is not False
                        or invoice.get("customer") != self.customer_id
                        or metadata.get("corelink_issue") != str(ISSUE)
                        or metadata.get("corelink_run") != self.run_id):
                    raise OperatorError("owned invoice is not a test-mode draft; refusing deletion")
                self.stripe.request("DELETE", f"/v1/invoices/{urllib.parse.quote(self.invoice_id)}")
                self.invoice_id = None
            except OperatorError as exc:
                self.cleanup_errors.append(str(exc))
        if self.item_id:
            try:
                item = self.stripe.request("GET", f"/v1/invoiceitems/{urllib.parse.quote(self.item_id)}")
                metadata = item.get("metadata", {})
                if (item.get("customer") != self.customer_id or item.get("livemode") is not False
                        or not (metadata.get("corelink_run") == self.run_id
                                or (self.credit_id and metadata.get("credit_id") == self.credit_id))):
                    raise OperatorError("invoice item ownership/mode mismatch; refusing deletion")
                self.stripe.request("DELETE", f"/v1/invoiceitems/{urllib.parse.quote(self.item_id)}")
                self.item_id = None
            except OperatorError as exc:
                self.cleanup_errors.append(str(exc))
        if self.customer_id and not self.invoice_id and not self.item_id:
            try:
                customer = self.stripe.request("GET", f"/v1/customers/{urllib.parse.quote(self.customer_id)}")
                if customer.get("metadata", {}).get("corelink_run") != self.run_id or customer.get("livemode") is not False:
                    raise OperatorError("customer ownership/mode mismatch; refusing deletion")
                self.stripe.request("DELETE", f"/v1/customers/{urllib.parse.quote(self.customer_id)}")
                self.customer_id = None
            except OperatorError as exc:
                self.cleanup_errors.append(str(exc))
        return not self.cleanup_errors and not any((self.invoice_id, self.item_id, self.customer_id))


def run_capability_probe(*, expected_sha: str, run_id: str, confirmation: str, output: Path) -> int:
    receipt: dict[str, Any] = {
        "schema": "corelink.issue-2568.sla-credit-real.v1", "issue": ISSUE,
        "mode": "test", "phase": "stripe_capability_probe", "candidate_sha": None,
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "provider_effects": [],
        "checks": {}, "cleanup": {"attempted": False, "succeeded": False},
        "redacted": True,
    }
    objects: OwnedStripeObjects | None = None
    rc = 1
    try:
        if confirmation != CONFIRMATION:
            raise OperatorError("explicit #2568 test-mode confirmation is missing")
        head = assert_checkout(expected_sha)
        receipt["candidate_sha"] = head
        if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", run_id):
            raise OperatorError("run_id is missing or malformed")
        account_binding = os.environ.get("STRIPE_TEST_ACCOUNT_ID", "")
        validate_account_binding(account_binding)
        key = os.environ.get("STRIPE_SECRET_KEY", "")
        validate_restricted_key(key)
        stripe = Stripe(key)
        account = stripe.request("GET", "/v1/account")
        if account.get("object") != "account" or account.get("id") != account_binding:
            raise OperatorError("Stripe account identity differs from the exact protected binding")
        receipt["checks"]["stripe_account_binding"] = "pass"
        receipt["stripe_response_api_version"] = stripe.response_api_version
        receipt["stripe_account_id"] = redacted_id(account.get("id"))
        receipt["stripe_account_id_sha256"] = sha256(account_binding.encode())
        receipt["checks"]["restricted_test_key_prefix"] = "pass"
        objects = OwnedStripeObjects(stripe, run_id)
        metadata = {"metadata[corelink_issue]": str(ISSUE), "metadata[corelink_run]": run_id}

        customer = stripe.request("POST", "/v1/customers", {
            "description": f"CoreLink #2568 test {run_id}", **metadata,
        }, idem=f"corelink-i2568-{run_id}-customer")
        # Record the ID before validating any other response field so cleanup
        # still knows the exact returned object on a partial/invalid response.
        objects.customer_id = customer.get("id") if isinstance(customer.get("id"), str) else None
        receipt["provider_effects"].append("owned_test_customer_created")
        if (not objects.customer_id or not objects.customer_id.startswith("cus_") or customer.get("livemode") is not False
                or customer.get("metadata", {}).get("corelink_issue") != str(ISSUE)
                or customer.get("metadata", {}).get("corelink_run") != run_id):
            raise OperatorError("Stripe customer create did not prove test-mode ownership")

        item = stripe.request("POST", "/v1/invoiceitems", {
            "customer": objects.customer_id, "amount": "-1", "currency": "usd",
            "description": "CoreLink #2568 bounded test capability item", **metadata,
        }, idem=f"corelink-i2568-{run_id}-invoiceitem")
        objects.item_id = item.get("id") if isinstance(item.get("id"), str) else None
        receipt["provider_effects"].append("owned_negative_one_usd_minor_invoice_item_created")
        if (not objects.item_id or item.get("customer") != objects.customer_id or item.get("amount") != -1
                or item.get("currency") != "usd" or item.get("livemode") is not False
                or item.get("metadata", {}).get("corelink_issue") != str(ISSUE)
                or item.get("metadata", {}).get("corelink_run") != run_id):
            raise OperatorError("Stripe invoice item did not match the bounded capability probe")

        invoice = stripe.request("POST", "/v1/invoices", {
            "customer": objects.customer_id, "currency": "usd", "auto_advance": "false",
            "pending_invoice_items_behavior": "include", **metadata,
        }, idem=f"corelink-i2568-{run_id}-draft-invoice")
        objects.invoice_id = invoice.get("id") if isinstance(invoice.get("id"), str) else None
        receipt["provider_effects"].append("owned_nonadvancing_draft_invoice_created")
        if (not objects.invoice_id or invoice.get("customer") != objects.customer_id or invoice.get("status") != "draft"
                or invoice.get("livemode") is not False or invoice.get("auto_advance") is not False
                or invoice.get("metadata", {}).get("corelink_issue") != str(ISSUE)
                or invoice.get("metadata", {}).get("corelink_run") != run_id):
            raise OperatorError("Stripe invoice was not the owned test-mode nonadvancing draft")
        lines = stripe.request("GET", f"/v1/invoices/{urllib.parse.quote(objects.invoice_id)}/lines?limit=100")
        data = lines.get("data")
        matches = []
        line_shapes = []
        if isinstance(data, list):
            for line in data:
                if isinstance(line, dict):
                    linked_id, shape = invoice_item_from_line(line)
                    line_shapes.append(shape)
                    if linked_id == objects.item_id:
                        matches.append(line)
        if len(matches) != 1:
            raise OperatorError("draft invoice did not contain the exact owned pending invoice item once")
        receipt["checks"]["owned_pending_item_included_once"] = "pass"
        receipt["invoice_line_shape"] = sorted(set(line_shapes))
        receipt["customer"] = redacted_id(objects.customer_id)
        receipt["invoice_item"] = redacted_id(objects.item_id)
        receipt["draft_invoice"] = redacted_id(objects.invoice_id)
        rc = 0
    except OperatorError as exc:
        receipt["failure"] = str(exc)
        receipt["required_act"] = str(exc)
    except Exception:
        receipt["failure"] = "unclassified_provider_failure"
        receipt["required_act"] = "inspect the redacted provider failure and reconcile only this run's owned objects"
    finally:
        if objects is not None:
            receipt["cleanup"]["attempted"] = True
            original_ids = (objects.invoice_id, objects.item_id, objects.customer_id)
            try:
                succeeded = objects.cleanup()
            except Exception:
                succeeded = False
                objects.cleanup_errors.append("owned Stripe test-object cleanup raised an unclassified failure")
            absence = False
            if succeeded:
                try:
                    paths = [f"/v1/{kind}/{urllib.parse.quote(identifier)}" for kind, identifier in (
                        ("invoices", original_ids[0]), ("invoiceitems", original_ids[1]), ("customers", original_ids[2])
                    ) if identifier]
                    absence = all(objects.stripe.absent(path) for path in paths)
                    succeeded = absence
                except OperatorError as exc:
                    objects.cleanup_errors.append(str(exc))
            receipt["cleanup"].update({
                "succeeded": succeeded,
                "absence_verified": absence,
                "remaining_owned_ids": [redacted_id(x) for x in (objects.invoice_id, objects.item_id, objects.customer_id) if x],
                "errors": objects.cleanup_errors,
            })
            if not succeeded:
                receipt["required_act"] = "complete only the listed run-owned test-object cleanup before retry"
                rc = 1
        receipt["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        try:
            write_receipt(output, receipt)
        except OSError:
            rc = 1
    return rc


def verify_source_checkout(source_root: Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    for relative, expected in SOURCE_DIGESTS.items():
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            raise OperatorError(f"canonical source path missing or unsafe: {relative}")
        actual = sha256(path.read_bytes())
        if actual != expected:
            raise OperatorError(f"canonical source digest drift: {relative}")
        observed[relative] = actual
    return observed


def verify_wrapper_bundle(source_root: Path, candidate_root: Path) -> None:
    source_root = source_root.resolve()
    source_head = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                                          text=True, stderr=subprocess.DEVNULL).strip()
    if source_head != SOURCE_SHA:
        raise OperatorError("canonical source checkout is not the frozen baseline")
    verify_source_checkout(source_root)
    runtime = Path(tempfile.mkdtemp(prefix=".i2568-wrapper-check-", dir=candidate_root.resolve()))
    runtime.chmod(0o700)
    try:
        _prepare_worker_tree(runtime, candidate_root.resolve(), source_root, "11111111-2222-4333-8444-555555555555")
        _safe_wrangler(["deploy", "--dry-run", "--config", str(runtime / "wrangler.toml")],
                       cwd=runtime, env={**os.environ, "NO_COLOR": "1", "CI": "1"})
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


def contract_check(root: Path) -> list[str]:
    errors: list[str] = []
    expected = {
        ".github/workflows/issue-2568-sla-credit-real.yml",
        "scripts/issue_2568_sla_credit_real.py",
        "scripts/verify_issue_2568_sla_credit_real.py",
        "scripts/issue_2568_sla_credit_worker.ts",
        "tests/test_issue_2568_sla_credit_real.py",
    }
    for relative in sorted(expected):
        if not (root / relative).is_file():
            errors.append(f"missing frozen path {relative}")
    if SOURCE_SHA != "5fabd93e98d805a39319fcb6a22c9ee5267fafd4":
        errors.append("frozen source SHA drift")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    contract = sub.add_parser("contract")
    contract.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    probe = sub.add_parser("capability-probe")
    probe.add_argument("--expected-sha", required=True)
    probe.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    probe.add_argument("--confirmation", default=os.environ.get("I2568_CONFIRMATION", ""))
    probe.add_argument("--output", type=Path, required=True)
    source = sub.add_parser("verify-source")
    source.add_argument("--source-root", type=Path, required=True)
    wrapper = sub.add_parser("verify-wrapper")
    wrapper.add_argument("--source-root", type=Path, required=True)
    operation = sub.add_parser("run-all")
    operation.add_argument("--expected-sha", required=True)
    operation.add_argument("--run-id", required=True)
    operation.add_argument("--source-root", type=Path, required=True)
    operation.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "contract":
            errors = contract_check(args.root.resolve())
            if errors:
                for error in errors:
                    print(f"FAIL: {error}", file=sys.stderr)
                return 1
            print("#2568 operator contract: PASS")
            return 0
        if args.command == "verify-source":
            source_head = subprocess.check_output(["git", "-C", str(args.source_root.resolve()), "rev-parse", "HEAD"],
                                                  text=True, stderr=subprocess.DEVNULL).strip()
            if source_head != SOURCE_SHA:
                raise OperatorError("canonical source checkout is not the frozen baseline")
            verify_source_checkout(args.source_root.resolve())
            print("#2568 frozen canonical source: PASS")
            return 0
        if args.command == "verify-wrapper":
            verify_wrapper_bundle(args.source_root, Path(__file__).resolve().parents[1])
            print("#2568 private Worker wrapper bundle: PASS")
            return 0
        if args.command == "capability-probe":
            return run_capability_probe(expected_sha=args.expected_sha, run_id=args.run_id,
                                        confirmation=args.confirmation, output=args.output)
        return run_all(expected_sha=args.expected_sha, run_id=args.run_id,
                       confirmation=os.environ.get("I2568_CONFIRMATION", ""),
                       source_root=args.source_root, output=args.output)
    except OperatorError as exc:
        print(f"#2568 operator: FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("#2568 operator: FAIL: unclassified private operation error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
