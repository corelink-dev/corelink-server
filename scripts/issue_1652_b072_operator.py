#!/usr/bin/env python3
"""Protected, one-shot-only B-072 staging operator and recovery path.

This file is credentialless during PR CI. Provider access is possible only from
the exact protected main workflow after a GitHub environment approval, exact
#1700 machine PASS evidence, and staging-only scoped credentials are verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Callable

REPOSITORY = "HuGR-dev/corelink-server"
REPOSITORY_ID = 1232040291
MAIN_REF = "refs/heads/main"
STAGING_ENVIRONMENT = "staging"
ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
STAGING_D1_ID = "d72a6b39-6a48-4338-bfda-1111dda98604"
ROOT_WORKER = "corelink-staging"
RECEIVER_WORKER = "corelink-synthetic-pager-staging"
ONE_SHOT_CRON = "* * * * *"
MIGRATION = Path("migrations/d1/0153_b072_one_shot_fence.sql")
REQUIRED_SCHEMA_OBJECTS = {
    "b072_one_shot_migration_receipt", "b072_one_shot_authorization",
    "b072_one_shot_activation", "b072_one_shot_revocation",
    "b072_one_shot_claim", "b072_one_shot_ingress",
    "b072_one_shot_migration_receipt_no_update", "b072_one_shot_migration_receipt_no_delete",
    "b072_one_shot_authorization_no_update", "b072_one_shot_authorization_no_delete",
    "b072_one_shot_activation_no_update", "b072_one_shot_activation_no_delete",
    "b072_one_shot_activation_validate", "b072_one_shot_revocation_no_update",
    "b072_one_shot_revocation_no_delete", "b072_one_shot_revocation_validate",
    "b072_one_shot_claim_no_update", "b072_one_shot_claim_no_delete", "b072_one_shot_claim_validate",
    "b072_one_shot_ingress_update_once", "b072_one_shot_ingress_no_delete",
}
TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 12 * 1024 * 1024


class OperatorError(RuntimeError):
    """A fail-closed, non-sensitive operator error."""


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_main_identity(environ: dict[str, str], *, api_main_sha: str, local_head: str) -> str:
    sha = environ.get("GITHUB_SHA", "")
    if (environ.get("GITHUB_REPOSITORY") != REPOSITORY or
            environ.get("GITHUB_REPOSITORY_ID") != str(REPOSITORY_ID) or
            environ.get("GITHUB_REF") != MAIN_REF or not re.fullmatch(r"[0-9a-f]{40}", sha) or
            local_head != sha or api_main_sha != sha):
        raise OperatorError("operator requires the exact current protected main SHA in HuGR-dev/corelink-server")
    return sha


def require_scoped_credentials(environ: dict[str, str]) -> tuple[str, str, str]:
    workers = environ.get("B072_STAGING_CF_WORKERS_TOKEN", "")
    d1_write = environ.get("B072_STAGING_D1_WRITE_TOKEN", "")
    route_read = environ.get("B072_STAGING_CF_ROUTE_READ_TOKEN", "")
    if not workers:
        raise OperatorError("setup required: provision B072_STAGING_CF_WORKERS_TOKEN scoped to the staging Worker account")
    if not d1_write:
        raise OperatorError("setup required: provision B072_STAGING_D1_WRITE_TOKEN scoped to the fixed staging D1 database")
    if not route_read:
        raise OperatorError("setup required: provision B072_STAGING_CF_ROUTE_READ_TOKEN scoped to staging zone route read")
    if len({workers, d1_write, route_read}) != 3:
        raise OperatorError("staging Worker, D1 write and route-read credentials must be separately scoped tokens")
    if environ.get("B072_STAGING_CF_ACCOUNT_ID") != ACCOUNT_ID:
        raise OperatorError("setup required: B072_STAGING_CF_ACCOUNT_ID must identify the frozen staging account")
    if environ.get("B072_STAGING_D1_DATABASE_ID") != STAGING_D1_ID:
        raise OperatorError("setup required: B072_STAGING_D1_DATABASE_ID must identify the frozen staging D1 database")
    if environ.get("CF_API_TOKEN") or environ.get("CLOUDFLARE_API_TOKEN"):
        raise OperatorError("generic Cloudflare credentials are forbidden in the B-072 operator environment")
    return workers, d1_write, route_read


def approved_environment_review(approvals: list[dict[str, Any]], *, run_id: int,
                                actor: str, environment: str = STAGING_ENVIRONMENT,
                                observed_at: datetime | None = None) -> dict[str, Any]:
    observed_at = observed_at or datetime.now(timezone.utc)
    for approval in approvals:
        if approval.get("state") != "approved":
            continue
        reviewer = approval.get("user")
        envs = approval.get("environments")
        if not isinstance(reviewer, dict) or not isinstance(envs, list):
            continue
        login = reviewer.get("login")
        reviewer_id = reviewer.get("id")
        if (not isinstance(login, str) or not login or login.casefold() == actor.casefold() or
                not isinstance(reviewer_id, int)):
            continue
        for item in envs:
            if isinstance(item, dict) and item.get("name") == environment:
                return {"reviewer_login": login, "reviewer_id": reviewer_id,
                        "environment": environment,
                        "run_id": run_id, "approval_observed_at": observed_at.astimezone(timezone.utc).isoformat()}
    raise OperatorError("no independent GitHub staging environment approval is attached to this run")


def require_configured_independent_approver(reviewers: list[dict[str, Any]], actor: str,
                                           approval: dict[str, Any]) -> None:
    eligible_ids: set[int] = set()
    for entry in reviewers:
        reviewer = entry.get("reviewer")
        login = reviewer.get("login") if isinstance(reviewer, dict) else None
        reviewer_id = reviewer.get("id") if isinstance(reviewer, dict) else None
        if isinstance(reviewer_id, int) and isinstance(login, str) and login.casefold() != actor.casefold():
            eligible_ids.add(reviewer_id)
    if not eligible_ids:
        raise OperatorError("existing staging environment lacks an independent required reviewer")
    approver = approval.get("reviewer_login")
    if approval.get("reviewer_id") not in eligible_ids or not isinstance(approver, str) or \
            approver.casefold() == actor.casefold():
        raise OperatorError("the actual staging approver is not an independent configured reviewer")


def verify_1700_receipt(run: dict[str, Any], artifact: dict[str, Any], receipt: dict[str, Any],
                        *, expected_run_id: int, expected_sha: str, expected_verification_sha: str) -> dict[str, Any]:
    if (not re.fullmatch(r"[0-9a-f]{40}", expected_verification_sha) or
            run.get("id") != expected_run_id or run.get("head_branch") != "main" or
            run.get("head_sha") != expected_verification_sha or run.get("event") != "workflow_dispatch" or
            run.get("status") != "completed" or run.get("conclusion") != "success" or
            not str(run.get("path", "")).startswith(".github/workflows/issue-1700-container-staging-deploy.yml@")):
        raise OperatorError("#1700 run is not a successful exact-main protected completion run")
    if (artifact.get("workflow_run", {}).get("id") != expected_run_id or
            artifact.get("expired") is True or
            artifact.get("name") != f"issue-1700-existing-completion-{expected_run_id}"):
        raise OperatorError("#1700 terminal completion artifact is absent, expired, or bound to another run")
    runtime = receipt.get("runtime")
    native = runtime.get("receipt") if isinstance(runtime, dict) else None
    after = receipt.get("after")
    before = receipt.get("before")
    if (receipt.get("contract") != "issue-1700-existing-runtime-completion-v1" or
            receipt.get("outcome") != "pass" or receipt.get("verification_sha") != expected_verification_sha or
            run.get("head_sha") != expected_verification_sha or
            not isinstance(runtime, dict) or runtime.get("contract") != "corelink-staging-runtime-deployment-proof-v1" or
            runtime.get("schedule_restored_empty") is not True or runtime.get("tail_deleted") is not True or
            not isinstance(native, dict) or native.get("contract") != "corelink-staging-d1-binding-runtime-v1" or
            native.get("outcome") != "pass" or native.get("probe_table_dropped") is not True or
            native.get("rollback_absence_verified") is not True or
            not isinstance(before, dict) or before.get("schedules_empty") is not True or
            not isinstance(after, dict) or after.get("schedules_empty") is not True or
            after.get("tails_empty") is not True):
        raise OperatorError("#1700 artifact does not contain exact runtime PASS plus cleanup/readback")
    return {"run_id": expected_run_id, "run_sha": expected_verification_sha,
            "b072_sha": expected_sha, "outcome": "pass",
            "artifact_id": artifact.get("id"), "contract": receipt["contract"]}


def _read_json(response: Any, *, expected: type = dict) -> Any:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OperatorError("bounded operator response exceeded its size limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OperatorError("operator target returned an invalid response") from error
    if not isinstance(value, expected):
        raise OperatorError("operator target returned an unexpected JSON shape")
    return value


class GitHub:
    def __init__(self, token: str, request: Callable[..., Any] | None = None):
        if not token:
            raise OperatorError("GitHub Actions token is unavailable for approval and artifact verification")
        self.token = token
        self._request = request or urllib.request.urlopen

    def get(self, path: str, *, expected: type = dict) -> Any:
        req = urllib.request.Request("https://api.github.com/repos/" + REPOSITORY + "/" + path,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2026-03-10"})
        try:
            with self._request(req, timeout=TIMEOUT_SECONDS) as response:
                return _read_json(response, expected=expected)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise OperatorError("GitHub approval or artifact read was unavailable") from error

    def main_sha(self) -> str:
        value = self.get("git/ref/heads/main")
        sha = value.get("object", {}).get("sha")
        if not isinstance(sha, str):
            raise OperatorError("current main SHA is unavailable from GitHub")
        return sha

    def environment(self) -> dict[str, Any]:
        return self.get("environments/staging")

    def approval(self, run_id: int, actor: str) -> dict[str, Any]:
        run = self.get(f"actions/runs/{run_id}")
        if (run.get("id") != run_id or run.get("repository", {}).get("id") != REPOSITORY_ID or
                run.get("head_sha") != os.environ.get("GITHUB_SHA") or
                run.get("head_branch") != "main" or run.get("event") != "workflow_dispatch" or
                run.get("status") != "in_progress"):
            raise OperatorError("operator run identity is not an exact current-main workflow dispatch")
        approvals = self.get(f"actions/runs/{run_id}/approvals", expected=list)
        if not isinstance(approvals, list):
            raise OperatorError("GitHub did not return workflow-run approval history")
        return approved_environment_review(approvals, run_id=run_id, actor=actor)

    def issue_1700_pass(self, run_id: int, sha: str, verification_sha: str) -> dict[str, Any]:
        run = self.get(f"actions/runs/{run_id}")
        artifacts = self.get(f"actions/runs/{run_id}/artifacts").get("artifacts")
        if not isinstance(artifacts, list):
            raise OperatorError("#1700 completion artifact listing is unavailable")
        wanted = [a for a in artifacts if isinstance(a, dict) and
                  a.get("name") == f"issue-1700-existing-completion-{run_id}"]
        if len(wanted) != 1:
            raise OperatorError("#1700 terminal PASS artifact is missing or ambiguous")
        artifact = wanted[0]
        metadata = artifact
        api_url = artifact.get("archive_download_url")
        if not isinstance(api_url, str) or not api_url.startswith("https://api.github.com/repos/"):
            raise OperatorError("#1700 artifact download URL is not an allowed GitHub API URL")
        request = urllib.request.Request(api_url, headers={"Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json"})
        try:
            with self._request(request, timeout=TIMEOUT_SECONDS) as response:
                archive = response.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise OperatorError("#1700 completion artifact download failed") from error
        if len(archive) > MAX_RESPONSE_BYTES:
            raise OperatorError("#1700 completion artifact exceeded its bounded size")
        try:
            with zipfile.ZipFile(BytesIO(archive)) as bundle:
                names = [name for name in bundle.namelist() if name.endswith("issue-1700-completion-receipt.json")]
                if len(names) != 1:
                    raise OperatorError("#1700 artifact has no unique completion receipt")
                receipt = json.loads(bundle.read(names[0]))
        except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
            raise OperatorError("#1700 artifact receipt is malformed") from error
        if not isinstance(receipt, dict):
            raise OperatorError("#1700 artifact receipt is not a JSON object")
        return verify_1700_receipt(run, metadata, receipt, expected_run_id=run_id,
                                   expected_sha=sha, expected_verification_sha=verification_sha)


class Cloudflare:
    def __init__(self, account: str, token: str, request: Callable[..., Any] | None = None):
        if account != ACCOUNT_ID or not token:
            raise OperatorError("Cloudflare staging account/credential preflight failed")
        self.account = account
        self.token = token
        self._request = request or urllib.request.urlopen

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        if not path.startswith(f"/accounts/{ACCOUNT_ID}/"):
            raise OperatorError("Cloudflare path escaped the fixed staging account")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                     **({"Content-Type": "application/json"} if data is not None else {})})
        try:
            with self._request(req, timeout=TIMEOUT_SECONDS) as response:
                value = _read_json(response)
        except urllib.error.HTTPError as error:
            raise OperatorError(f"Cloudflare {method} staging read/write returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise OperatorError(f"Cloudflare {method} staging read/write has unknown state") from error
        if value.get("success") is not True:
            raise OperatorError(f"Cloudflare {method} staging response was not successful")
        return value

    def d1(self, database_id: str, token: str, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        if database_id != STAGING_D1_ID or not token:
            raise OperatorError("D1 query is not bound to the fixed staging database")
        data = json.dumps({"sql": sql, "params": params or []}).encode()
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{STAGING_D1_ID}/query",
            data=data, method="POST", headers={"Authorization": "Bearer " + token,
                "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with self._request(req, timeout=TIMEOUT_SECONDS) as response:
                result = _read_json(response)
        except urllib.error.HTTPError as error:
            raise OperatorError(f"Cloudflare staging D1 query returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise OperatorError("Cloudflare staging D1 query has unknown state") from error
        if result.get("success") is not True or not isinstance(result.get("result"), list):
            raise OperatorError("Cloudflare staging D1 query result was not successful")
        rows: list[dict[str, Any]] = []
        for item in result["result"]:
            if not isinstance(item, dict) or item.get("success") is False:
                raise OperatorError("Cloudflare staging D1 statement failed")
            result_rows = item.get("results", [])
            if not isinstance(result_rows, list) or any(not isinstance(row, dict) for row in result_rows):
                raise OperatorError("Cloudflare staging D1 query returned malformed rows")
            rows.extend(result_rows)
        return rows

    def zone_route_inventory(self) -> list[dict[str, Any]]:
        zones = self.call_global("GET", "/zones?name=humangr.com&per_page=50")
        rows = zones.get("result")
        info = zones.get("result_info")
        if (not isinstance(rows, list) or len(rows) != 1 or rows[0].get("name") != "humangr.com" or
                not isinstance(info, dict) or info.get("total_pages") != 1):
            raise OperatorError("staging zone route preflight did not resolve one exact zone")
        zone_id = rows[0].get("id")
        if not isinstance(zone_id, str) or not re.fullmatch(r"[0-9a-f]{32}", zone_id):
            raise OperatorError("staging zone route preflight returned an invalid zone id")
        routes: list[dict[str, Any]] = []
        page = 1
        while True:
            payload = self.call_global("GET", f"/zones/{zone_id}/workers/routes?page={page}&per_page=100")
            batch, page_info = payload.get("result"), payload.get("result_info")
            if not isinstance(batch, list) or any(not isinstance(route, dict) for route in batch) or \
                    not isinstance(page_info, dict) or type(page_info.get("total_pages")) is not int or \
                    not 1 <= page_info["total_pages"] <= 20:
                raise OperatorError("staging zone route inventory is malformed or unbounded")
            routes.extend(batch)
            if page >= page_info["total_pages"]:
                break
            page += 1
        return routes

    def call_global(self, method: str, path: str) -> dict[str, Any]:
        if not (path == "/zones?name=humangr.com&per_page=50" or
                re.fullmatch(r"/zones/[0-9a-f]{32}/workers/routes\?page=[1-9][0-9]*&per_page=100", path)):
            raise OperatorError("Cloudflare global read escaped the fixed staging route inventory")
        req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path,
            method=method, headers={"Authorization": "Bearer " + self.token,
                                    "Accept": "application/json"})
        try:
            with self._request(req, timeout=TIMEOUT_SECONDS) as response:
                value = _read_json(response)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise OperatorError("staging zone route readback failed") from error
        if value.get("success") is not True:
            raise OperatorError("staging zone route readback was not successful")
        return value


def _result(value: dict[str, Any]) -> Any:
    result = value.get("result")
    if result is None:
        raise OperatorError("Cloudflare staging Worker readback is missing result")
    return result


def version_plain_vars(version: Any) -> dict[str, Any]:
    result = version.get("result") if isinstance(version, dict) else None
    resources = result.get("resources") if isinstance(result, dict) else None
    bindings = resources.get("bindings") if isinstance(resources, dict) else None
    if not isinstance(bindings, list):
        raise OperatorError("Worker active-version binding metadata is unavailable")
    return {item["name"]: item.get("text") for item in bindings if isinstance(item, dict)
            and item.get("type") == "plain_text" and isinstance(item.get("name"), str)}


def active_version(deployments: Any) -> str:
    rows = deployments.get("result") if isinstance(deployments, dict) else None
    if isinstance(rows, dict):
        rows = rows.get("items", rows.get("deployments"))
    if not isinstance(rows, list) or not rows:
        raise OperatorError("active Worker deployment could not be proven")
    versions = rows[0].get("versions") if isinstance(rows[0], dict) else None
    if not isinstance(versions, list) or len(versions) != 1 or versions[0].get("percentage") != 100:
        raise OperatorError("Worker does not have one exact 100 percent active version")
    version = versions[0].get("version_id")
    if not isinstance(version, str) or not version:
        raise OperatorError("active Worker version id is missing")
    return version


def exact_crons(response: dict[str, Any]) -> list[str]:
    rows = _result(response)
    schedules = rows.get("schedules") if isinstance(rows, dict) else None
    if not isinstance(schedules, list) or any(not isinstance(item, dict) or not isinstance(item.get("cron"), str) for item in schedules):
        raise OperatorError("Worker schedule readback is malformed")
    return [item["cron"] for item in schedules]


def worker_preflight(cf: Cloudflare, route_cf: Cloudflare, sha: str, root_version: str, receiver_version: str) -> dict[str, Any]:
    root_deployment = cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/deployments")
    receiver_deployment = cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/deployments")
    root_active = active_version(root_deployment)
    receiver_active = active_version(receiver_deployment)
    if root_active != root_version or receiver_active != receiver_version:
        raise OperatorError("root/receiver active version differs from the explicitly reviewed preimage")
    root_resources = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/versions/{root_active}"))
    receiver_resources = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/versions/{receiver_active}"))
    root_bindings = root_resources.get("resources", {}).get("bindings") if isinstance(root_resources, dict) else None
    receiver_bindings = receiver_resources.get("resources", {}).get("bindings") if isinstance(receiver_resources, dict) else None
    def plain_vars(bindings: Any) -> dict[str, Any]:
        if not isinstance(bindings, list):
            return {}
        return {item["name"]: item.get("text") for item in bindings if isinstance(item, dict)
                and item.get("type") == "plain_text" and isinstance(item.get("name"), str)}
    root_schedules = exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules"))
    if root_schedules != []:
        raise OperatorError("root staging schedules are not empty; refusing to overwrite drift")
    root_vars = plain_vars(root_bindings)
    if root_vars.get("ENVIRONMENT") != "staging" or \
            root_vars.get("SYNTHETIC_DRILL_PROVIDER_MODE") != "provider_deferred" or root_vars.get("SENTRY_RELEASE") != sha:
        raise OperatorError("root staging version is not the exact serving SHA in provider_deferred staging mode")
    receiver_vars = plain_vars(receiver_bindings)
    if receiver_vars.get("ENVIRONMENT") != "staging" or \
            receiver_vars.get("SYNTHETIC_DRILL_ENABLED") != "false" or \
            receiver_vars.get("SYNTHETIC_DRILL_PROVIDER_MODE") != "provider_deferred":
        raise OperatorError("receiver staging disabled preimage/provider mode is not exact")
    service = [b for b in root_bindings or [] if isinstance(b, dict) and b.get("type") == "service" and
               b.get("name") == "SCHEDULED_DRILL_DELIVERY"] if isinstance(root_bindings, list) else []
    d1 = [b for b in root_bindings or [] if isinstance(b, dict) and b.get("type") == "d1" and
          b.get("name") == "CONFIG_DB"] if isinstance(root_bindings, list) else []
    receiver_d1 = [b for b in receiver_bindings or [] if isinstance(b, dict) and b.get("type") == "d1" and
                   b.get("name") == "CONFIG_DB"] if isinstance(receiver_bindings, list) else []
    if (len(service) != 1 or service[0].get("service") != RECEIVER_WORKER or
            len(d1) != 1 or d1[0].get("id") != STAGING_D1_ID or
            len(receiver_d1) != 1 or receiver_d1[0].get("id") != STAGING_D1_ID):
        raise OperatorError("root staging service binding is not the named receiver")
    zone_routes = route_cf.zone_route_inventory()
    receiver_routes = [route for route in zone_routes if route.get("script") == RECEIVER_WORKER]
    root_routes = [route for route in zone_routes if route.get("script") == ROOT_WORKER]
    if receiver_routes or root_routes:
        raise OperatorError("staging root or receiver has a public route; refusing a one-shot activation")
    root_subdomain = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/subdomain"))
    if not isinstance(root_subdomain, dict) or root_subdomain.get("enabled") is not False or \
            root_subdomain.get("previews_enabled") is not False:
        raise OperatorError("root staging workers.dev/preview ingress is not disabled")
    receiver_subdomain = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/subdomain"))
    if not isinstance(receiver_subdomain, dict) or receiver_subdomain.get("enabled") is not False or \
            receiver_subdomain.get("previews_enabled") is not False:
        raise OperatorError("receiver workers.dev/preview ingress is not disabled")
    return {"root_version": root_active, "receiver_disabled_version": receiver_active,
            "root_schedules": [], "root_settings": {"vars": root_vars, "bindings": root_bindings},
            "receiver_settings": {"vars": receiver_vars, "bindings": receiver_bindings},
            "root_routes": [], "receiver_routes": [], "root_subdomain": root_subdomain,
            "receiver_subdomain": receiver_subdomain}


def apply_and_verify_migration(cf: Cloudflare, d1_token: str, source_root: Path, now_ms: int) -> str:
    content = (source_root / MIGRATION).read_bytes()
    migration_sha = digest(content)
    schema = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT name FROM sqlite_master WHERE type IN ('table','trigger') AND name LIKE 'b072_one_shot_%' ORDER BY name")
    names = {str(row.get("name")) for row in schema}
    if not REQUIRED_SCHEMA_OBJECTS.issubset(names):
        sql = content.decode("utf-8")
        cf.d1(STAGING_D1_ID, d1_token, sql)
    verified_schema = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT name FROM sqlite_master WHERE type IN ('table','trigger') AND name LIKE 'b072_one_shot_%' ORDER BY name")
    if not REQUIRED_SCHEMA_OBJECTS.issubset({str(row.get("name")) for row in verified_schema}):
        raise OperatorError("staging D1 B-072 migration schema/readback is incomplete")
    marker = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT singleton_id, migration_name, content_sha256 FROM b072_one_shot_migration_receipt WHERE singleton_id = 1")
    if marker:
        row = marker[0]
        if row.get("migration_name") != MIGRATION.name or row.get("content_sha256") != migration_sha:
            raise OperatorError("staging D1 B-072 migration checksum differs from this exact main SHA")
    else:
        cf.d1(STAGING_D1_ID, d1_token,
            "INSERT INTO b072_one_shot_migration_receipt(singleton_id,migration_name,content_sha256,applied_at_ms) VALUES(1,?,?,?)",
            [MIGRATION.name, migration_sha, now_ms])
    verified = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT migration_name, content_sha256 FROM b072_one_shot_migration_receipt WHERE singleton_id = 1")
    if len(verified) != 1 or verified[0].get("migration_name") != MIGRATION.name or \
            verified[0].get("content_sha256") != migration_sha:
        raise OperatorError("staging D1 migration checksum/readback failed")
    return migration_sha


def auth_values(*, sha: str, receiver_version: str, reviewer: dict[str, Any], run_id: int,
                now_ms: int, nonce: str) -> tuple[int, int, int]:
    authorized_at = now_ms
    starts_at = authorized_at + 30 * 60_000
    ends_at = starts_at + 30 * 60_000
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not receiver_version or len(receiver_version) > 200 or \
            not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce) or starts_at - authorized_at < 20 * 60_000:
        raise OperatorError("immutable B-072 authorization fields are malformed")
    if not reviewer.get("reviewer_login") or reviewer.get("run_id") != run_id:
        raise OperatorError("immutable authorization lacks an independent run-bound reviewer")
    return authorized_at, starts_at, ends_at


def insert_authorization(cf: Cloudflare, d1_token: str, *, sha: str, receiver_version: str,
                         reviewer: dict[str, Any], run_id: int, nonce: str,
                         times: tuple[int, int, int]) -> None:
    authorized, starts, ends = times
    cf.d1(STAGING_D1_ID, d1_token,
        "INSERT INTO b072_one_shot_authorization(singleton_id,issue_id,serving_sha,approval_nonce,receiver_worker_revision,approved_reviewer,approved_run_id,authorized_at_ms,starts_at_ms,ends_at_ms) VALUES(1,1652,?,?,?,?,?,?,?,?)",
        [sha, nonce, receiver_version, reviewer["reviewer_login"], run_id, authorized, starts, ends])
    rows = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT issue_id, serving_sha, approval_nonce, receiver_worker_revision, approved_reviewer, approved_run_id, authorized_at_ms, starts_at_ms, ends_at_ms FROM b072_one_shot_authorization WHERE singleton_id = 1")
    expected = {"issue_id": 1652, "serving_sha": sha, "approval_nonce": nonce,
        "receiver_worker_revision": receiver_version, "approved_reviewer": reviewer["reviewer_login"],
        "approved_run_id": run_id, "authorized_at_ms": authorized, "starts_at_ms": starts, "ends_at_ms": ends}
    if len(rows) != 1 or rows[0] != expected:
        raise OperatorError("immutable B-072 authorization readback failed")


def put_schedules(cf: Cloudflare, crons: list[str]) -> None:
    cf.call("PUT", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules",
            {"schedules": [{"cron": cron} for cron in crons]})
    if exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules")) != crons:
        raise OperatorError("root schedule PUT exact readback failed")


def deploy_version(cf: Cloudflare, worker: str, version: str) -> None:
    if worker not in (ROOT_WORKER, RECEIVER_WORKER) or not version:
        raise OperatorError("rollback target is outside the exact Worker allowlist")
    cf.call("POST", f"/accounts/{ACCOUNT_ID}/workers/scripts/{worker}/deployments",
        {"strategy": "percentage", "versions": [{"version_id": version, "percentage": 100}],
         "annotations": {"workers/message": "B-072 exact disabled preimage rollback"}})


def revoke(cf: Cloudflare, d1_token: str, *, nonce: str, now_ms: int, reason: str) -> None:
    if reason not in ("disarmed", "partial_arm_recovery", "failed_execution"):
        raise OperatorError("revocation reason is not allowed")
    cf.d1(STAGING_D1_ID, d1_token,
        "INSERT OR IGNORE INTO b072_one_shot_revocation(singleton_id,approval_nonce,revoked_at_ms,reason) VALUES(1,?,?,?)",
        [nonce, now_ms, reason])
    rows = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT approval_nonce, revoked_at_ms, reason FROM b072_one_shot_revocation WHERE singleton_id = 1")
    if len(rows) != 1 or rows[0].get("approval_nonce") != nonce:
        raise OperatorError("B-072 immutable revocation tombstone is absent or mismatched")


def terminal_evidence(cf: Cloudflare, d1_token: str, *, drill_id: str, scheduled_at: int,
                      sha: str, receiver_version: str) -> dict[str, Any] | None:
    receipts = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT drill_id, scheduled_at_ms, correlation_id, provider_mode, outcome, scheduler_worker_revision, serving_sha, receiver_worker_revision, receiver_result FROM synthetic_page_provider_receipts WHERE drill_id = ?",
        [drill_id])
    audit = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT event_type, correlation_id FROM synthetic_page_provider_audit_events WHERE drill_id = ?",
        [drill_id])
    ingresses = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT drill_id, scheduled_at_ms, serving_sha, receiver_worker_revision, ingress_count FROM b072_one_shot_ingress WHERE singleton_id = 1")
    if not receipts and not ingresses:
        return None
    correlation = f"PAT-CORRELATION-ID-001:{drill_id}"
    if len(receipts) != 1 or len(audit) != 1 or len(ingresses) != 1:
        raise OperatorError("receiver receipt/audit/ingress evidence is incomplete or duplicated")
    receipt, event, ingress = receipts[0], audit[0], ingresses[0]
    expected = {"drill_id": drill_id, "scheduled_at_ms": scheduled_at, "correlation_id": correlation,
        "provider_mode": "provider_deferred", "outcome": "provider_deferred",
        "scheduler_worker_revision": sha, "serving_sha": sha,
        "receiver_worker_revision": receiver_version, "receiver_result": "persisted_provider_deferred"}
    if receipt != expected or event != {"event_type": "provider_deferred", "correlation_id": correlation} or \
            ingress != {"drill_id": drill_id, "scheduled_at_ms": scheduled_at, "serving_sha": sha,
                        "receiver_worker_revision": receiver_version, "ingress_count": 1}:
        raise OperatorError("one-shot receipt, audit and independent ingress counter do not exactly correlate")
    drills = cf.d1(STAGING_D1_ID, d1_token,
        "SELECT drill_id, scheduled_at_ms, correlation_id FROM synthetic_page_drills_b072 WHERE drill_id = ?",
        [drill_id])
    if len(drills) != 1 or drills[0] != {"drill_id": drill_id, "scheduled_at_ms": scheduled_at,
                                          "correlation_id": correlation}:
        raise OperatorError("receiver drill row is absent or differs from terminal evidence")
    return {"drill_id": drill_id, "scheduled_at_ms": scheduled_at,
            "receipt": expected, "audit": event, "ingress_count": 1}


def _report(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def require_runtime_identity(environ: dict[str, str], source_root: Path, github: GitHub) -> tuple[str, dict[str, Any]]:
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise OperatorError("cannot prove exact checkout identity") from error
    sha = exact_main_identity(environ, api_main_sha=github.main_sha(), local_head=head)
    run_id = int(environ.get("GITHUB_RUN_ID", "0"))
    actor = environ.get("GITHUB_ACTOR", "")
    if run_id <= 0 or not actor:
        raise OperatorError("GitHub operator run identity is incomplete")
    env = github.environment()
    rules = env.get("protection_rules")
    reviewers = [r for rule in rules or [] if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
                 for r in rule.get("reviewers", []) if isinstance(r, dict)] if isinstance(rules, list) else []
    approval = github.approval(run_id, actor)
    require_configured_independent_approver(reviewers, actor, approval)
    return sha, approval


def execute(source_root: Path, env: dict[str, str], github: GitHub, cf: Cloudflare,
            *, root_version: str, receiver_version: str, terminal_run_id: int,
            report_path: Path, now_ms: Callable[[], int] | None = None) -> dict[str, Any]:
    now_ms = now_ms or (lambda: int(time.time() * 1000))
    sha, approval = require_runtime_identity(env, source_root, github)
    terminal_pass = github.issue_1700_pass(terminal_run_id, sha, env.get("B072_ISSUE_1700_SHA", ""))
    workers_token, d1_token, route_token = require_scoped_credentials(env)
    cf = Cloudflare(env["B072_STAGING_CF_ACCOUNT_ID"], workers_token, request=cf._request)
    route_cf = Cloudflare(env["B072_STAGING_CF_ACCOUNT_ID"], route_token, request=cf._request)
    preimage = worker_preflight(cf, route_cf, sha, root_version, receiver_version)
    report: dict[str, Any] = {"contract": "issue-1652-b072-one-shot-operator-v1", "run_id": int(env["GITHUB_RUN_ID"]),
        "sha": sha, "approval": approval, "issue_1700": terminal_pass, "preimage": {
            "root_version": root_version, "receiver_disabled_version": receiver_version,
            "root_schedules": [], "root_d1_binding": {"name": "CONFIG_DB", "id": STAGING_D1_ID},
            "root_receiver_service": RECEIVER_WORKER,
            "root_routes": [], "root_workers_dev": False,
            "receiver_environment": "staging", "receiver_provider_mode": "provider_deferred",
            "receiver_routes": [], "receiver_workers_dev": False}}
    path = f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}"
    nonce = ""
    auth_may_exist = False
    receiver_activated = False
    schedule_armed = False
    activated = False
    cleanup_ok = False
    try:
        migration_sha = apply_and_verify_migration(cf, d1_token, source_root, now_ms())
        # Upload a candidate without activating it so its immutable version id
        # can be pinned into authorization before any receiver can accept work.
        receiver_version_new = upload_receiver_version(source_root, cf, env, sha)
        nonce = __import__("secrets").token_urlsafe(36)
        times = auth_values(sha=sha, receiver_version=receiver_version_new, reviewer=approval,
                            run_id=int(env["GITHUB_RUN_ID"]), now_ms=now_ms(), nonce=nonce)
        report["migration_sha256"] = migration_sha
        report["candidate_receiver_version"] = receiver_version_new
        report["authorization"] = {"nonce_sha256": digest(nonce.encode()), "window_start_ms": times[1],
            "window_end_ms": times[2], "approved_reviewer": approval["reviewer_login"],
            "approved_run_id": approval["run_id"]}
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _report(report_path, report)
        # A write can commit even if the API response/readback is lost. Treat it
        # as present before issuing the request so the finally block revokes it.
        auth_may_exist = True
        insert_authorization(cf, d1_token, sha=sha, receiver_version=receiver_version_new,
                             reviewer=approval, run_id=int(env["GITHUB_RUN_ID"]), nonce=nonce, times=times)

        activate_receiver_version(cf, receiver_version_new, sha, path)
        receiver_activated = True
        report["receiver_active_version"] = receiver_version_new
        if exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules")) != []:
            raise OperatorError("root schedule drifted after receiver activation; refusing arm")
        _, starts, _ = times
        put_schedules(cf, [ONE_SHOT_CRON])
        schedule_armed = True
        # Anchor the 20-minute margin to successful PUT plus exact GET readback,
        # not to the earlier request start while propagation is still unknown.
        arm_at = now_ms()
        if starts - arm_at < 20 * 60_000:
            raise OperatorError("schedule readback is too late to retain the propagation safety interval")
        report["schedule_arm"] = {"put": [{"cron": ONE_SHOT_CRON}], "readback": [ONE_SHOT_CRON],
                                  "readback_at_ms": arm_at}

        cf.d1(STAGING_D1_ID, d1_token,
            "INSERT INTO b072_one_shot_activation(singleton_id,approval_nonce,receiver_worker_revision,armed_cron,armed_at_ms,activated_at_ms) VALUES(1,?,?,?,?,?)",
            [nonce, receiver_version_new, ONE_SHOT_CRON, arm_at, now_ms()])
        activation = cf.d1(STAGING_D1_ID, d1_token,
            "SELECT approval_nonce, receiver_worker_revision, armed_cron FROM b072_one_shot_activation WHERE singleton_id = 1")
        if len(activation) != 1 or activation[0].get("approval_nonce") != nonce or \
                activation[0].get("receiver_worker_revision") != receiver_version_new or \
                activation[0].get("armed_cron") != ONE_SHOT_CRON:
            raise OperatorError("post-arm B-072 activation readback failed")
        activated = True
        _, starts, ends = times
        while now_ms() < ends:
            scheduled = cf.d1(STAGING_D1_ID, d1_token,
                "SELECT drill_id, scheduled_at_ms FROM b072_one_shot_claim WHERE singleton_id = 1")
            if scheduled:
                claimed = scheduled[0]
                evidence = terminal_evidence(cf, d1_token, drill_id=claimed.get("drill_id", ""),
                    scheduled_at=claimed.get("scheduled_at_ms", -1), sha=sha, receiver_version=receiver_version_new)
                if evidence is not None:
                    report["terminal_evidence"] = evidence
                    break
            time.sleep(10)
        else:
            raise OperatorError("bounded one-shot window expired without complete receiver-side evidence")
    except Exception as error:
        report["execution_error"] = safe_error(error)
    finally:
        if auth_may_exist:
            try:
                revoke(cf, d1_token, nonce=nonce, now_ms=now_ms(), reason="disarmed" if activated else "failed_execution")
                report["revocation"] = "durable_readback_verified"
            except Exception as error:
                report["revocation"] = safe_error(error)
            try:
                current = exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules"))
                if current == [ONE_SHOT_CRON]:
                    put_schedules(cf, [])
                elif current != []:
                    raise OperatorError("root schedule drift prevents safe disarm")
                report["schedule_disarm"] = {"expected": [], "readback": exact_crons(
                    cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules"))}
            except Exception as error:
                report["schedule_disarm"] = safe_error(error)
            try:
                deploy_version(cf, RECEIVER_WORKER, receiver_version)
                observed = active_version(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/deployments"))
                if observed != receiver_version:
                    raise OperatorError("receiver exact disabled preimage version did not restore")
                report["receiver_rollback"] = {"version": observed, "enabled": False}
            except Exception as error:
                report["receiver_rollback"] = safe_error(error)
            report["postflight"] = readback_postflight(cf, route_cf, d1_token, root_version,
                receiver_version, receiver_version_new if "receiver_version_new" in locals() else "",
                sha, nonce, now_ms())
            revoked = report.get("revocation") == "durable_readback_verified"
            expired = now_ms() >= times[2] if "times" in locals() else False
            cleanup_ok = revoked or expired
            report["cleanup_complete"] = bool(cleanup_ok and
                report["schedule_disarm"] == {"expected": [], "readback": []} and
                isinstance(report["receiver_rollback"], dict) and
                report["postflight"].get("verified") is True)
            if not revoked and not expired:
                report["residual_risk"] = "at most one provider_deferred service-binding POST remains possible until authorization expiry; zero provider/PagerDuty calls"
                report["cleanup_complete"] = False
        _report(report_path, report)
    if report.get("execution_error") or not report.get("cleanup_complete"):
        raise OperatorError("B-072 execution did not reach independently verified terminal cleanup; inspect redacted run artifact")
    return report


def _worker_versions(cf: Cloudflare) -> list[dict[str, Any]]:
    payload = cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/versions")
    rows = _result(payload)
    if isinstance(rows, dict):
        rows = rows.get("items")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
        raise OperatorError("receiver version inventory is malformed")
    return rows


def upload_receiver_version(source_root: Path, cf: Cloudflare, env: dict[str, str], sha: str) -> str:
    # Wrangler emits only a version upload here; the active version is changed
    # separately through the exact 100% deployment API after preflight.
    run_id = env.get("GITHUB_RUN_ID", "")
    marker = run_id
    before = {row["id"] for row in _worker_versions(cf)}
    local_env = {key: env[key] for key in (
        "PATH", "HOME", "CI", "RUNNER_TEMP", "TMPDIR", "TMP", "TEMP", "NODE_OPTIONS",
        "COREPACK_HOME", "PNPM_HOME", "XDG_CACHE_HOME") if key in env}
    local_env["CI"] = "true"
    local_env["CLOUDFLARE_ACCOUNT_ID"] = ACCOUNT_ID
    local_env["CLOUDFLARE_API_TOKEN"] = env["B072_STAGING_CF_WORKERS_TOKEN"]
    command = ["pnpm", "exec", "wrangler", "versions", "upload", "--env", "staging",
        "--name", RECEIVER_WORKER, "--message", marker,
        "--var", "SYNTHETIC_DRILL_ENABLED:true", "--var", "SYNTHETIC_DRILL_PROVIDER_MODE:provider_deferred",
        "--var", f"SENTRY_RELEASE:{sha}", "--var", f"B072_OPERATOR_RUN_ID:{run_id}"]
    try:
        subprocess.run(command, cwd=source_root / "apps/synthetic-pager-worker", env=local_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as error:
        # An upload may commit despite transport/runner failure. Caller still
        # leaves the root schedule empty and recovery/rollback remain bounded.
        raise OperatorError("staging receiver version upload failed or has unknown state") from error
    after = _worker_versions(cf)
    candidates = [row for row in after if row.get("id") not in before]
    if len(candidates) != 1:
        raise OperatorError("receiver upload did not create exactly one attributable inactive version")
    version = candidates[0]["id"]
    details = cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/versions/{version}")
    detail = _result(details)
    vars_ = version_plain_vars(details)
    bindings = detail.get("resources", {}).get("bindings") if isinstance(detail, dict) else None
    d1 = [binding for binding in bindings or [] if isinstance(binding, dict) and binding.get("type") == "d1" and
          binding.get("name") == "CONFIG_DB"] if isinstance(bindings, list) else []
    if (vars_.get("ENVIRONMENT") != "staging" or vars_.get("B072_OPERATOR_RUN_ID") != marker or
            vars_.get("SYNTHETIC_DRILL_ENABLED") != "true" or
            vars_.get("SYNTHETIC_DRILL_PROVIDER_MODE") != "provider_deferred" or
            vars_.get("SENTRY_RELEASE") != sha or len(d1) != 1 or d1[0].get("id") != STAGING_D1_ID):
        raise OperatorError("uploaded receiver version marker/resources differ from B-072 staging contract")
    return version


def activate_receiver_version(cf: Cloudflare, version: str, sha: str, api_path: str) -> None:
    deploy_version(cf, RECEIVER_WORKER, version)
    observed = active_version(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/deployments"))
    if observed != version:
        raise OperatorError("activated receiver version readback differs from the uploaded candidate")
    version_details = cf.call("GET", api_path + f"/versions/{version}")
    vars_ = version_plain_vars(version_details)
    if vars_.get("ENVIRONMENT") != "staging" or \
            vars_.get("SYNTHETIC_DRILL_ENABLED") != "true" or \
            vars_.get("SYNTHETIC_DRILL_PROVIDER_MODE") != "provider_deferred" or vars_.get("SENTRY_RELEASE") != sha:
        raise OperatorError("activated receiver version settings differ from the B-072 staging contract")


def readback_postflight(cf: Cloudflare, route_cf: Cloudflare, d1_token: str,
                        root_version: str, receiver_version: str, authorized_receiver_version: str,
                        serving_sha: str, nonce: str, now_ms: int) -> dict[str, Any]:
    output: dict[str, Any] = {}
    try:
        output["root_schedules"] = exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules"))
        output["root_version"] = active_version(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/deployments"))
        output["receiver_version"] = active_version(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/deployments"))
        routes = route_cf.zone_route_inventory()
        receiver_routes = [route for route in routes if route.get("script") == RECEIVER_WORKER]
        root_routes = [route for route in routes if route.get("script") == ROOT_WORKER]
        output["receiver_routes_empty"] = receiver_routes == []
        output["receiver_route_count"] = len(receiver_routes)
        output["root_routes_empty"] = root_routes == []
        output["root_route_count"] = len(root_routes)
        root_subdomain = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/subdomain"))
        receiver_subdomain = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/subdomain"))
        output["root_subdomain_disabled"] = isinstance(root_subdomain, dict) and \
            root_subdomain.get("enabled") is False and root_subdomain.get("previews_enabled") is False
        output["receiver_subdomain_disabled"] = isinstance(receiver_subdomain, dict) and \
            receiver_subdomain.get("enabled") is False and receiver_subdomain.get("previews_enabled") is False
        claims = cf.d1(STAGING_D1_ID, d1_token,
            "SELECT drill_id, scheduled_at_ms, serving_sha, approval_nonce FROM b072_one_shot_claim WHERE singleton_id = 1")
        output["claim_present"] = len(claims) == 1
        revocations = cf.d1(STAGING_D1_ID, d1_token,
            "SELECT approval_nonce, revoked_at_ms, reason FROM b072_one_shot_revocation WHERE singleton_id = 1")
        activations = cf.d1(STAGING_D1_ID, d1_token,
            "SELECT approval_nonce, receiver_worker_revision FROM b072_one_shot_activation WHERE singleton_id = 1")
        authorizations = cf.d1(STAGING_D1_ID, d1_token,
            "SELECT approval_nonce, ends_at_ms, receiver_worker_revision, serving_sha FROM b072_one_shot_authorization WHERE singleton_id = 1")
        output["preimage_version_expected"] = receiver_version
        output["revocation_verified"] = bool(revocations and revocations[0].get("approval_nonce") == nonce)
        output["activation_matches"] = bool(activations and activations[0].get("approval_nonce") == nonce and
            activations[0].get("receiver_worker_revision") == authorized_receiver_version)
        output["authorization_matches"] = bool(authorizations and authorizations[0].get("approval_nonce") == nonce and
            authorizations[0].get("receiver_worker_revision") == authorized_receiver_version and
            authorizations[0].get("serving_sha") == serving_sha)
        output["claim_consistent"] = (not claims or (len(claims) == 1 and
            claims[0].get("approval_nonce") == nonce and claims[0].get("serving_sha") == serving_sha))
        output["activation_consistent"] = not activations or output["activation_matches"]
        if output["revocation_verified"]:
            output["revoked_at_ms"] = revocations[0].get("revoked_at_ms")
            output["revocation_reason"] = revocations[0].get("reason")
        if output["authorization_matches"]:
            output["window_end_ms"] = authorizations[0].get("ends_at_ms")
        output["window_expired"] = bool(output["authorization_matches"] and
            now_ms >= authorizations[0].get("ends_at_ms", 2**63 - 1))
        output["verified"] = (output["root_schedules"] == [] and output["root_version"] == root_version and
            output["receiver_version"] == receiver_version and output["receiver_routes_empty"] and
            output["root_routes_empty"] and output["root_subdomain_disabled"] and
            output["receiver_subdomain_disabled"] and output["authorization_matches"] and
            output["activation_consistent"] and output["claim_consistent"] and
            (output["revocation_verified"] or output["window_expired"]))
    except Exception as error:
        output["verified"] = False
        output["error"] = safe_error(error)
    return output


def safe_error(error: Exception) -> str:
    message = str(error)
    permitted_setup = {
        "setup required: provision B072_STAGING_CF_WORKERS_TOKEN scoped to the staging Worker account",
        "setup required: provision B072_STAGING_D1_WRITE_TOKEN scoped to the fixed staging D1 database",
        "setup required: provision B072_STAGING_CF_ROUTE_READ_TOKEN scoped to staging zone route read",
        "setup required: B072_STAGING_CF_ACCOUNT_ID must identify the frozen staging account",
        "setup required: B072_STAGING_D1_DATABASE_ID must identify the frozen staging D1 database",
        "setup required: B072_STAGING_D1_WRITE_TOKEN",
        "setup required: B072_STAGING_CF_WORKERS_TOKEN for schedule disarm/version rollback",
    }
    if isinstance(error, OperatorError) and message in permitted_setup:
        return message
    if isinstance(error, OperatorError) and len(message) < 240 and not re.search(r"token|secret", message, re.I):
        return message
    return "operation failed; provider details were suppressed"


def recover(cf: Cloudflare, d1_token: str | None, *, original_report: dict[str, Any],
            route_cf: Cloudflare | None,
            report_path: Path, now_ms: Callable[[], int] | None = None) -> dict[str, Any]:
    now_ms = now_ms or (lambda: int(time.time() * 1000))
    preimage = original_report.get("preimage")
    auth = original_report.get("authorization")
    nonce_hash = auth.get("nonce_sha256") if isinstance(auth, dict) else None
    if not isinstance(preimage, dict) or not isinstance(auth, dict) or not isinstance(nonce_hash, str):
        raise OperatorError("recovery artifact lacks a bounded receiver/schedule preimage")
    output: dict[str, Any] = {"contract": "issue-1652-b072-one-shot-recovery-v1",
        "original_run_id": original_report.get("run_id"), "nonce_sha256": nonce_hash}
    rows: list[dict[str, Any]] = []
    authorization_proof = False
    authorization_absent = False
    database_window_expired = False
    if d1_token:
        try:
            rows = cf.d1(STAGING_D1_ID, d1_token,
                "SELECT approval_nonce, ends_at_ms, serving_sha, approved_run_id FROM b072_one_shot_authorization WHERE singleton_id = 1")
            if not rows:
                authorization_absent = True
                activations = cf.d1(STAGING_D1_ID, d1_token,
                    "SELECT singleton_id FROM b072_one_shot_activation WHERE singleton_id = 1")
                claims = cf.d1(STAGING_D1_ID, d1_token,
                    "SELECT singleton_id FROM b072_one_shot_claim WHERE singleton_id = 1")
                authorization_proof = not activations and not claims
            elif len(rows) != 1 or digest(str(rows[0].get("approval_nonce", "")).encode()) != nonce_hash or \
                    rows[0].get("serving_sha") != original_report.get("sha") or \
                    rows[0].get("approved_run_id") != original_report.get("run_id"):
                raise OperatorError("recovery artifact and durable authorization do not correlate")
            else:
                authorization_proof = True
                database_window_expired = now_ms() >= rows[0].get("ends_at_ms", 2**63 - 1)
                activations = cf.d1(STAGING_D1_ID, d1_token,
                    "SELECT approval_nonce FROM b072_one_shot_activation WHERE singleton_id = 1")
                claims = cf.d1(STAGING_D1_ID, d1_token,
                    "SELECT approval_nonce, serving_sha FROM b072_one_shot_claim WHERE singleton_id = 1")
                if activations and digest(str(activations[0].get("approval_nonce", "")).encode()) != nonce_hash:
                    raise OperatorError("recovery activation does not match the original authorization")
                if claims and (digest(str(claims[0].get("approval_nonce", "")).encode()) != nonce_hash or
                               claims[0].get("serving_sha") != original_report.get("sha")):
                    raise OperatorError("recovery claim does not match the original authorization")
            output["authorization_readback_verified"] = authorization_proof
            output["authorization_present"] = bool(rows)
        except Exception as error:
            output["authorization_readback"] = safe_error(error)
            rows = []
            authorization_proof = False
            authorization_absent = False
            database_window_expired = False
    else:
        output["authorization_readback"] = "setup required: B072_STAGING_D1_WRITE_TOKEN for authorization readback/revocation"
    try:
        if d1_token and rows and authorization_proof:
            revoke(cf, d1_token, nonce=rows[0]["approval_nonce"], now_ms=now_ms(), reason="partial_arm_recovery")
            output["revocation"] = "durable_readback_verified"
        elif authorization_absent and authorization_proof:
            output["revocation"] = "not_required_no_authorization_row"
        else:
            output["revocation"] = "setup required: B072_STAGING_D1_WRITE_TOKEN"
    except Exception as error:
        output["revocation"] = safe_error(error)
    try:
        schedules = exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules"))
        if schedules == [ONE_SHOT_CRON]:
            put_schedules(cf, [])
        elif schedules != []:
            raise OperatorError("root schedule drift prevents bounded recovery disarm")
        output["root_schedules"] = exact_crons(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/schedules"))
        output["root_version"] = active_version(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/deployments"))
    except Exception as error:
        output["root_schedules"] = safe_error(error)
    try:
        receiver_version = preimage.get("receiver_disabled_version")
        deploy_version(cf, RECEIVER_WORKER, receiver_version)
        output["receiver_version"] = active_version(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/deployments"))
    except Exception as error:
        output["receiver_version"] = safe_error(error)
    output["window_expired"] = database_window_expired
    try:
        routes = route_cf.zone_route_inventory() if route_cf else None
        receiver_routes = [route for route in routes if route.get("script") == RECEIVER_WORKER] if routes is not None else None
        root_routes = [route for route in routes if route.get("script") == ROOT_WORKER] if routes is not None else None
        output["receiver_routes_empty"] = receiver_routes == [] if receiver_routes is not None else False
        output["receiver_route_count"] = len(receiver_routes) if receiver_routes is not None else None
        output["root_routes_empty"] = root_routes == [] if root_routes is not None else False
        root_subdomain = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{ROOT_WORKER}/subdomain"))
        receiver_subdomain = _result(cf.call("GET", f"/accounts/{ACCOUNT_ID}/workers/scripts/{RECEIVER_WORKER}/subdomain"))
        output["root_subdomain_disabled"] = isinstance(root_subdomain, dict) and root_subdomain.get("enabled") is False and root_subdomain.get("previews_enabled") is False
        output["receiver_subdomain_disabled"] = isinstance(receiver_subdomain, dict) and receiver_subdomain.get("enabled") is False and receiver_subdomain.get("previews_enabled") is False
    except Exception as error:
        output["receiver_routes"] = safe_error(error)
    output["cleanup_complete"] = output.get("root_schedules") == [] and \
        output.get("root_version") == preimage.get("root_version") and \
        output.get("receiver_version") == preimage.get("receiver_disabled_version") and \
        output.get("receiver_routes_empty") is True and \
        output.get("root_routes_empty") is True and output.get("root_subdomain_disabled") is True and \
        output.get("receiver_subdomain_disabled") is True and \
        authorization_proof and (output.get("revocation") in
        ("durable_readback_verified", "not_required_no_authorization_row") or output["window_expired"])
    if not output["cleanup_complete"]:
        output["residual_risk"] = "at most one provider_deferred service-binding POST until durable revocation or authorization expiry; zero provider/PagerDuty calls"
    _report(report_path, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("preflight", "execute", "recover"), required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--root-version", default=os.environ.get("B072_EXPECTED_ROOT_VERSION", ""))
    parser.add_argument("--receiver-version", default=os.environ.get("B072_EXPECTED_RECEIVER_VERSION", ""))
    parser.add_argument("--issue-1700-run-id", type=int, default=int(os.environ.get("B072_ISSUE_1700_RUN_ID", "0")))
    parser.add_argument("--original-run-id", type=int, default=int(os.environ.get("B072_ORIGINAL_RUN_ID", "0")))
    parser.add_argument("--report", type=Path, default=Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "issue-1652-b072-operator-receipt.json")
    args = parser.parse_args()
    try:
        env = dict(os.environ)
        github = GitHub(env.get("GITHUB_TOKEN", ""))
        sha, approval = require_runtime_identity(env, args.source_root, github)
        if args.mode == "preflight":
            workers, _, route = require_scoped_credentials(env)
            cf = Cloudflare(ACCOUNT_ID, workers)
            route_cf = Cloudflare(ACCOUNT_ID, route)
            if not args.root_version or not args.receiver_version:
                raise OperatorError("setup required: provide reviewed root and disabled receiver version preimages")
            preimage = worker_preflight(cf, route_cf, sha, args.root_version, args.receiver_version)
            if args.issue_1700_run_id > 0:
                github.issue_1700_pass(args.issue_1700_run_id, sha, env.get("B072_ISSUE_1700_SHA", ""))
            _report(args.report, {"mode": "preflight", "sha": sha, "approval": approval,
                                  "preimage": {"root_version": args.root_version,
                                               "receiver_disabled_version": args.receiver_version,
                                               "schedules": preimage["root_schedules"]}})
        elif args.mode == "execute":
            workers, _, _ = require_scoped_credentials(env)
            cf = Cloudflare(ACCOUNT_ID, workers)
            if args.issue_1700_run_id <= 0:
                raise OperatorError("setup required: provide a live #1700 workflow run ID for machine PASS verification")
            execute(args.source_root, env, github, cf, root_version=args.root_version,
                receiver_version=args.receiver_version, terminal_run_id=args.issue_1700_run_id,
                report_path=args.report)
        else:
            workers = env.get("B072_STAGING_CF_WORKERS_TOKEN", "")
            if not workers:
                raise OperatorError("setup required: B072_STAGING_CF_WORKERS_TOKEN for schedule disarm/version rollback")
            cf = Cloudflare(ACCOUNT_ID, workers)
            route_token = env.get("B072_STAGING_CF_ROUTE_READ_TOKEN", "")
            route_cf = Cloudflare(ACCOUNT_ID, route_token) if route_token else None
            d1_token = env.get("B072_STAGING_D1_WRITE_TOKEN")
            if args.original_run_id <= 0:
                raise OperatorError("recovery requires the original protected B-072 run id")
            artifact = github.get(f"actions/runs/{args.original_run_id}/artifacts").get("artifacts")
            matches = [a for a in artifact or [] if isinstance(a, dict) and a.get("name") == f"issue-1652-b072-execution-{args.original_run_id}"]
            if len(matches) != 1:
                raise OperatorError("recovery requires the original retained B-072 execution artifact")
            # The recovery job fetches the artifact via the same bounded GitHub client path.
            original_report = download_operator_report(github, args.original_run_id, matches[0])
            result = recover(cf, d1_token, original_report=original_report, report_path=args.report,
                             route_cf=route_cf)
            if not result.get("cleanup_complete"):
                raise OperatorError("recovery cleanup remains incomplete; residual risk recorded")
        print(f"B-072 {args.mode} preflight/operation completed; redacted receipt: {args.report}")
        return 0
    except (OperatorError, ValueError, OSError) as error:
        message = safe_error(error) if isinstance(error, Exception) else "operation failed"
        print(f"::error::{message}", file=sys.stderr)
        return 1


def download_operator_report(github: GitHub, run_id: int, artifact: dict[str, Any]) -> dict[str, Any]:
    url = artifact.get("archive_download_url")
    if not isinstance(url, str) or not url.startswith("https://api.github.com/repos/"):
        raise OperatorError("original operator artifact URL is invalid")
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + github.token,
        "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OperatorError("original operator artifact exceeds bounded size")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            files = [name for name in archive.namelist() if name.endswith("issue-1652-b072-operator-receipt.json")]
            if len(files) != 1:
                raise OperatorError("original operator artifact lacks one receipt")
            report = json.loads(archive.read(files[0]))
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
        raise OperatorError("original operator artifact is malformed") from error
    if not isinstance(report, dict) or report.get("run_id") != run_id:
        raise OperatorError("original operator receipt is not bound to its run")
    return report


if __name__ == "__main__":
    raise SystemExit(main())
