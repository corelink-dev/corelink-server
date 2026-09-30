#!/usr/bin/env python3
"""Bounded IAD Container image rollout without uploading a Worker.

Operator route for #1648. ``plan`` is read-only; ``apply`` and ``rollback``
require protected-environment release flags and exact provider preimages.
Provider mutations are deliberately never retried after an ambiguous result.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any

ACCOUNT = "6a1fc1c626fc2628823e60b9db01f5cd"
APP = "a033572c-0803-4866-b3a3-61f4812843b1"
WORKER = "corelink-prod"
REPOSITORY = f"registry.cloudflare.com/{ACCOUNT}/corelink-prod-corelinkserver-prod"
OLD_TAG = f"{REPOSITORY}:9308f4aa8-r1"
OLD_DIGEST = "sha256:9efdfdfe26a63504a580832d43b4ad686351e3c1500fd8ec2d1e8e29f46a71d0"
NEW_DIGEST = "sha256:ecd63379d2040c6a891edaeb140fd388f26b5ffc181987c9c777060ced633e8a"
BUILD_RUN = 36392540950
BUILD_SOURCE = "46e2d1cbe7c00a303c0942e8f46751dce75e5c14"
OLD_MANIFEST_RECEIPT_SHA256 = "309be1b3635920c12676b64c52ca6970581b0a47cd00ef9e2610b4c5585b4a9a"
OLD_REF = f"{REPOSITORY}@{OLD_DIGEST}"
NEW_REF = f"{REPOSITORY}@{NEW_DIGEST}"
OLD_WORKER = "0b77d7b0-f91f-4905-aedb-2361de494b69"
EXPECTED_DO_NAMESPACE = "0c15b1b2676b4bd88b88058b3f9f7dc5"
BASE = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}"
APP_PATH = f"/containers/applications/{APP}"
ROLLOUTS_PATH = f"{APP_PATH}/rollouts"
DEPLOYMENTS_PATH = f"/workers/scripts/{WORKER}/deployments"
REGISTRY_CREDENTIALS_PATH = "/containers/registries/registry.cloudflare.com/credentials"
OLD_MANIFEST_URL = (f"https://registry.cloudflare.com/v2/{ACCOUNT}/"
                    "corelink-prod-corelinkserver-prod/manifests/9308f4aa8-r1")
SAFE_HASH = re.compile(r"^[0-9a-f]{64}$")
SAFE_VERSION = re.compile(r"^[1-9][0-9]*$")
SAFE_AUTHORITY = re.compile(r"^issue-1648-comment-[1-9][0-9]{5,19}$")


class GateError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def require(condition: bool, why: str) -> None:
    if not condition:
        raise GateError(why)


class API:
    def __init__(self, token: str):
        require(len(token) >= 20, "credential_not_bound")
        self.token = token

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        require(method in {"GET", "PATCH", "POST"}, "method_rejected")
        require(path in {APP_PATH, ROLLOUTS_PATH, DEPLOYMENTS_PATH,
                         REGISTRY_CREDENTIALS_PATH} or
                re.fullmatch(re.escape(ROLLOUTS_PATH) + r"/[0-9a-f-]{36}", path) is not None,
                "path_rejected")
        data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        req = urllib.request.Request(
            BASE + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=25) as response:
                raw = response.read(2_000_001)
                require(len(raw) <= 2_000_000, "response_too_large")
                parsed = json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise GateError(f"provider_http_{exc.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise GateError("provider_result_unknown") from None
        require(isinstance(parsed, dict) and parsed.get("success") is True,
                "provider_response_not_success")
        return parsed.get("result")

    def verify_old_tag_manifest(self) -> str:
        """Resolve the mutable old tag immediately before the application PATCH."""
        credentials = self.request("POST", REGISTRY_CREDENTIALS_PATH,
                                   {"expiration_minutes": 5, "permissions": ["pull"]})
        require(isinstance(credentials, dict) and
                isinstance(credentials.get("username"), str) and
                isinstance(credentials.get("password"), str), "registry_credential_shape")
        authorization = "Basic " + base64.b64encode(
            (credentials["username"] + ":" + credentials["password"]).encode()).decode()
        request = urllib.request.Request(
            OLD_MANIFEST_URL, method="GET",
            headers={"Authorization": authorization,
                     "Accept": "application/vnd.oci.image.manifest.v1+json, "
                               "application/vnd.docker.distribution.manifest.v2+json"})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=25) as response:
                body = response.read(1_000_001)
                require(len(body) <= 1_000_000, "old_manifest_too_large")
                header = response.headers.get("Docker-Content-Digest", "")
        except urllib.error.HTTPError as exc:
            raise GateError(f"registry_http_{exc.code}") from None
        except (urllib.error.URLError, TimeoutError):
            raise GateError("registry_result_unknown") from None
        actual = "sha256:" + hashlib.sha256(body).hexdigest()
        require(header == actual == OLD_DIGEST, "old_tag_digest_drift")
        return actual


def app_snapshot(result: Any, *, require_ready: bool = True) -> dict[str, Any]:
    require(isinstance(result, dict), "app_shape")
    require(result.get("id") == APP, "app_id_drift")
    require(result.get("name") == "corelink-prod-corelinkserver-prod", "app_name_drift")
    version = result.get("version")
    require(type(version) is int and version > 0, "app_version_missing")
    config = result.get("configuration")
    require(isinstance(config, dict) and isinstance(config.get("image"), str), "config_missing")
    durable_objects = result.get("durable_objects")
    require(isinstance(durable_objects, dict) and
            durable_objects.get("namespace_id") == EXPECTED_DO_NAMESPACE,
            "do_namespace_drift")
    health = result.get("health")
    require(isinstance(health, dict), "health_missing")
    instances = health.get("instances")
    require(isinstance(instances, dict), "instance_health_missing")
    healthy, active, failed = (instances.get(key) for key in ("healthy", "active", "failed"))
    desired = result.get("instances")
    other_states = [instances.get(key) for key in
                    ("assigned", "stopped", "scheduling", "starting")]
    require(all(type(x) is int for x in (healthy, active, failed, desired, *other_states)),
            "health_incomplete")
    ready = (desired == 16 and healthy + active == desired and failed == 0 and
             all(x == 0 for x in other_states) and health.get("errors") == [])
    if require_ready:
        require(ready, "health_not_ready")
    return {
        "version": version, "configuration": config, "config_sha256": canonical_hash(config),
        "image": config["image"], "desired": desired, "healthy": healthy,
        "active": active, "failed": failed, "ready": ready,
        "active_rollout_id": result.get("active_rollout_id"),
        "do_namespace": durable_objects["namespace_id"],
    }


def active_worker(result: Any) -> str:
    deployments = result if isinstance(result, list) else result.get("deployments") if isinstance(result, dict) else None
    require(isinstance(deployments, list) and len(deployments) > 0, "deployments_shape")
    latest = deployments[0]
    require(isinstance(latest, dict), "deployment_shape")
    versions = latest.get("versions")
    require(isinstance(versions, list) and len(versions) == 1, "worker_traffic_split")
    version = versions[0]
    require(version.get("percentage") == 100 and isinstance(version.get("version_id"), str),
            "worker_not_100_percent")
    return version["version_id"]


def no_active_rollout(result: Any, app: dict[str, Any]) -> None:
    require(app["active_rollout_id"] in {None, ""}, "app_rollout_active")
    entries = result if isinstance(result, list) else result.get("rollouts") if isinstance(result, dict) else None
    require(isinstance(entries, list), "rollouts_shape")
    for item in entries:
        require(isinstance(item, dict), "rollout_shape")
        require(item.get("status") not in {"pending", "progressing"}, "rollout_in_progress")


def preimage(api: API) -> tuple[dict[str, Any], str]:
    app = app_snapshot(api.request("GET", APP_PATH))
    no_active_rollout(api.request("GET", ROLLOUTS_PATH), app)
    worker = active_worker(api.request("GET", DEPLOYMENTS_PATH))
    return app, worker


def receipt(mode: str, state: str, app: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    out = {"schema_version": 1, "issue": 1648, "mode": mode, "state": state,
           "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "account": ACCOUNT,
           "app_id": APP, "worker": WORKER, "build_run": BUILD_RUN,
           "build_source": BUILD_SOURCE, "old_manifest_receipt_sha256": OLD_MANIFEST_RECEIPT_SHA256}
    if app is not None:
        out.update({k: app[k] for k in ("version", "config_sha256", "image", "desired", "healthy", "failed")})
    out.update(extra)
    return out


def save(value: dict[str, Any], path: str) -> None:
    payload = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        with open(path + ".journal", "a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    print(payload, end="")


def run(args: argparse.Namespace, api: API) -> dict[str, Any]:
    before, worker = preimage(api)
    require(worker == OLD_WORKER, "worker_version_drift")
    if args.mode == "plan":
        require(before["image"] in {OLD_TAG, OLD_REF, NEW_REF}, "unrecognized_image")
        return receipt("plan", "READ_ONLY", before, worker_version=worker,
                       old_digest=OLD_DIGEST, new_digest=NEW_DIGEST,
                       write_scope="NOT_PROVEN_BY_READ")

    authority = os.environ.get("I1648_AUTHORITY_REF", "")
    scope_sha = os.environ.get("I1648_SCOPE_RECEIPT_SHA256", "")
    require(SAFE_AUTHORITY.fullmatch(authority) is not None, "production_approval_unbound")
    require(not scope_sha or SAFE_HASH.fullmatch(scope_sha) is not None,
            "scope_receipt_hash_invalid")
    require(bool(args.receipt), "mutation_receipt_path_missing")
    require(args.expected_app_version and SAFE_VERSION.fullmatch(args.expected_app_version) is not None,
            "expected_version_invalid")
    require(args.expected_config_sha256 and SAFE_HASH.fullmatch(args.expected_config_sha256) is not None,
            "expected_config_hash_invalid")
    require(before["version"] == int(args.expected_app_version), "app_version_drift")
    require(before["config_sha256"] == args.expected_config_sha256, "app_config_drift")
    expected_image = OLD_TAG if args.mode == "apply" else NEW_REF
    target = NEW_REF if args.mode == "apply" else OLD_REF
    require(before["image"] == expected_image, "image_precondition_failed")
    require(args.confirm == f"{args.mode}-iad-b063", "confirmation_invalid")
    if args.mode == "apply":
        require(api.verify_old_tag_manifest() == OLD_DIGEST, "old_tag_digest_drift")

    target_config = dict(before["configuration"])
    target_config["image"] = target
    require({k: v for k, v in target_config.items() if k != "image"} ==
            {k: v for k, v in before["configuration"].items() if k != "image"},
            "non_image_config_delta")
    # Two provider mutations mirror Wrangler's own application path. If either
    # result is ambiguous, stop; do not retry, auto-rollback or start another leg.
    save(receipt(args.mode, "PREPARED_BEFORE_PATCH", before, worker_version=worker,
                 target_image=target, authority_ref=authority, scope_receipt_sha256=scope_sha), args.receipt)
    api.request("PATCH", APP_PATH, {"configuration": target_config})
    save(receipt(args.mode, "PATCH_RETURNED_SUCCESS_ROLLOUT_PENDING", before,
                 worker_version=worker, target_image=target), args.receipt)
    # For scheduler-backed Containers, PATCH records/modifies application
    # configuration but does not apply an image change to instances. The
    # explicit rollout applies target_configuration; expecting GET(APP) to
    # expose the new image before this POST is invalid and can strand a
    # successful PATCH before rollout creation.
    after_patch = app_snapshot(api.request("GET", APP_PATH), require_ready=False)
    require(after_patch["version"] == before["version"], "app_version_changed_after_patch")
    require(after_patch["image"] in {before["image"], target}, "unexpected_image_after_patch")
    require({k: v for k, v in after_patch["configuration"].items() if k != "image"} ==
            {k: v for k, v in before["configuration"].items() if k != "image"},
            "patch_non_image_drift")
    require(after_patch["active_rollout_id"] in {None, ""}, "rollout_active_after_patch")
    no_active_rollout(api.request("GET", ROLLOUTS_PATH), after_patch)
    require(active_worker(api.request("GET", DEPLOYMENTS_PATH)) == worker,
            "worker_changed_after_patch")
    save(receipt(args.mode, "PATCH_READBACK_PASS_ROLLOUT_PENDING", after_patch,
                 worker_version=worker, target_image=target), args.receipt)
    save(receipt(args.mode, "ROLLOUT_POST_PENDING", after_patch, worker_version=worker,
                 target_image=target), args.receipt)
    rollout = api.request("POST", ROLLOUTS_PATH, {
        "description": f"B-063 IAD {args.mode}: immutable image only",
        "strategy": "rolling", "target_configuration": target_config,
        "step_percentage": 100, "kind": "full_auto",
    })
    require(isinstance(rollout, dict) and isinstance(rollout.get("id"), str),
            "rollout_ack_unknown")
    rollout_id = rollout["id"]
    save(receipt(args.mode, "ROLLOUT_ACK_POLLING", after_patch, worker_version=worker,
                 target_image=target, rollout_id=rollout_id), args.receipt)
    deadline = time.monotonic() + args.timeout_seconds
    consecutive = 0
    rollout_target_version: int | None = None
    while time.monotonic() < deadline:
        current_result = api.request("GET", APP_PATH)
        current = app_snapshot(current_result, require_ready=False)
        require(active_worker(api.request("GET", DEPLOYMENTS_PATH)) == worker,
                "worker_changed_during_rollout")
        require({k: v for k, v in current["configuration"].items() if k != "image"} ==
                {k: v for k, v in before["configuration"].items() if k != "image"},
                "rollout_non_image_config_drift")
        current_rollout = api.request("GET", f"{ROLLOUTS_PATH}/{rollout_id}")
        require(isinstance(current_rollout, dict), "rollout_read_shape")
        require(current_rollout.get("status") not in {"reverted", "replaced"}, "rollout_reverted")
        observed_target_version = current_rollout.get("target_version")
        require(type(observed_target_version) is int and observed_target_version > before["version"],
                "rollout_target_version_invalid")
        if rollout_target_version is None:
            rollout_target_version = observed_target_version
        require(observed_target_version == rollout_target_version,
                "rollout_target_version_changed")
        rollout_target_configuration = current_rollout.get("target_configuration")
        require(isinstance(rollout_target_configuration, dict) and
                rollout_target_configuration.get("image") == target,
                "rollout_target_image_drift")
        if current_rollout.get("status") == "completed" and current["ready"] and \
                current["version"] == rollout_target_version and current["image"] == target and \
                {k: v for k, v in current["configuration"].items() if k != "image"} == \
                {k: v for k, v in before["configuration"].items() if k != "image"}:
            consecutive += 1
            if consecutive >= 3:
                return receipt(args.mode, "ROLLOUT_COMPLETE", current,
                               worker_version=worker, rollout_id=rollout_id,
                               target_version=rollout_target_version,
                               old_digest=OLD_DIGEST, new_digest=NEW_DIGEST)
        else:
            consecutive = 0
        time.sleep(10)
    raise GateError("rollout_not_confirmed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "apply", "rollback"))
    parser.add_argument("--expected-app-version", default="")
    parser.add_argument("--expected-config-sha256", default="")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--receipt", default="")
    args = parser.parse_args(argv)
    try:
        require(30 <= args.timeout_seconds <= 900, "timeout_out_of_range")
        token = os.environ.get("CF_API_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN") or ""
        result = run(args, API(token))
        save(result, args.receipt)
        return 0
    except GateError as exc:
        save(receipt(args.mode, "FAIL_CLOSED_OR_PROVIDER_UNKNOWN", error_class=str(exc)), args.receipt)
        return 2
    except Exception:
        save(receipt(args.mode, "FAIL_CLOSED_OR_PROVIDER_UNKNOWN", error_class="internal_error"), args.receipt)
        return 2


if __name__ == "__main__":
    sys.exit(main())
