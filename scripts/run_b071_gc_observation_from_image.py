#!/usr/bin/env python3
"""Bind the B-071 observer binary and one-scope manifest to a deployed image."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import base64
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE_ENV = "B071_GC_OBSERVATION_IMAGE_REF"
SCOPE_ENV = "B071_GC_OBSERVATION_SCOPE_JSON"
REGISTRY_TOKEN_ENV = "B071_CF_REGISTRY_READ_TOKEN"
RUNTIME_SECRETS = ("CLOUDFLARE_ACCOUNT_ID", "D1_DATABASE_ID", "CF_API_TOKEN", "R2_TDK_HEX")
REGISTRY_HOST = "registry.cloudflare.com"
REGISTRY_CREDENTIAL_URL = "https://api.cloudflare.com/client/v4/accounts/{account_id}/containers/registries/registry.cloudflare.com/credentials"
REGISTRY_CREDENTIAL_EXPIRY_MINUTES = 15
REGISTRY_CREDENTIAL_SAFETY_SECONDS = 60
IMAGE_REPOSITORIES = frozenset(
    {
        "corelink-prod-corelinkserver-prod",
        "corelink-prod-sam-corelinkserver-prod",
        "corelink-prod-lhr-corelinkserver-prod",
        "corelink-prod-nrt-corelinkserver-prod",
        "corelink-prod-syd-corelinkserver-prod",
    }
)
IMAGE_REF = re.compile(
    r"^registry\.cloudflare\.com/(?P<account>[0-9a-f]{32})/"
    r"(?P<repository>[a-z0-9][a-z0-9._-]*)@sha256:(?P<digest>[0-9a-f]{64})$"
)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
BINARY = "/usr/local/bin/corelink-gc-sweep-production"


class GateError(ValueError):
    pass


def _validate_inputs(env: dict[str, str]) -> tuple[str, bytes]:
    image = env.get(IMAGE_ENV, "")
    image_match = IMAGE_REF.fullmatch(image)
    if image_match is None or image_match.group("repository") not in IMAGE_REPOSITORIES:
        raise GateError(f"{IMAGE_ENV} must identify an approved production image by immutable digest")
    account_id = env.get("CLOUDFLARE_ACCOUNT_ID", "")
    if not re.fullmatch(r"[0-9a-f]{32}", account_id) or image_match.group("account") != account_id:
        raise GateError("image account must match CLOUDFLARE_ACCOUNT_ID")
    registry_token = env.get(REGISTRY_TOKEN_ENV, "")
    if not isinstance(registry_token, str) or not registry_token.strip():
        raise GateError(f"missing required registry-read binding: {REGISTRY_TOKEN_ENV}")
    for name in RUNTIME_SECRETS:
        if not env.get(name):
            raise GateError(f"missing required runtime binding: {name}")
    if registry_token == env["CF_API_TOKEN"]:
        raise GateError("registry-read and D1-read credentials must be distinct")
    raw = env.get(SCOPE_ENV, "")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError(f"{SCOPE_ENV} must be exact one-scope JSON") from exc
    if (not isinstance(doc, dict) or set(doc) != {"schema_version", "scopes"}
            or doc.get("schema_version") != 1 or not isinstance(doc.get("scopes"), list)
            or len(doc["scopes"]) != 1):
        raise GateError(f"{SCOPE_ENV} must contain exactly one scope")
    scope = doc["scopes"][0]
    if not isinstance(scope, dict) or set(scope) != {"tenant_id", "region", "run_id", "bucket"}:
        raise GateError(f"{SCOPE_ENV} scope must contain exactly tenant_id, region, run_id, bucket")
    if not isinstance(scope["tenant_id"], str) or not UUID.fullmatch(scope["tenant_id"]):
        raise GateError("scope tenant_id must be a canonical lowercase UUID")
    if not isinstance(scope["run_id"], str) or not UUID.fullmatch(scope["run_id"]):
        raise GateError("scope run_id must be a canonical lowercase UUID")
    if not isinstance(scope["region"], str) or scope["region"] not in {"iad", "lhr", "nrt", "sam"}:
        raise GateError("scope region is unsupported")
    if any(not isinstance(scope[k], str) or not scope[k].strip() or scope[k] != scope[k].strip()
           for k in ("region", "bucket")):
        raise GateError("scope region and bucket must be nonempty trimmed strings")
    if not env.get("GITHUB_ACTOR", "").strip():
        raise GateError("missing operator binding: GITHUB_ACTOR")
    if env.get("B071_SOURCE_REF") != "refs/heads/main":
        raise GateError("observation source must be dispatched from main")
    source_sha = env.get("B071_SOURCE_SHA", "")
    if not GIT_SHA.fullmatch(source_sha) or source_sha != _git_head():
        raise GateError("observation source SHA must match the checked-out commit")
    return image, raw.encode("utf-8")


def _git_head() -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    return result.stdout.strip()


def _run(
    command: list[str],
    *,
    capture: bool = False,
    clean: bool = False,
    extra_env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    safe_env = {k: os.environ[k] for k in ("PATH", "HOME", "DOCKER_CONFIG", "SSL_CERT_FILE", "SSL_CERT_DIR") if k in os.environ}
    if extra_env:
        safe_env.update(extra_env)
    return subprocess.run(
        command,
        check=True,
        text=True,
        env=safe_env if clean else None,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _mint_pull_credentials(account_id: str, token: str) -> tuple[str, str, float]:
    """Mint a short-lived, pull-only credential; never expose its response."""
    if not isinstance(token, str) or not token.strip() or any(ch.isspace() for ch in token):
        raise GateError("registry-read token is malformed")
    started = time.monotonic()
    request = urllib.request.Request(
        REGISTRY_CREDENTIAL_URL.format(account_id=account_id),
        data=json.dumps(
            {
                "permissions": ["pull"],
                "expiration_minutes": REGISTRY_CREDENTIAL_EXPIRY_MINUTES,
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise GateError("Cloudflare registry credential request returned an unexpected status")
            payload_bytes = response.read(64 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        raise GateError(f"Cloudflare registry credential request failed (HTTP {exc.code})") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise GateError(f"Cloudflare registry credential request failed ({type(exc).__name__})") from None
    if len(payload_bytes) > 64 * 1024:
        raise GateError("Cloudflare registry credential response exceeded the bounded size")
    try:
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise GateError("Cloudflare registry credential response was not valid JSON") from None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"errors", "messages", "result", "success"}
        or payload.get("success") is not True
        or payload.get("errors") != []
        or not isinstance(payload.get("messages"), list)
    ):
        raise GateError("Cloudflare registry credential request was not successful")
    result = payload.get("result")
    if not isinstance(result, dict) or set(result) != {"account_id", "password", "registry_host", "username"}:
        raise GateError("Cloudflare registry credential response had an unsupported shape")
    if result["account_id"] != account_id or result["registry_host"] != REGISTRY_HOST:
        raise GateError("Cloudflare registry credential response did not match the requested account and host")
    username = result["username"]
    password = result["password"]
    if (
        not isinstance(username, str)
        or not username
        or ":" in username
        or any(ch.isspace() for ch in username)
        or not isinstance(password, str)
        or not password
        or any(ch.isspace() for ch in password)
        or len(username) > 4096
        or len(password) > 4096
    ):
        raise GateError("Cloudflare registry credential response contained invalid credential fields")
    return username, password, started + REGISTRY_CREDENTIAL_EXPIRY_MINUTES * 60


def _write_registry_docker_config(directory: Path, username: str, password: str) -> Path:
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    config = json.dumps(
        {"auths": {REGISTRY_HOST: {"auth": auth}}},
        separators=(",", ":"),
    ).encode("utf-8")
    path = directory / "config.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(config)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
    path.chmod(0o600)
    return path


def _docker_environment(config_directory: Path) -> dict[str, str]:
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SSL_CERT_FILE", "SSL_CERT_DIR") if k in os.environ}
    env["DOCKER_CONFIG"] = str(config_directory)
    return env


def _remove_registry_credentials(config_directory: Path, docker_env: dict[str, str]) -> None:
    try:
        _run(
            ["docker", "logout", REGISTRY_HOST],
            capture=True,
            clean=True,
            extra_env=docker_env,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        # The private temporary config is still removed below; this logout is
        # best-effort cleanup and its output can include registry metadata.
        pass
    config_file = config_directory / "config.json"
    if config_file.exists() and not config_file.is_symlink():
        config_file.unlink()
    if config_directory.exists() and not config_directory.is_symlink():
        config_directory.rmdir()


def _pull_and_verify_image(image: str, username: str, password: str, deadline: float) -> None:
    with tempfile.TemporaryDirectory(prefix="b071-docker-config-") as temp_config:
        config_directory = Path(temp_config) / "docker"
        _write_registry_docker_config(config_directory, username, password)
        docker_env = _docker_environment(config_directory)
        try:
            if deadline - time.monotonic() <= REGISTRY_CREDENTIAL_SAFETY_SECONDS:
                raise GateError("registry pull credential lease is too close to expiry")
            _run(["docker", "pull", image], capture=True, clean=True, extra_env=docker_env, timeout=300)
            inspected = _run(
                ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
                capture=True,
                clean=True,
                extra_env=docker_env,
                timeout=15,
            )
            _require_repo_digest(image, inspected.stdout or "")
        finally:
            _remove_registry_credentials(config_directory, docker_env)


def _require_repo_digest(image: str, inspect_output: str) -> None:
    try:
        repo_digests = json.loads(inspect_output)
    except json.JSONDecodeError as exc:
        raise GateError("Docker did not return image RepoDigests") from exc
    if not isinstance(repo_digests, list) or image not in repo_digests:
        raise GateError("pulled image is not bound to the requested immutable digest")


def run(env: dict[str, str] | None = None) -> None:
    env = dict(os.environ if env is None else env)
    image, scope = _validate_inputs(env)  # all bindings fail closed before image/provider access
    account_id = env["CLOUDFLARE_ACCOUNT_ID"]
    username, password, deadline = _mint_pull_credentials(account_id, env[REGISTRY_TOKEN_ENV])
    with tempfile.TemporaryDirectory(prefix="b071-observe-") as directory:
        temp = Path(directory)
        scope_path = temp / "scope.json"
        scope_path.write_bytes(scope)
        scope_path.chmod(0o600)
        _pull_and_verify_image(image, username, password, deadline)
        container = _run(["docker", "create", "--network", "none", "--entrypoint", "/bin/true", image], capture=True, clean=True).stdout.strip()
        if not container:
            raise GateError("Docker did not create an extraction container")
        extracted = temp / "corelink-gc-sweep-production"
        try:
            _run(["docker", "cp", f"{container}:{BINARY}", str(extracted)], clean=True)
        finally:
            _run(["docker", "rm", container], clean=True)
        info = extracted.lstat()
        if not stat.S_ISREG(info.st_mode) or not os.access(extracted, os.X_OK):
            raise GateError("extracted observer must be a regular executable from the pinned image")
        output = ROOT / "evidence/owner-actions/B-071/gc-production-dry-run.json"
        collector = ROOT / "scripts/collect_b071_gc_observation.py"
        runtime_env = {name: env[name] for name in RUNTIME_SECRETS}
        _run(
            [sys.executable, str(collector), "collect", "--scopes", str(scope_path), "--binary", str(extracted),
             "--image-digest", image, "--operator", env["GITHUB_ACTOR"], "--output", str(output),
             "--timeout-seconds", "240"],
            clean=True,
            extra_env=runtime_env,
            timeout=270,
        )
        _run(
            [sys.executable, str(collector), "verify", "--evidence", str(output), "--expect-approval", "pending"],
            clean=True,
            extra_env=runtime_env,
            timeout=15,
        )


if __name__ == "__main__":
    try:
        run()
    except (GateError, OSError, subprocess.CalledProcessError) as exc:
        print(f"B-071 staging observation blocked: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except subprocess.TimeoutExpired:
        print("B-071 staging observation blocked: bounded command timed out", file=sys.stderr)
        raise SystemExit(1)
