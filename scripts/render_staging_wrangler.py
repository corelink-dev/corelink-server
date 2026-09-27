#!/usr/bin/env python3
"""Render isolated Wrangler configs from the canonical staging topology.

The renderer deliberately has one origin input: the top-level
``canonical_origin`` field in ``infra/staging/topology.json``.  The adapter
validates that boundary before any value is used to render a Worker config.
Generated configs are intended for ``RUNNER_TEMP`` and never for the repo.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = ROOT / "infra/staging/topology.json"
CANONICAL_HOST = "staging.corelink.humangr.com"
CANONICAL_ORIGIN = f"https://{CANONICAL_HOST}"
PRODUCTION_NAME = re.compile(r"(^|[-_.])(prod|production)([-_.]|$)", re.IGNORECASE)
STAGING_SUFFIX = re.compile(r"-staging$", re.IGNORECASE)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_ID = re.compile(r"^[0-9a-f]{32}$", re.I)
R2_ENDPOINT_HOST = re.compile(r"^[0-9a-f]{32}\.r2\.cloudflarestorage\.com$", re.I)
GITHUB_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)


class ContractError(ValueError):
    """The topology cannot be safely used as a staging render contract."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return value


def _canonical_origin(value: Any) -> str:
    """Validate the only accepted origin and return the original spelling."""
    origin = _string(value, "canonical_origin")
    try:
        parsed = urlparse(origin)
        port = parsed.port
    except ValueError as error:
        raise ContractError("canonical_origin must be the HTTPS staging origin") from error
    if (
        origin != CANONICAL_ORIGIN
        or parsed.scheme != "https"
        or parsed.hostname != CANONICAL_HOST
        or port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or PRODUCTION_NAME.search(origin)
    ):
        raise ContractError("canonical_origin must be the HTTPS staging origin")
    return origin


@dataclass(frozen=True)
class StagingTopologyAdapter:
    """Typed access to the validated, repository-owned staging topology."""

    canonical_origin: str
    cloudflare: Mapping[str, Any]
    outputs: Mapping[str, Any]
    required_secret_names: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "StagingTopologyAdapter":
        root = _mapping(raw, "topology")
        # Do not accept a nested alias.  This catches both the rejected PR's
        # lookup bug and a stale duplicate that could silently diverge later.
        cloudflare_raw = _mapping(root.get("cloudflare"), "cloudflare")
        if "canonical_origin" in cloudflare_raw:
            raise ContractError("canonical_origin must exist only at topology root")
        origin = _canonical_origin(root.get("canonical_origin"))
        outputs = _mapping(root.get("outputs"), "outputs")
        target_host = outputs.get("target_host")
        if target_host is not None and target_host != origin:
            raise ContractError("outputs.target_host conflicts with canonical_origin")
        secrets = _mapping(root.get("required_secret_names"), "required_secret_names")
        adapter = cls(
            canonical_origin=origin,
            cloudflare=cloudflare_raw,
            outputs=outputs,
            required_secret_names=secrets,
        )
        adapter._validate_contract()
        return adapter

    @classmethod
    def from_file(cls, path: Path = TOPOLOGY) -> "StagingTopologyAdapter":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ContractError(f"cannot read topology: {error}") from error
        return cls.from_mapping(raw)

    @property
    def workers(self) -> tuple[str, str, str]:
        cloudflare = self.cloudflare
        names = (
            _string(cloudflare.get("root_worker"), "cloudflare.root_worker"),
            _string(cloudflare.get("signup_worker"), "cloudflare.signup_worker"),
            _string(cloudflare.get("synthetic_receiver_worker"), "cloudflare.synthetic_receiver_worker"),
        )
        return names

    def worker_for_role(self, role: str) -> str:
        roles = {"root": self.workers[0], "signup": self.workers[1], "synthetic": self.workers[2]}
        try:
            return roles[role]
        except KeyError as error:
            raise ContractError(f"unsupported Worker role: {role}") from error

    def settings_for(self, worker: str) -> Mapping[str, Any]:
        settings_keys = {
            self.workers[0]: "root_worker_settings",
            self.workers[1]: "signup_worker_settings",
            self.workers[2]: "synthetic_receiver_worker_settings",
        }
        try:
            return _mapping(self.cloudflare.get(settings_keys[worker]), f"settings for {worker}")
        except KeyError as error:
            raise ContractError(f"unexpected Worker: {worker}") from error

    def routes_for(self, worker: str, phase: str) -> list[Mapping[str, Any]]:
        if phase not in {"bootstrap", "final"}:
            raise ContractError("phase must be bootstrap or final")
        if phase == "bootstrap":
            return []
        return [
            _mapping(route, "cloudflare.routes entry")
            for route in _list(self.cloudflare.get("routes"), "cloudflare.routes")
            if _mapping(route, "cloudflare.routes entry").get("worker") == worker
        ]

    def _validate_contract(self) -> None:
        cloudflare = self.cloudflare
        workers = self.workers
        output_workers = _list(self.outputs.get("worker_names"), "outputs.worker_names")
        if output_workers != list(workers) or len(set(output_workers)) != 3:
            raise ContractError("outputs.worker_names must identify exactly the three staging Workers")
        for name in workers:
            _require_staging_name(name, "Worker name")

        resources = _list(self.outputs.get("resource_names"), "outputs.resource_names")
        for name in resources:
            _require_staging_name(name, "resource name")

        zone_name = _string(cloudflare.get("zone_name"), "cloudflare.zone_name")
        routes = _list(cloudflare.get("routes"), "cloudflare.routes")
        expected_routes = {(workers[0], f"{CANONICAL_HOST}/*", zone_name)}
        actual_routes: set[tuple[str, str, str]] = set()
        for raw_route in routes:
            route = _mapping(raw_route, "cloudflare.routes entry")
            if route.get("worker") not in workers or route.get("zone_name") != zone_name:
                raise ContractError("route references an unexpected Worker or zone")
            pattern = _string(route.get("pattern"), "route.pattern")
            pattern_host = pattern.split("/", 1)[0].rstrip(".").lower()
            if pattern_host != CANONICAL_HOST or PRODUCTION_NAME.search(pattern):
                raise ContractError("route escapes the canonical staging host")
            actual_routes.add((route["worker"], pattern, zone_name))
        if actual_routes != expected_routes or len(routes) != len(expected_routes):
            raise ContractError("routes must contain exactly the root staging route")

        secret_names = {
            name
            for worker, names in self.required_secret_names.items()
            if worker != "github_environment_staging"
            for name in _list(names, f"required_secret_names.{worker}")
            if isinstance(name, str)
        }
        for settings_key in (
            "root_worker_settings",
            "signup_worker_settings",
            "synthetic_receiver_worker_settings",
        ):
            settings = _mapping(cloudflare.get(settings_key), f"cloudflare.{settings_key}")
            vars_map = _mapping(settings.get("vars"), f"{settings_key}.vars")
            if vars_map.get("ENVIRONMENT") != "staging":
                raise ContractError("Worker environment var must remain staging")
            for name, value in vars_map.items():
                if name in secret_names:
                    raise ContractError("a secret name was placed in non-secret vars")
                if isinstance(value, str) and PRODUCTION_NAME.search(value):
                    raise ContractError("non-secret Worker vars contain a production target")
        signup_vars = _mapping(
            _mapping(cloudflare.get("signup_worker_settings"), "signup settings").get("vars"),
            "signup_worker_settings.vars",
        )
        if signup_vars.get("CORELINK_API_BASE") != self.canonical_origin:
            raise ContractError("signup API base must match canonical_origin")

        for raw_database in _list(cloudflare.get("d1"), "cloudflare.d1"):
            database = _mapping(raw_database, "D1 entry")
            _require_staging_name(_string(database.get("database_name"), "D1 database name"), "D1 database name")
            if not UUID.fullmatch(_string(database.get("database_id"), "D1 database ID")):
                raise ContractError("D1 database ID is malformed")
            for raw_binding in _list(database.get("bindings"), "D1 bindings"):
                binding = _mapping(raw_binding, "D1 binding")
                if binding.get("worker") not in workers:
                    raise ContractError("D1 binding references an unexpected Worker")

        for raw_bucket in _list(cloudflare.get("r2"), "cloudflare.r2"):
            bucket = _mapping(raw_bucket, "R2 entry")
            _require_staging_name(_string(bucket.get("bucket_name"), "R2 bucket name"), "R2 bucket name")
            if bucket.get("worker") not in workers:
                raise ContractError("R2 binding references an unexpected Worker")

        for raw_namespace in _list(cloudflare.get("kv"), "cloudflare.kv"):
            namespace = _mapping(raw_namespace, "KV entry")
            _require_staging_name(_string(namespace.get("namespace_title"), "KV namespace name"), "KV namespace name")
            if not HEX_ID.fullmatch(_string(namespace.get("namespace_id"), "KV namespace ID")):
                raise ContractError("KV namespace ID is malformed")
            if namespace.get("worker") not in workers:
                raise ContractError("KV binding references an unexpected Worker")

        for raw_binding in _list(cloudflare.get("durable_objects"), "cloudflare.durable_objects"):
            if _mapping(raw_binding, "Durable Object binding").get("worker") not in workers:
                raise ContractError("Durable Object binding references an unexpected Worker")

        for raw_queue in _list(cloudflare.get("queues"), "cloudflare.queues"):
            queue = _mapping(raw_queue, "queue entry")
            _require_staging_name(_string(queue.get("queue_name"), "queue name"), "queue name")
            _require_staging_name(_string(queue.get("dead_letter_queue"), "dead-letter queue name"), "dead-letter queue name")
            if not HEX_ID.fullmatch(_string(queue.get("queue_id"), "queue ID")):
                raise ContractError("queue ID is malformed")
            if not HEX_ID.fullmatch(_string(queue.get("dead_letter_queue_id"), "dead-letter queue ID")):
                raise ContractError("dead-letter queue ID is malformed")
            if queue.get("consumer_worker") not in workers:
                raise ContractError("queue references an unexpected Worker")

        for raw_binding in _list(cloudflare.get("service_bindings"), "cloudflare.service_bindings"):
            binding = _mapping(raw_binding, "service binding")
            if binding.get("worker") not in workers or binding.get("service") not in workers:
                raise ContractError("service binding references an unexpected Worker")


def _require_staging_name(value: str, label: str) -> None:
    if not value or PRODUCTION_NAME.search(value) or not STAGING_SUFFIX.search(value):
        raise ContractError(f"{label} is not staging-scoped")


def _provider_endpoint(value: Any) -> str:
    endpoint = _string(value, "STAGING_R2_S3_ENDPOINT")
    try:
        parsed = urlparse(endpoint)
        port = parsed.port
    except ValueError as error:
        raise ContractError("R2 provider endpoint is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not R2_ENDPOINT_HOST.fullmatch(parsed.hostname or "")
        or port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or PRODUCTION_NAME.search(endpoint)
        or PRODUCTION_NAME.search(parsed.hostname or "")
    ):
        raise ContractError("R2 provider endpoint is invalid")
    return endpoint


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return toml_string(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise ContractError(f"unsupported TOML value type: {type(value).__name__}")


def table(name: str, values: Mapping[str, Any]) -> list[str]:
    return [f"[{name}]", *(f"{key} = {toml_value(value)}" for key, value in values.items())]


def array_table(name: str, values: Mapping[str, Any]) -> list[str]:
    return [f"[[{name}]]", *(f"{key} = {toml_value(value)}" for key, value in values.items())]


def render_worker(
    topology: StagingTopologyAdapter,
    worker: str,
    r2_endpoint: str,
    phase: str,
    output_path: Path,
) -> str:
    """Render one direct Wrangler config after adapter validation."""
    r2_endpoint = _provider_endpoint(r2_endpoint)
    settings = topology.settings_for(worker)

    def repository_path(path: str) -> str:
        return Path(os.path.relpath(ROOT / path, output_path.parent)).as_posix()

    lines = [
        "# Generated by scripts/render_staging_wrangler.py from topology.json.",
        "# Do not hand edit. This isolated config contains no inherited env tables.",
        f'name = {toml_string(worker)}',
        f'main = {toml_string(repository_path(_string(settings.get("main"), "Worker main")))}',
        "workers_dev = false",
        f'compatibility_date = {toml_string(_string(settings.get("compatibility_date"), "compatibility_date"))}',
    ]
    if settings.get("compatibility_flags"):
        lines.append(f'compatibility_flags = {toml_value(_list(settings["compatibility_flags"], "compatibility_flags"))}')

    vars_map = dict(_mapping(settings.get("vars"), "Worker vars"))
    if worker == topology.workers[0]:
        for key, value in list(vars_map.items()):
            if isinstance(value, Mapping) and value.get("source") == "provider_output":
                if value.get("name") != "r2_s3_endpoint":
                    raise ContractError("topology contains an unsupported provider output")
                vars_map[key] = r2_endpoint
            elif isinstance(value, Mapping) and value.get("source") == "github_sha":
                release = os.environ.get("GITHUB_SHA", "")
                if not GITHUB_SHA.fullmatch(release):
                    raise ContractError("GITHUB_SHA must be an exact 40-hex dispatch SHA")
                vars_map[key] = release
            elif isinstance(value, Mapping):
                raise ContractError("topology contains an unsupported root Worker value source")
    if worker == topology.workers[2]:
        lines.append('version_metadata = { binding = "CF_VERSION_METADATA" }')
    lines.extend(["", *table("vars", vars_map)])

    for route in topology.routes_for(worker, phase):
        lines.extend(["", *array_table("routes", {
            "pattern": _string(route.get("pattern"), "route.pattern"),
            "zone_name": _string(route.get("zone_name"), "route.zone_name"),
        })])

    cloudflare = topology.cloudflare
    for raw_database in _list(cloudflare.get("d1"), "cloudflare.d1"):
        database = _mapping(raw_database, "D1 entry")
        for raw_binding in _list(database.get("bindings"), "D1 bindings"):
            binding = _mapping(raw_binding, "D1 binding")
            if binding.get("worker") == worker:
                lines.extend(["", *array_table("d1_databases", {
                    "binding": _string(binding.get("binding"), "D1 binding name"),
                    "database_name": _string(database.get("database_name"), "D1 database name"),
                    "database_id": _string(database.get("database_id"), "D1 database ID"),
                    "migrations_dir": repository_path(_string(database.get("migrations_dir"), "migrations_dir")),
                })])

    for raw_bucket in _list(cloudflare.get("r2"), "cloudflare.r2"):
        bucket = _mapping(raw_bucket, "R2 entry")
        if bucket.get("worker") == worker:
            lines.extend(["", *array_table("r2_buckets", {
                "binding": _string(bucket.get("binding"), "R2 binding"),
                "bucket_name": _string(bucket.get("bucket_name"), "R2 bucket name"),
            })])

    for raw_namespace in _list(cloudflare.get("kv"), "cloudflare.kv"):
        namespace = _mapping(raw_namespace, "KV entry")
        if namespace.get("worker") == worker:
            lines.extend(["", *array_table("kv_namespaces", {
                "binding": _string(namespace.get("binding"), "KV binding"),
                "id": _string(namespace.get("namespace_id"), "KV namespace ID"),
            })])

    do_classes: list[str] = []
    for raw_binding in _list(cloudflare.get("durable_objects"), "cloudflare.durable_objects"):
        binding = _mapping(raw_binding, "Durable Object binding")
        if binding.get("worker") == worker:
            class_name = _string(binding.get("class_name"), "Durable Object class")
            if class_name not in do_classes:
                do_classes.append(class_name)
            lines.extend(["", *array_table("durable_objects.bindings", {
                "name": _string(binding.get("binding"), "Durable Object binding"),
                "class_name": class_name,
            })])
    if do_classes:
        lines.extend(["", *array_table("migrations", {"tag": "staging-v1", "new_sqlite_classes": do_classes})])

    for raw_binding in _list(cloudflare.get("service_bindings"), "cloudflare.service_bindings"):
        binding = _mapping(raw_binding, "service binding")
        if binding.get("worker") == worker:
            lines.extend(["", *array_table("services", {
                "binding": _string(binding.get("binding"), "service binding"),
                "service": _string(binding.get("service"), "service target"),
            })])

    for raw_queue in _list(cloudflare.get("queues"), "cloudflare.queues"):
        queue = _mapping(raw_queue, "queue entry")
        if queue.get("consumer_worker") != worker:
            continue
        lines.extend(["", *array_table("queues.producers", {
            "binding": _string(queue.get("producer_binding"), "queue producer binding"),
            "queue": _string(queue.get("queue_name"), "queue name"),
        })])
        lines.extend(["", *array_table("queues.consumers", {
            "queue": _string(queue.get("queue_name"), "queue name"),
            "max_batch_size": 10,
            "max_batch_timeout": 30,
            "max_retries": 10,
            "dead_letter_queue": _string(queue.get("dead_letter_queue"), "dead-letter queue"),
        })])
        lines.extend(["", *array_table("queues.consumers", {
            "queue": _string(queue.get("dead_letter_queue"), "dead-letter queue"),
            "max_batch_size": 10,
            "max_batch_timeout": 30,
            "max_retries": 3,
        })])

    if worker == topology.workers[0]:
        container = _mapping(cloudflare.get("container"), "cloudflare.container")
        if container.get("worker") != worker:
            raise ContractError("container is assigned to an unexpected Worker")
        lines.extend(["", *array_table("containers", {
            "class_name": _string(container.get("class_name"), "container class"),
            "image": repository_path(_string(container.get("source"), "container source").removeprefix("./")),
            "instance_type": _string(container.get("instance_type"), "container instance type"),
            "max_instances": container.get("max_instances"),
        })])

    observability = settings.get("observability")
    if isinstance(observability, Mapping):
        lines.extend(["", *table("observability", observability)])
    crons = settings.get("crons")
    if crons is not None:
        lines.extend(["", *table("triggers", {"crons": _list(crons, "Worker crons")})])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("bootstrap", "final"), required=True)
    parser.add_argument("--worker", choices=("root", "signup", "synthetic"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        topology = StagingTopologyAdapter.from_file()
        r2_endpoint = os.environ.get("STAGING_R2_S3_ENDPOINT", "")
        worker = topology.worker_for_role(args.worker)
        output_path = args.output.resolve()
        try:
            output_path.relative_to(ROOT)
        except ValueError:
            pass
        else:
            raise ContractError("rendered configs must be written outside the repository")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            render_worker(topology, worker, r2_endpoint, args.phase, output_path),
            encoding="utf-8",
        )
        print(f"rendered {args.phase} config for {worker} to {output_path}")
    except (OSError, TypeError, ContractError, ValueError) as error:
        print(f"staging config render rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
