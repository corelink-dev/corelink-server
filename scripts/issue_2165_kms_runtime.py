#!/usr/bin/env python3
"""Bounded, fail-closed runtime operator for Issue #2165.

The manifest is a protected runtime configuration file. It must never be
created from workflow inputs or published as an artifact. This operator does
not claim a lifecycle PASS unless the production service exposes the frozen
authenticated route contract; that contract is deliberately checked before
starting a task or changing a KMS grant.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ipaddress
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import issue_2165_cf5128_readback as cf_readback

SCHEMA = "corelink-issue-2165-kms-runtime-v1"
MAX_CONCURRENT_TASKS = 2
ENVIRONMENT = "b083-kms-lifecycle"
PHASES = ("pregrant-deny", "lifecycle", "cleanup")
IMAGE_DIGEST = re.compile(r"^.+@sha256:[a-fA-F0-9]{64}$")
ACCOUNT_ID = re.compile(r"^\d{12}$")
_PROD_MARKERS = {"prod6a", "production", "prod"}


class ContractError(ValueError):
    """Manifest or live AWS state does not meet the bounded contract."""


class UnsupportedContract(ContractError):
    """The required production service contract has not been supplied."""


def _need(obj: dict[str, Any], key: str, kind: type, where: str = "manifest") -> Any:
    value = obj.get(key)
    if not isinstance(value, kind) or (kind is str and not value.strip()):
        raise ContractError(f"{where}.{key} must be {kind.__name__}")
    return value


def _no_prod(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            _no_prod(key)
            _no_prod(nested)
    elif isinstance(value, list):
        for nested in value:
            _no_prod(nested)
    elif isinstance(value, str) and value.casefold() in _PROD_MARKERS:
        raise ContractError("production target markers are forbidden")


def validate_manifest(m: dict[str, Any], now: datetime | None = None, environ: dict[str, str] | None = None, allow_expired: bool = False) -> dict[str, Any]:
    """Validate identifiers and the bounded approval envelope, without echoing secrets."""
    if m.get("schema") != SCHEMA:
        raise ContractError(f"schema must be {SCHEMA}")
    if m.get("environment") != ENVIRONMENT:
        raise ContractError(f"environment must be exactly {ENVIRONMENT}")
    _no_prod(m)
    aws = m.get("aws")
    if not isinstance(aws, dict):
        raise ContractError("aws object is required")
    account = _need(aws, "account_id", str, "aws")
    if not ACCOUNT_ID.fullmatch(account):
        raise ContractError("aws.account_id must be a 12-digit account id")
    if _need(aws, "region", str, "aws") != "us-east-1":
        raise ContractError("aws.region must be us-east-1")
    for name in ("cluster_arn", "task_definition_arn", "image_uri", "controller_role_arn", "runtime_role_arn", "execution_role_arn", "custodian_role_arn", "cmk_arn"):
        _need(aws, name, str, "aws")
    if not IMAGE_DIGEST.fullmatch(aws["image_uri"]):
        raise ContractError("aws.image_uri must use an immutable sha256 digest")
    if any(not aws[x].startswith(f"arn:aws:iam::{account}:role/") for x in ("controller_role_arn", "runtime_role_arn", "execution_role_arn", "custodian_role_arn")):
        raise ContractError("controller, runtime, execution, and custodian roles must belong to aws.account_id")
    if not aws["cmk_arn"].startswith(f"arn:aws:kms:us-east-1:{account}:key/"):
        raise ContractError("aws.cmk_arn must identify a key in the bound account and region")
    operator = m.get("operator")
    if not isinstance(operator, dict) or operator.get("container_name") != "issue-2165-operator":
        raise ContractError("operator.container_name must be issue-2165-operator")
    for name in ("task_definition_arn", "operator_role_arn", "operator_execution_role_arn", "staging_admission_key_secret_arn"):
        _need(operator, name, str, "operator")
    if not IMAGE_DIGEST.fullmatch(_need(operator, "image_uri", str, "operator")):
        raise ContractError("operator.image_uri must use an immutable sha256 digest")
    if _need(operator, "entrypoint", str, "operator") != "/usr/local/bin/issue-2165-operator":
        raise ContractError("operator.entrypoint must be the approved bounded operator executable")
    _need(operator, "internal_auth_secret_arn", str, "operator")
    wrapped_a = _need(operator, "tcs_wrapped_secret_arn_a", str, "operator")
    wrapped_b = _need(operator, "tcs_wrapped_secret_arn_b", str, "operator")
    if wrapped_a == wrapped_b or "tcs_wrapped_secret_arn" in operator:
        raise ContractError("tenant A/B wrapped TCS secret references must be distinct; legacy shared ciphertext ref is forbidden")
    pat_secret_pattern = re.compile(rf"^arn:aws:secretsmanager:us-east-1:{account}:secret:[A-Za-z0-9/_+=.@-]{{1,512}}$")
    for name in ("pat_a_secret_arn", "pat_b_secret_arn"):
        if not pat_secret_pattern.fullmatch(_need(operator, name, str, "operator")):
            raise ContractError(f"operator.{name} must be a protected same-account us-east-1 Secrets Manager ARN")
    if operator["pat_a_secret_arn"] == operator["pat_b_secret_arn"]:
        raise ContractError("operator tenant PAT secret ARNs must be distinct")
    quota = operator.get("storage_quota_bytes")
    if type(quota) is not int or quota < 128 or quota > 2**63 - 1:
        raise ContractError("operator.storage_quota_bytes must be an approved bounded positive integer")
    op_roles = [operator["operator_role_arn"], operator["operator_execution_role_arn"]]
    if len(set(op_roles + [aws["controller_role_arn"], aws["runtime_role_arn"], aws["execution_role_arn"], aws["custodian_role_arn"]])) != 6:
        raise ContractError("controller, app runtime/execution, custodian, and operator task/execution roles must be distinct")
    if aws["task_definition_arn"] == operator["task_definition_arn"]:
        raise ContractError("app and operator task definition ARNs must be distinct")
    if aws["runtime_role_arn"] == operator["operator_role_arn"]:
        raise ContractError("app runtime and operator task roles must be distinct")
    if aws["execution_role_arn"] == operator["operator_execution_role_arn"]:
        raise ContractError("app and operator execution roles must be distinct")
    if any(not role.startswith(f"arn:aws:iam::{account}:role/") for role in op_roles):
        raise ContractError("operator task roles must belong to aws.account_id")
    if not re.fullmatch(r"[a-fA-F0-9]{40}", _need(operator, "target_deployment_sha", str, "operator")):
        raise ContractError("operator.target_deployment_sha must be an exact 40-character deployment SHA")
    cf = m.get("cloudflare")
    if not isinstance(cf, dict) or cf.get("account_alias") != "cf5128":
        raise ContractError("cloudflare.account_alias must be cf5128")
    cf_account = _need(cf, "account_id", str, "cloudflare")
    d1 = cf.get("d1")
    if not isinstance(d1, dict):
        raise ContractError("cloudflare.d1 object is required")
    env = os.environ if environ is None else environ
    protected = {
        "B083_AWS_ACCOUNT_ID": aws["account_id"],
        "B083_AWS_REGION": aws["region"],
        "B083_AWS_CLUSTER_ARN": aws["cluster_arn"],
        "B083_AWS_TASK_DEFINITION_ARN": aws["task_definition_arn"],
        "B083_AWS_CONTROLLER_ROLE_ARN": aws["controller_role_arn"],
        "B083_AWS_RUNTIME_ROLE_ARN": aws["runtime_role_arn"],
        "B083_AWS_APP_EXECUTION_ROLE_ARN": aws["execution_role_arn"],
        "B083_AWS_CUSTODIAN_ROLE_ARN": aws["custodian_role_arn"],
        "B083_IMAGE_URI": aws["image_uri"],
        "B083_KMS_KEY_ARN": aws["cmk_arn"],
        "B083_AWS_OPERATOR_TASK_DEFINITION_ARN": operator["task_definition_arn"],
        "B083_AWS_OPERATOR_ROLE_ARN": operator["operator_role_arn"],
        "B083_AWS_OPERATOR_EXECUTION_ROLE_ARN": operator["operator_execution_role_arn"],
        "B083_AWS_OPERATOR_IMAGE_URI": operator["image_uri"],
        "B083_D1_REGION": d1["region"],
        "B083_CF_ACCOUNT_ID": cf_account,
    }
    for name, value in protected.items():
        if env.get(name) != value:
            raise ContractError(f"manifest {name} must exactly match its protected environment binding")
    namespace = _need(m, "run_namespace", str)
    if not re.fullmatch(r"i2165-b083-[0-9]{8}-[a-f0-9]{8}", namespace) or env.get("B083_RUN_NAMESPACE") != namespace:
        raise ContractError("run_namespace must be the exact protected temporary owned issue namespace")
    net = m.get("network")
    if not isinstance(net, dict) or net.get("public_ingress") is not False or net.get("app_port") != 50051 or net.get("assign_public_ip") is not True:
        raise ContractError("network must enable outbound public IP, disable public ingress, and bind app port 50051")
    _need(net, "vpc_id", str, "network")
    for name in ("app_security_group_id", "operator_security_group_id"):
        _need(net, name, str, "network")
    provisioning = net.get("provisioning_receipt")
    if not isinstance(provisioning, dict):
        raise ContractError("network.provisioning_receipt is required for newly owned security groups")
    _need(provisioning, "ref", str, "network.provisioning_receipt")
    digest = _need(provisioning, "sha256", str, "network.provisioning_receipt")
    if not re.fullmatch(r"[a-f0-9]{64}", digest) or env.get("B083_NETWORK_RECEIPT_SHA256") != digest:
        raise ContractError("network provisioning receipt digest must match protected B083_NETWORK_RECEIPT_SHA256")
    if provisioning.get("app_security_group_id") != net["app_security_group_id"] or provisioning.get("operator_security_group_id") != net["operator_security_group_id"]:
        raise ContractError("network provisioning receipt must bind both exact security groups")
    try:
        created = datetime.fromisoformat(_need(provisioning, "created_at", str, "network.provisioning_receipt").replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("network provisioning receipt created_at must be ISO-8601 UTC") from exc
    if created.tzinfo is None or created.utcoffset() != timedelta(0) or created > (now or datetime.now(timezone.utc)):
        raise ContractError("network provisioning receipt must have a past UTC creation time")
    subnets = net.get("routed_subnet_ids")
    if not isinstance(subnets, list) or not subnets or any(not isinstance(x, str) or not x for x in subnets):
        raise ContractError("network.routed_subnet_ids must list exact routed task subnet IDs")

    cf = m.get("cloudflare")
    if not isinstance(cf, dict) or cf.get("account_alias") != "cf5128":
        raise ContractError("cloudflare.account_alias must be cf5128")
    cf_account = _need(cf, "account_id", str, "cloudflare")
    if cf_account == "6a1fc1c626fc2628823e60b9db01f5cd":
        raise ContractError("production Cloudflare account is forbidden")
    d1, r2 = cf.get("d1"), cf.get("r2")
    if not isinstance(d1, dict) or d1.get("binding") != "B083_D1" or not _need(d1, "database_id", str, "cloudflare.d1"):
        raise ContractError("cloudflare.d1 must bind B083_D1 and a database_id")
    _need(d1, "region", str, "cloudflare.d1")
    expected_endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    if not isinstance(r2, dict) or r2.get("binding") != "B083_R2" or r2.get("region") != "auto" or r2.get("endpoint") != expected_endpoint:
        raise ContractError("cloudflare.r2 must bind B083_R2 to the exact cf5128 account endpoint in auto region")
    _need(r2, "bucket", str, "cloudflare.r2")

    tenants = m.get("disposable_tenants")
    if not isinstance(tenants, list) or len(tenants) != 2 or any(not isinstance(x, str) or not x.strip() for x in tenants) or len(set(tenants)) != 2:
        raise ContractError("exactly two distinct disposable_tenants are required")
    storage_prefixes = cf.get("r2_prefixes")
    if not isinstance(storage_prefixes, list) or len(storage_prefixes) < 2:
        raise ContractError("cloudflare.r2_prefixes must list exact disposable prefixes by serving region")
    by_tenant: dict[str, dict[str, Any]] = {}
    for item in storage_prefixes:
        if not isinstance(item, dict):
            raise ContractError("each cloudflare.r2_prefixes entry must be an object")
        tenant = _need(item, "tenant_id", str, "cloudflare.r2_prefixes")
        region = _need(item, "region", str, "cloudflare.r2_prefixes")
        prefix = _need(item, "prefix", str, "cloudflare.r2_prefixes")
        if tenant not in tenants:
            raise ContractError("cloudflare.r2_prefixes must only identify disposable tenants")
        if prefix.startswith("/") or ".." in prefix or "*" in prefix or not prefix.startswith(region + "/") or not prefix.endswith("/"):
            raise ContractError("each disposable R2 prefix must be a confined exact region/prefix path")
        by_tenant.setdefault(tenant, {})
        if region in by_tenant[tenant]:
            raise ContractError("cloudflare.r2_prefixes must contain unique tenant/region entries")
        by_tenant[tenant][region] = prefix
    if set(by_tenant) != set(tenants):
        raise ContractError("cloudflare.r2_prefixes must cover both disposable tenants")
    sink = m.get("audit_sink")
    if not isinstance(sink, dict) or sink.get("durable") is not True:
        raise ContractError("audit_sink must identify a durable sink")
    _need(sink, "kind", str, "audit_sink")
    _need(sink, "target_id", str, "audit_sink")
    if sink.get("kind") != "d1-audit-outbox+r2-archive" or sink.get("d1_table") != "audit_outbox":
        raise ContractError("audit_sink must bind the durable D1 audit_outbox and R2 archive")
    expected_columns = ["id", "tenant_id", "digest", "request_id", "event_type", "payload_json", "enqueued_at", "emitted_at"]
    if sink.get("d1_columns") != expected_columns:
        raise ContractError("audit_sink.d1_columns must match the native audit_outbox schema")
    if sink.get("r2_bucket") != r2["bucket"]:
        raise ContractError("audit_sink.r2_bucket must match the bound B083_R2 bucket")
    archive_key = _need(sink, "r2_archive_key", str, "audit_sink")
    if not archive_key.startswith("issue-2165/") or "/audit/" not in archive_key or ".." in archive_key or archive_key.startswith("/"):
        raise ContractError("audit_sink.r2_archive_key must be a confined retained per-run audit object key")
    outbox_refs = m.get("audit_outbox_refs")
    if not isinstance(outbox_refs, list) or len(outbox_refs) > 10:
        raise ContractError("audit_outbox_refs must be a list of zero to ten D1-backed receipt refs")
    pairs: set[tuple[str, str]] = set()
    requests: set[str] = set()
    for ref in outbox_refs:
        if not isinstance(ref, dict):
            raise ContractError("each audit_outbox_refs entry must be an object")
        request_id = _need(ref, "request_id", str, "audit_outbox_refs")
        event_type = _need(ref, "event_type", str, "audit_outbox_refs")
        if (request_id, event_type) in pairs or request_id in requests:
            raise ContractError("audit_outbox_refs request IDs and request/event pairs must be unique")
        pairs.add((request_id, event_type))
        requests.add(request_id)
    expires = _need(m, "expires_at", str)
    try:
        expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("expires_at must be an ISO-8601 UTC timestamp") from exc
    if expiry.tzinfo is None or expiry.utcoffset() != timedelta(0):
        raise ContractError("expires_at must be UTC")
    current = now or datetime.now(timezone.utc)
    if (not allow_expired and not current < expiry <= current + timedelta(hours=24)) or (allow_expired and expiry > current + timedelta(hours=24)):
        raise ContractError("manifest must be unexpired and expire within 24 hours")
    if type(m.get("estimated_cost_usd")) not in (int, float) or not 0 < m["estimated_cost_usd"] <= 20:
        raise ContractError("estimated_cost_usd must be greater than zero and at most 20")
    approval = m.get("approval")
    if not isinstance(approval, dict) or approval.get("approved") is not True:
        raise ContractError("owner approval is required")
    for key in ("target", "rollback"):
        _need(approval, key, str, "approval")
    if "task" in m and not isinstance(m["task"], dict):
        raise ContractError("task state must be an object")
    if "grant" in m and not isinstance(m["grant"], dict):
        raise ContractError("grant state must be an object")
    return m


def read_manifest(path: Path, phase: str = "", stage: str = "run") -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ContractError("manifest must be a regular protected file")
    if not os.environ.get("B083_TARGET_MANIFEST_SECRET_ARN"):
        raise ContractError("manifest must be fetched through protected B083_TARGET_MANIFEST_SECRET_ARN")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp or path.parent.resolve() != Path(runner_temp).resolve():
        raise ContractError("manifest file must be confined directly under RUNNER_TEMP")
    if path.stat().st_mode & 0o077:
        raise ContractError("manifest file permissions must exclude group and other access")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("manifest JSON must be an object")
    return validate_manifest(data, environ=os.environ, allow_expired=phase == "cleanup" or stage == "cleanup")


def _aws(*args: str, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    try:
        result = runner(["aws", *args, "--region", "us-east-1", "--output", "json"], check=True, capture_output=True, text=True, timeout=45)
        value = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise ContractError(f"AWS CLI operation failed ({args[0]}): {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"AWS CLI operation {args[0]} returned a non-object")
    return value


def verify_live_target(m: dict[str, Any], runner: Callable[..., Any] = subprocess.run) -> None:
    aws = m["aws"]
    operator = m["operator"]
    ident = _aws("sts", "get-caller-identity", runner=runner)
    if ident.get("Account") != aws["account_id"] or not _assumed_role_matches(ident.get("Arn", ""), aws["controller_role_arn"]):
        raise ContractError("active AWS identity must be the exact protected controller role in manifest account")
    desc = _aws("ecs", "describe-task-definition", "--task-definition", aws["task_definition_arn"], runner=runner).get("taskDefinition", {})
    app_containers = desc.get("containerDefinitions", [])
    app = app_containers[0] if len(app_containers) == 1 else {}
    operator_desc = _aws("ecs", "describe-task-definition", "--task-definition", operator["task_definition_arn"], runner=runner).get("taskDefinition", {})
    operator_containers = operator_desc.get("containerDefinitions", [])
    sidecar = operator_containers[0] if len(operator_containers) == 1 else {}
    sidecar_secrets = {s.get("name"): s.get("valueFrom") for s in sidecar.get("secrets", []) if isinstance(s, dict)}
    expected_refs = _expected_operator_secret_refs(m, os.environ)
    sidecar_environment = {e.get("name"): e.get("value") for e in sidecar.get("environment", []) if isinstance(e, dict)}
    if {"ISSUE_2165_TENANTS_JSON", "ISSUE_2165_PAT_A", "ISSUE_2165_PAT_B"} & set(sidecar_environment):
        raise ContractError("tenant identifiers and PATs must be injected only from protected Secrets Manager task secret refs")
    if sidecar_environment.get("ISSUE_2165_STORAGE_QUOTA_BYTES") != str(operator["storage_quota_bytes"]):
        raise ContractError("operator task definition storage quota must match the exact protected manifest value")
    if (
        desc.get("taskDefinitionArn") != aws["task_definition_arn"]
        or desc.get("taskRoleArn") != aws["runtime_role_arn"]
        or desc.get("executionRoleArn") != aws["execution_role_arn"]
        or desc.get("networkMode") != "awsvpc"
        or "FARGATE" not in desc.get("requiresCompatibilities", [])
        or len(app_containers) != 1
        or app.get("image") != aws["image_uri"]
        or operator_desc.get("taskDefinitionArn") != operator["task_definition_arn"]
        or operator_desc.get("taskRoleArn") != operator["operator_role_arn"]
        or operator_desc.get("executionRoleArn") != operator["operator_execution_role_arn"]
        or operator_desc.get("networkMode") != "awsvpc"
        or "FARGATE" not in operator_desc.get("requiresCompatibilities", [])
        or len(operator_containers) != 1
        or sidecar.get("name") != operator["container_name"]
        or sidecar.get("image") != operator["image_uri"]
        or sidecar.get("entryPoint") != [operator["entrypoint"]]
        or sidecar_secrets != expected_refs
    ):
        raise ContractError("live app/operator Fargate task definitions must match exact images, distinct roles, entrypoint, and protected secret refs")


    cluster = _aws("ecs", "describe-clusters", "--clusters", aws["cluster_arn"], runner=runner).get("clusters", [])
    if len(cluster) != 1 or cluster[0].get("clusterArn") != aws["cluster_arn"] or cluster[0].get("status") != "ACTIVE":
        raise ContractError("live ECS cluster is not the exact active manifest cluster")
    app_sg = _aws("ec2", "describe-security-groups", "--group-ids", m["network"]["app_security_group_id"], runner=runner).get("SecurityGroups", [])
    op_sg = _aws("ec2", "describe-security-groups", "--group-ids", m["network"]["operator_security_group_id"], runner=runner).get("SecurityGroups", [])
    if len(app_sg) != 1 or len(op_sg) != 1 or app_sg[0].get("VpcId") != m["network"]["vpc_id"] or op_sg[0].get("VpcId") != m["network"]["vpc_id"]:
        raise ContractError("app and operator security groups must be in the exact protected VPC")
    expected_tags = {"Issue": "2165", "Environment": "nonprod", "Owner": "Support03", "RunNamespace": m["run_namespace"]}
    for security_group in (app_sg[0], op_sg[0]):
        tags = {tag.get("Key"): tag.get("Value") for tag in security_group.get("Tags", [])}
        if any(tags.get(key) != value for key, value in expected_tags.items()):
            raise ContractError("both exact security groups must carry the protected issue/nonprod/owner/run namespace tags")
    _validate_security_group_rules(app_sg[0], op_sg[0], m["network"])
    for subnet_id in m["network"]["routed_subnet_ids"]:
        subnet_rows = _aws("ec2", "describe-subnets", "--subnet-ids", subnet_id, runner=runner).get("Subnets", [])
        if len(subnet_rows) != 1 or subnet_rows[0].get("VpcId") != m["network"]["vpc_id"]:
            raise ContractError("selected task subnet must belong to the exact manifest VPC")
        tables = _aws("ec2", "describe-route-tables", "--filters", f"Name=association.subnet-id,Values={subnet_id}", runner=runner).get("RouteTables", [])
        if not tables:
            tables = _aws("ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={m['network']['vpc_id']}", "Name=association.main,Values=true", runner=runner).get("RouteTables", [])
        if len(tables) != 1 or tables[0].get("VpcId") != m["network"]["vpc_id"] or not any(r.get("DestinationCidrBlock") == "0.0.0.0/0" and str(r.get("GatewayId", "")).startswith("igw-") and r.get("State") == "active" for r in tables[0].get("Routes", [])):
            raise ContractError("selected subnet route table must have an active default route to the existing IGW")


def _expected_operator_secret_refs(m: dict[str, Any], environ: dict[str, str]) -> dict[str, str]:
    operator = m["operator"]
    account = m["aws"]["account_id"]
    manifest_arn = environ.get("B083_TARGET_MANIFEST_SECRET_ARN", "")
    pattern = re.compile(rf"^arn:aws:secretsmanager:us-east-1:{account}:secret:[A-Za-z0-9/_+=.@-]{{1,512}}$")
    if not pattern.fullmatch(manifest_arn):
        raise ContractError("protected manifest secret ARN must be same-account us-east-1 Secrets Manager")
    return {
        "CORELINK_INTERNAL_AUTH_KEY": operator["internal_auth_secret_arn"],
        "CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY": operator["staging_admission_key_secret_arn"],
        "ISSUE_2165_TCS_WRAPPED_B64_A": operator["tcs_wrapped_secret_arn_a"],
        "ISSUE_2165_TCS_WRAPPED_B64_B": operator["tcs_wrapped_secret_arn_b"],
        "ISSUE_2165_TENANTS_JSON": f"{manifest_arn}:disposable_tenants::",
        "ISSUE_2165_PAT_A": operator["pat_a_secret_arn"],
        "ISSUE_2165_PAT_B": operator["pat_b_secret_arn"],
    }


def _assumed_role_matches(caller_arn: str, role_arn: str) -> bool:
    assumed = caller_arn.split(":assumed-role/", 1)
    if len(assumed) != 2:
        return False
    caller_name = assumed[1].split("/", 1)[0]
    role_name = role_arn.rsplit("/", 1)[-1]
    return caller_name == role_name


def _validate_security_group_rules(app_sg: dict[str, Any], op_sg: dict[str, Any], network: dict[str, Any]) -> None:
    """Require one-way operator-to-app ingress and exact scoped outbound rules."""
    ingress = app_sg.get("IpPermissions", [])
    ingress_ok = (len(ingress) == 1 and ingress[0].get("IpProtocol") == "tcp"
                  and ingress[0].get("FromPort") == 50051 and ingress[0].get("ToPort") == 50051
                  and {g.get("GroupId") for g in ingress[0].get("UserIdGroupPairs", [])} == {network["operator_security_group_id"]}
                  and not ingress[0].get("IpRanges") and not ingress[0].get("Ipv6Ranges"))
    if not ingress_ok:
        raise ContractError("app security group must allow only operator security group ingress on TCP 50051")
    if op_sg.get("IpPermissions", []):
        raise ContractError("operator security group must have no inbound rules")
    egress = op_sg.get("IpPermissionsEgress", [])
    egress_rules = {(r.get("IpProtocol"), r.get("FromPort"), r.get("ToPort"), tuple(sorted(g.get("GroupId", "") for g in r.get("UserIdGroupPairs", []))), tuple(sorted(c.get("CidrIp", "") for c in r.get("IpRanges", [])))) for r in egress}
    expected_egress = {
        ("tcp", 50051, 50051, (network["app_security_group_id"],), ()),
        ("tcp", 443, 443, (), ("0.0.0.0/0",)),
    }
    if egress_rules != expected_egress or any(r.get("Ipv6Ranges") for r in egress):
        raise ContractError("operator security group egress must be app TCP 50051 plus outbound TLS TCP 443 only")
    app_egress = app_sg.get("IpPermissionsEgress", [])
    app_egress_ok = (len(app_egress) == 1 and app_egress[0].get("IpProtocol") == "tcp"
                     and app_egress[0].get("FromPort") == 443 and app_egress[0].get("ToPort") == 443
                     and [x.get("CidrIp") for x in app_egress[0].get("IpRanges", [])] == ["0.0.0.0/0"]
                     and not app_egress[0].get("UserIdGroupPairs") and not app_egress[0].get("Ipv6Ranges"))
    if not app_egress_ok:
        raise ContractError("app security group egress must allow outbound TLS TCP 443 only")


def run_phase(phase: str, m: dict[str, Any], evidence_dir: Path, runner: Callable[..., Any] = subprocess.run, stage: str = "run") -> None:
    if phase == "cleanup" and stage == "run":
        stage = "cleanup"
    if stage == "cleanup":
        _cleanup_handoff(m, evidence_dir, runner)
        return
    if stage not in {"run", "start", "observe", "cleanup"}:
        raise ContractError("stage must be run, start, observe, or cleanup")
    verify_live_target(m, runner)
    capture_failure_retry = phase == "pregrant-deny" and os.environ.get("B083_CAPTURE_FAILURE_RETRY") == "1"
    pregrant_d1_before = None
    if capture_failure_retry:
        token = os.environ.get("B083_CF_API_TOKEN", "")
        if not token:
            raise ContractError("failure-retry source capture requires the protected CF5128 read-only token")
        pregrant_d1_before = _failure_retry_d1_snapshot(m, token)
    if stage != "run":
        if stage in {"start", "observe"} and phase != "lifecycle":
            raise ContractError("start/observe handoff stages are available only for lifecycle")
        if stage == "cleanup" and phase not in {"lifecycle", "cleanup"}:
            raise ContractError("cleanup handoff stage is available only for lifecycle or cleanup")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        if not re.fullmatch(r"[A-Za-z0-9-]{1,36}", run_id):
            raise ContractError("GITHUB_RUN_ID must be a bounded opaque run identifier")
        if stage == "start":
            app_task = _start_task(m, m["aws"]["task_definition_arn"], "app", run_id, runner)
            try:
                app_origin = _resolve_app_origin(m, app_task, runner)
                op_task = _start_task(m, m["operator"]["task_definition_arn"], "operator", run_id, runner, app_origin=app_origin, allowed_existing_task_arns=(app_task,))
                _task_private_ip(m, op_task, m["network"]["operator_security_group_id"], runner)
            except BaseException:
                _stop_exact_task(m["aws"]["cluster_arn"], app_task, runner)
                raise
            try:
                _write_handoff_outputs(app_task, op_task, run_id)
            except BaseException:
                _stop_exact_task(m["aws"]["cluster_arn"], op_task, runner)
                _stop_exact_task(m["aws"]["cluster_arn"], app_task, runner)
                raise
            return
        handoff = _read_handoff(m, run_id, runner)
        if stage == "observe":
            _resolve_app_origin(m, handoff["app_task_arn"], runner)
            _task_private_ip(m, handoff["operator_task_arn"], m["network"]["operator_security_group_id"], runner)
            execution: dict[str, Any] = {}
            raw_exec_response: list[str] = []
            rows = _exec_operator(m, handoff["operator_task_arn"], "lifecycle", runner, provenance_out=execution, raw_response_out=raw_exec_response)
            _validate_operator_result(rows, "lifecycle")
            source_receipts = _audit_source_receipts(rows, execution)
            lifecycle_rows = _runtime_lifecycle_rows(rows)
            evidence_dir.mkdir(parents=True, exist_ok=True)
            path = evidence_dir / "lifecycle-route-observations.json"
            path.write_text(json.dumps({"schema": "corelink.issue-2165-kms-runtime-route-observations-v1", "phase": "lifecycle", "observations": rows}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            path.chmod(0o600)
            exec_path = evidence_dir / "lifecycle-ecs-exec-source.json"
            runtime_source = {"provenance": execution, "raw_response": raw_exec_response[0], "response_rows": rows}
            exec_path.write_text(json.dumps(runtime_source, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            exec_path.chmod(0o600)
            receipt_path = evidence_dir / "lifecycle-audit-source-receipts.json"
            receipt_path.write_text(json.dumps(source_receipts, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            receipt_path.chmod(0o600)
            _write_audit_source_receipts_output(source_receipts)
            _write_runtime_lifecycle_rows_output(lifecycle_rows)
            output_path = os.environ.get("GITHUB_OUTPUT", "")
            if not output_path:
                raise ContractError("GITHUB_OUTPUT is required for restricted lifecycle Exec evidence handoff")
            with open(output_path, "a", encoding="utf-8") as stream:
                stream.write("lifecycle_exec_source_json=" + json.dumps(runtime_source, sort_keys=True, separators=(",", ":")) + "\n")
            return
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,36}", run_id):
        raise ContractError("GITHUB_RUN_ID must be a bounded opaque run identifier")
    app_task: str | None = None
    operator_tasks: list[str] = []
    operator_task: str | None = None
    route_results: list[dict[str, Any]] = []
    pregrant_exec: dict[str, Any] = {}
    pregrant_raw_response: list[str] = []
    primary_error: BaseException | None = None
    try:
        app_task = _start_task(m, m["aws"]["task_definition_arn"], "app", run_id, runner)
        app_origin = _resolve_app_origin(m, app_task, runner)
        operator_task = _start_task(m, m["operator"]["task_definition_arn"], "operator", run_id, runner, app_origin=app_origin, allowed_existing_task_arns=(app_task,))
        operator_tasks.append(operator_task)
        _task_private_ip(m, operator_task, m["network"]["operator_security_group_id"], runner)
        route_results = _exec_operator(
            m, operator_task, phase, runner,
            provenance_out=pregrant_exec if capture_failure_retry else None,
            raw_response_out=pregrant_raw_response if capture_failure_retry else None,
        )
        _validate_operator_result(route_results, phase)
        if capture_failure_retry:
            assert pregrant_d1_before is not None
            pregrant_d1_after = _failure_retry_d1_snapshot(m, os.environ["B083_CF_API_TOKEN"])
            if pregrant_d1_before["rows"] != pregrant_d1_after["rows"]:
                raise ContractError("pregrant activation denial changed the exact D1 tenant BYOK configuration rows")
            by_slot: dict[str, dict[str, Any]] = {}
            for row in route_results:
                slot = row.get("slot")
                request_hash = row.get("request_body_sha256")
                if slot not in {"tenant_a", "tenant_b"} or not isinstance(request_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", request_hash) or slot in by_slot:
                    raise ContractError("pregrant sidecar rows must bind both tenant slots to request-body SHA-256")
                by_slot[slot] = {"slot": slot, "status": row["status"],
                                 "request_started_at_utc": row.get("request_started_at_utc"),
                                 "observed_at_utc": row.get("observed_at_utc"),
                                 "request_body_sha256": request_hash}
            if set(by_slot) != {"tenant_a", "tenant_b"}:
                raise ContractError("pregrant evidence must cover both tenant slots")
            evidence = {
                "schema": "corelink.issue-2165-failure-retry-pregrant-v1",
                "run_id": run_id,
                "bindings": {"account_id": m["aws"]["account_id"], "region": m["aws"]["region"],
                             "cmk_arn": m["aws"]["cmk_arn"], "cluster_arn": m["aws"]["cluster_arn"],
                             "task_definition_arn": m["aws"]["task_definition_arn"], "runtime_role_arn": m["aws"]["runtime_role_arn"],
                             "image_uri": m["aws"]["image_uri"]},
                "app_task_arn": app_task, "operator_task_arn": operator_task,
                "exec_provenance": pregrant_exec, "exec_response_sha256": pregrant_exec["execute_response_sha256"],
                "route_rows": [by_slot[slot] for slot in ("tenant_a", "tenant_b")],
                "d1_before": pregrant_d1_before, "d1_after": pregrant_d1_after,
            }
            evidence["evidence_sha256"] = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            evidence_dir.mkdir(parents=True, exist_ok=True)
            evidence_path = evidence_dir / "pregrant-failure-retry-evidence.json"
            evidence_path.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            evidence_path.chmod(0o600)
            output = {
                "schema": evidence["schema"], "run_id": run_id, "bindings": evidence["bindings"],
                "app_task_arn": app_task, "operator_task_arn": operator_task,
                "exec_provenance": pregrant_exec,
                "route_rows": evidence["route_rows"],
                "d1_before": _failure_retry_d1_public(pregrant_d1_before, m),
                "d1_after": _failure_retry_d1_public(pregrant_d1_after, m),
                "evidence_sha256": evidence["evidence_sha256"],
            }
            github_output = os.environ.get("GITHUB_OUTPUT", "")
            if not github_output:
                raise ContractError("GITHUB_OUTPUT is required for failure-retry pregrant handoff")
            with open(github_output, "a", encoding="utf-8") as stream:
                stream.write("failure_retry_pregrant_json=" + json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
        evidence_dir.mkdir(parents=True, exist_ok=True)
        out = evidence_dir / f"{phase}-route-observations.json"
        out.write_text(json.dumps({"schema": "corelink.issue-2165-sidecar.v1", "phase": phase, "run_id": run_id, "observations": route_results}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        out.chmod(0o600)
        if phase == "lifecycle":
            raise UnsupportedContract("both authenticated BYOK activation routes returned real HTTP responses, but the operator helper supplies partial route observations only; ten unique audit:// lifecycle receipts, audit sink readback, and run_loop revoke_restore p99 proof are still required")
        if phase == "cleanup":
            _stop_exact_task(m["aws"]["cluster_arn"], operator_task, runner)
            operator_tasks.remove(operator_task)
            operator_task = None
            _stop_exact_task(m["aws"]["cluster_arn"], app_task, runner)
            app_task = None
            cleanup(m, evidence_dir, runner)
    except BaseException as exc:
        primary_error = exc
    finally:
        if phase == "lifecycle" and operator_task and route_results:
            try:
                cleanup_rows = _exec_operator(m, operator_task, "cleanup", runner)
                _validate_operator_result(cleanup_rows, "cleanup")
            except (ContractError, OSError, subprocess.SubprocessError) as cleanup_exc:
                if primary_error is None:
                    primary_error = cleanup_exc
        for task in list(operator_tasks):
            try:
                _stop_exact_task(m["aws"]["cluster_arn"], task, runner)
            except (ContractError, OSError, subprocess.SubprocessError) as cleanup_exc:
                if primary_error is None:
                    primary_error = cleanup_exc
        if app_task:
            try:
                _stop_exact_task(m["aws"]["cluster_arn"], app_task, runner)
            except (ContractError, OSError, subprocess.SubprocessError) as cleanup_exc:
                if primary_error is None:
                    primary_error = cleanup_exc
    if primary_error is not None:
        raise primary_error


def _write_handoff_outputs(app_task: str, operator_task: str, run_id: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise ContractError("GITHUB_OUTPUT is required for protected task handoff")
    # These are nonsecret task/run identifiers needed by the next protected
    # job. Keep them out of logs and artifacts; GITHUB_OUTPUT is the handoff.
    with open(output_path, "a", encoding="utf-8") as stream:
        stream.write(f"app_task_arn={app_task}\noperator_task_arn={operator_task}\nruntime_run_id={run_id}\n")


def _read_handoff(m: dict[str, Any], run_id: str, runner: Callable[..., Any], allow_stopped: bool = False, allow_expired: bool = False) -> dict[str, str]:
    names = {
        "app_task_arn": "B083_ISSUE2165_APP_TASK_ARN",
        "operator_task_arn": "B083_ISSUE2165_OPERATOR_TASK_ARN",
        "runtime_run_id": "B083_ISSUE2165_RUN_ID",
    }
    result = {key: os.environ.get(env_name, "") for key, env_name in names.items()}
    if result["runtime_run_id"] != run_id or any(not result[key] for key in ("app_task_arn", "operator_task_arn")):
        raise ContractError("protected lifecycle task handoff environment is incomplete or belongs to another run")
    for name, task_arn, task_definition in (
        ("app", result["app_task_arn"], m["aws"]["task_definition_arn"]),
        ("operator", result["operator_task_arn"], m["operator"]["task_definition_arn"]),
    ):
        tasks = _aws("ecs", "describe-tasks", "--cluster", m["aws"]["cluster_arn"], "--tasks", task_arn, "--include", "TAGS", runner=runner).get("tasks", [])
        allowed_status = {"RUNNING", "STOPPED"} if allow_stopped else {"RUNNING"}
        if len(tasks) != 1 or tasks[0].get("taskArn") != task_arn or tasks[0].get("taskDefinitionArn") != task_definition or tasks[0].get("clusterArn") != m["aws"]["cluster_arn"] or tasks[0].get("lastStatus") not in allowed_status:
            raise ContractError(f"protected {name} task handoff does not resolve to the exact running/stopped task")
        tags = {tag.get("key"): tag.get("value") for tag in tasks[0].get("tags", [])}
        expected_tags = {"Issue": "2165", "Environment": "nonprod", "Owner": "Support03", "RunNamespace": m["run_namespace"]}
        if tasks[0].get("startedBy") != run_id or any(tags.get(k) != v for k, v in expected_tags.items()):
            raise ContractError(f"protected {name} task handoff does not match this run's exact owned task tags")
        if not allow_expired:
            try:
                started = datetime.fromisoformat(str(tasks[0].get("startedAt", "")).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ContractError(f"protected {name} task has no valid startedAt timestamp") from exc
            if started.tzinfo is None or datetime.now(timezone.utc) - started > timedelta(minutes=60):
                raise ContractError(f"protected {name} task exceeded the 60-minute runtime bound")
    return result


def _cleanup_handoff(m: dict[str, Any], evidence_dir: Path, runner: Callable[..., Any]) -> None:
    identity = _aws("sts", "get-caller-identity", runner=runner)
    if identity.get("Account") != m["aws"]["account_id"] or not _assumed_role_matches(identity.get("Arn", ""), m["aws"]["controller_role_arn"]):
        raise ContractError("task cleanup requires the exact controller role in the manifest account")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,36}", run_id):
        raise ContractError("GITHUB_RUN_ID must be a bounded opaque run identifier")
    handoff = _read_handoff(m, run_id, runner, allow_stopped=True, allow_expired=True)
    errors: list[str] = []
    tasks: dict[str, dict[str, Any]] = {}
    for name, arn in (("app", handoff["app_task_arn"]), ("operator", handoff["operator_task_arn"])):
        rows = _aws("ecs", "describe-tasks", "--cluster", m["aws"]["cluster_arn"], "--tasks", arn, runner=runner).get("tasks", [])
        if len(rows) == 1:
            tasks[name] = rows[0]
    if len(tasks) != 2:
        errors.append("cleanup could not verify both exact handoff tasks")
    elif tasks["app"].get("lastStatus") == "RUNNING" and tasks["operator"].get("lastStatus") == "RUNNING":
        try:
            _validate_operator_result(_exec_operator(m, handoff["operator_task_arn"], "cleanup", runner), "cleanup")
        except (ContractError, OSError, subprocess.SubprocessError) as exc:
            errors.append(f"authenticated tenant cleanup failed: {exc}")
    else:
        errors.append("one or both tasks were already stopped; tenant route cleanup could not be verified")
    for task_arn in (handoff["operator_task_arn"], handoff["app_task_arn"]):
        try:
            _stop_exact_task(m["aws"]["cluster_arn"], task_arn, runner)
        except (ContractError, OSError, subprocess.SubprocessError) as exc:
            errors.append(f"task stop failed: {exc}")
    try:
        cleanup(m, evidence_dir, runner)
    except (ContractError, OSError, subprocess.SubprocessError) as exc:
        errors.append(f"custodian/readback cleanup incomplete: {exc}")
    if errors:
        raise ContractError("; ".join(errors))


def _start_task(m: dict[str, Any], task_definition: str, kind: str, run_id: str, runner: Callable[..., Any], *, app_origin: str | None = None, allowed_existing_task_arns: tuple[str, ...] = ()) -> str:
    aws, net = m["aws"], m["network"]
    _assert_task_capacity(aws["cluster_arn"], allowed_existing_task_arns, runner)
    group = net["app_security_group_id"] if kind == "app" else net["operator_security_group_id"]
    network = "awsvpcConfiguration={subnets=[" + ",".join(net["routed_subnet_ids"]) + "],securityGroups=[" + group + "],assignPublicIp=ENABLED}"
    overrides: dict[str, Any] = {"containerOverrides": []}
    if kind == "operator":
        env = [
            {"name": "ISSUE_2165_APP_ORIGIN", "value": app_origin},
            {"name": "ISSUE_2165_RUN_ID", "value": os.environ.get("GITHUB_RUN_ID", "")},
        ]
        overrides["containerOverrides"] = [{"name": m["operator"]["container_name"], "environment": env}]
    suffix = hashlib.sha256(kind.encode() + b":" + run_id.encode()).hexdigest()[:8]
    client_token = (run_id[:26] + "-" + suffix)[:64]
    try:
        result = runner(
            ["aws", "ecs", "run-task", "--cluster", aws["cluster_arn"], "--task-definition", task_definition, "--count", "1", "--launch-type", "FARGATE", "--platform-version", "LATEST", *(["--enable-execute-command"] if kind == "operator" else []), "--network-configuration", network, "--overrides", json.dumps(overrides, separators=(",", ":")), "--tags", "key=Issue,value=2165", "key=Environment,value=nonprod", "key=Owner,value=Support03", f"key=RunNamespace,value={m['run_namespace']}", "--started-by", run_id[:36], "--client-token", client_token, "--region", "us-east-1", "--output", "json"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        result_json = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise ContractError(f"bounded ECS run-task failed: {type(exc).__name__}") from exc
    tasks = result_json.get("tasks", []) if isinstance(result_json, dict) else []
    failures = result_json.get("failures", []) if isinstance(result_json, dict) else []
    if failures or len(tasks) != 1 or not isinstance(tasks[0].get("taskArn"), str) or tasks[0].get("clusterArn") != aws["cluster_arn"] or tasks[0].get("taskDefinitionArn") != task_definition:
        raise ContractError(f"ECS run-task did not return exactly the bound {kind} task")
    task_arn = tasks[0]["taskArn"]
    for _ in range(24):
        desc = _aws("ecs", "describe-tasks", "--cluster", aws["cluster_arn"], "--tasks", task_arn, runner=runner).get("tasks", [])
        if len(desc) != 1 or desc[0].get("taskArn") != task_arn or desc[0].get("taskDefinitionArn") != task_definition:
            raise ContractError("launched ECS task no longer matches its exact task definition")
        if desc[0].get("lastStatus") == "RUNNING":
            return task_arn
        if desc[0].get("lastStatus") == "STOPPED":
            raise ContractError("bounded ECS task stopped before operator execution")
        time.sleep(5)
    raise ContractError("bounded ECS task did not reach RUNNING within 120 seconds")


def _assert_task_capacity(cluster_arn: str, allowed_existing: tuple[str, ...], runner: Callable[..., Any]) -> None:
    candidates: set[str] = set()
    for status in ("RUNNING", "PENDING", "STOPPED"):
        command = ["ecs", "list-tasks", "--cluster", cluster_arn, "--desired-status", status]
        if status == "STOPPED":
            # ECS retains stopped tasks briefly. A full page makes the set of
            # STOPPING tasks ambiguous, so wait and retry the lifecycle safely.
            command.extend(("--max-results", "100", "--no-paginate"))
        result = _aws(*command, runner=runner)
        task_arns = result.get("taskArns", [])
        if not isinstance(task_arns, list) or any(not isinstance(arn, str) or not arn for arn in task_arns):
            raise ContractError("ECS active-task inventory is malformed")
        if status == "STOPPED" and len(task_arns) >= 100:
            raise ContractError("recent stopped-task inventory is capped; refusing an ambiguous task launch")
        candidates.update(task_arns)
    if len(candidates) > 100:
        raise ContractError("ECS task inventory exceeds the bounded DescribeTasks read")
    statuses: dict[str, str] = {}
    if candidates:
        response = _aws("ecs", "describe-tasks", "--cluster", cluster_arn, "--tasks", *sorted(candidates), runner=runner)
        tasks = response.get("tasks", [])
        failures = response.get("failures", [])
        if failures or not isinstance(tasks, list) or {row.get("taskArn") for row in tasks if isinstance(row, dict)} != candidates:
            raise ContractError("ECS task status readback is incomplete or mismatched")
        for task in tasks:
            if task.get("clusterArn") != cluster_arn or not isinstance(task.get("lastStatus"), str):
                raise ContractError("ECS task status is not bound to the exact target cluster")
            statuses[task["taskArn"]] = task["lastStatus"]
    active = {arn for arn, status in statuses.items() if status != "STOPPED"}
    unexpected = active.difference(allowed_existing)
    if unexpected:
        raise ContractError("dedicated ECS cluster has an unexpected active task; refusing a third or foreign task")
    if len(active) >= MAX_CONCURRENT_TASKS:
        raise ContractError("dedicated ECS cluster is already at the two-task concurrency limit")
    if not set(allowed_existing).issubset(active):
        raise ContractError("the exact app task is no longer active before its operator partner starts")
    if any(statuses[arn] != "RUNNING" for arn in allowed_existing):
        raise ContractError("the exact app task is not RUNNING before its operator partner starts")


def _resolve_app_origin(m: dict[str, Any], task_arn: str, runner: Callable[..., Any]) -> str:
    ip = _task_private_ip(m, task_arn, m["network"]["app_security_group_id"], runner)
    return f"http://{ip}:50051"


def _failure_retry_d1_snapshot(m: dict[str, Any], token: str) -> dict[str, Any]:
    """Capture a fixed CF5128 D1 SELECT snapshot with independent zero-write metadata."""
    cf_target = m["cloudflare"]
    d1 = cf_target["d1"]
    path = f"/accounts/{cf_target['account_id']}/d1/database/{d1['database_id']}/query"
    sql = ("SELECT tenant_id, mode, cmk_provider, cmk_key_id, state, updated_at_ms "
           "FROM tenant_byok_config WHERE tenant_id IN (?, ?) ORDER BY tenant_id")
    params = list(m["disposable_tenants"])
    payload = cf_readback._api_json("POST", path, token, {"sql": sql, "params": params})
    fields = {"tenant_id", "mode", "cmk_provider", "cmk_key_id", "state", "updated_at_ms"}
    try:
        rows = cf_readback._extract_select_rows(payload, fields)
    except cf_readback.ReadbackError as exc:
        raise ContractError("failure-retry D1 snapshot did not prove an exact zero-write SELECT") from exc
    meta = payload["result"][0]["meta"]
    if meta.get("changed_db") is not False or type(meta.get("rows_written")) is not int or meta["rows_written"] != 0 or type(meta.get("changes")) is not int or meta["changes"] != 0:
        raise ContractError("failure-retry D1 snapshot must independently prove zero writes")
    rows.sort(key=lambda row: row["tenant_id"])
    return {
        "account_alias": "cf5128",
        "account_id": cf_target["account_id"],
        "method": "parameterized-select-post",
        "observed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "endpoint": cf_readback.CF_API + path,
        "database_id": d1["database_id"],
        "region": d1["region"],
        "query_sha256": hashlib.sha256(json.dumps({"sql": sql, "params": params}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "response_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "rows": rows,
        "read_only_metadata": {"changed_db": False, "rows_written": 0, "changes": 0},
    }


def _failure_retry_d1_public(snapshot: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Drop raw tenant identifiers while preserving independently checkable slot state."""
    by_id = {row["tenant_id"]: row for row in snapshot["rows"]}
    slots = []
    for slot, tenant_id in zip(("tenant_a", "tenant_b"), manifest["disposable_tenants"], strict=True):
        row = by_id[tenant_id]
        slots.append({key: row.get(key) for key in ("mode", "cmk_provider", "state", "updated_at_ms")})
        slots[-1]["slot"] = slot
    return {
        "observed_at_utc": snapshot["observed_at_utc"],
        "endpoint": snapshot["endpoint"],
        "database_id": snapshot["database_id"],
        "region": snapshot["region"],
        "query_sha256": snapshot["query_sha256"],
        "response_sha256": snapshot["response_sha256"],
        "row_count": len(snapshot["rows"]),
        "slot_states": slots,
        "read_only_metadata": snapshot["read_only_metadata"],
    }


def _task_private_ip(m: dict[str, Any], task_arn: str, expected_group: str, runner: Callable[..., Any]) -> ipaddress.IPv4Address:
    aws, net = m["aws"], m["network"]
    tasks = _aws("ecs", "describe-tasks", "--cluster", aws["cluster_arn"], "--tasks", task_arn, runner=runner).get("tasks", [])
    if len(tasks) != 1 or tasks[0].get("taskArn") != task_arn:
        raise ContractError("app task readback did not resolve exactly one app task")
    attachments = tasks[0].get("attachments", [])
    details = [d for a in attachments for d in a.get("details", []) if isinstance(d, dict)]
    eni_ids = [d.get("value") for d in details if d.get("name") == "networkInterfaceId"]
    subnet_ids = [d.get("value") for d in details if d.get("name") == "subnetId"]
    if len(eni_ids) != 1 or len(subnet_ids) != 1 or subnet_ids[0] not in net["routed_subnet_ids"]:
        raise ContractError("app task must have exactly one ENI in an approved routed subnet")
    eni = _aws("ec2", "describe-network-interfaces", "--network-interface-ids", eni_ids[0], runner=runner).get("NetworkInterfaces", [])
    if len(eni) != 1 or eni[0].get("VpcId") != net["vpc_id"] or eni[0].get("SubnetId") != subnet_ids[0] or {g.get("GroupId") for g in eni[0].get("Groups", [])} != {expected_group}:
        raise ContractError("task ENI VPC, subnet, or security group does not match the manifest")
    try:
        ip = ipaddress.ip_address(eni[0].get("PrivateIpAddress", ""))
    except ValueError as exc:
        raise ContractError("task ENI does not have a valid private IPv4 address") from exc
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private:
        raise ContractError("task ENI address must be private IPv4")
    return ip


def _exec_operator(m: dict[str, Any], task_arn: str, phase: str, runner: Callable[..., Any], *, provenance_out: dict[str, Any] | None = None, raw_response_out: list[str] | None = None) -> list[dict[str, Any]]:
    aws, operator = m["aws"], m["operator"]
    task_rows = _aws("ecs", "describe-tasks", "--cluster", aws["cluster_arn"], "--tasks", task_arn, runner=runner).get("tasks", [])
    if len(task_rows) != 1 or task_rows[0].get("taskArn") != task_arn or task_rows[0].get("clusterArn") != aws["cluster_arn"] or task_rows[0].get("taskDefinitionArn") != operator["task_definition_arn"] or task_rows[0].get("lastStatus") != "RUNNING":
        raise ContractError("ECS Exec requires the exact RUNNING operator task in the protected cluster and task definition")
    containers = task_rows[0].get("containers", [])
    image_digest = operator["image_uri"].rsplit("@", 1)[-1]
    matches = [container for container in containers if container.get("name") == operator["container_name"]]
    if len(matches) != 1 or matches[0].get("lastStatus") != "RUNNING" or matches[0].get("imageDigest") != image_digest:
        raise ContractError("ECS Exec operator container must read back the exact RUNNING immutable image digest")
    task_provenance = {
        "task_arn": task_arn,
        "cluster_arn": aws["cluster_arn"],
        "task_definition_arn": operator["task_definition_arn"],
        "image_uri": operator["image_uri"],
        "image_digest": image_digest,
    }
    command = f"{operator['entrypoint']} --phase {phase}"
    try:
        result = runner(["aws", "ecs", "execute-command", "--cluster", aws["cluster_arn"], "--task", task_arn, "--container", operator["container_name"], "--interactive", "--command", command, "--region", "us-east-1", "--output", "json"], check=True, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContractError(f"ECS Exec sidecar operation failed: {type(exc).__name__}") from exc
    rows = []
    for line in result.stdout.splitlines():
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContractError("ECS Exec stdout must contain only sanitized sidecar JSONL records") from exc
        if not isinstance(value, dict) or value.get("schema") != "corelink.issue-2165-sidecar.v1":
            raise ContractError("ECS Exec stdout contains a record outside the sanitized sidecar schema")
        rows.append(value)
    if not rows:
        raise ContractError("operator sidecar emitted no sanitized corelink.issue-2165-sidecar.v1 route result")
    if len(result.stdout.encode("utf-8")) > 65536:
        raise ContractError("operator ECS Exec response exceeds the bounded 64 KiB evidence limit")
    if any(row.get("phase") != phase for row in rows):
        raise ContractError("operator sidecar result phase does not match invocation")
    if provenance_out is not None:
        task_provenance["execute_response_sha256"] = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        task_provenance["response_rows_sha256"] = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        provenance_out.update(task_provenance)
    if raw_response_out is not None:
        raw_response_out.append(result.stdout)
    return rows


def _stop_exact_task(cluster_arn: str, task_arn: str, runner: Callable[..., Any]) -> None:
    before = _aws("ecs", "describe-tasks", "--cluster", cluster_arn, "--tasks", task_arn, runner=runner).get("tasks", [])
    if len(before) != 1 or before[0].get("taskArn") != task_arn or before[0].get("clusterArn") != cluster_arn:
        raise ContractError("task ARN does not resolve to exactly one task in the bound ECS cluster")
    if before[0].get("lastStatus") == "STOPPED":
        return
    try:
        runner(["aws", "ecs", "stop-task", "--cluster", cluster_arn, "--task", task_arn, "--reason", "Issue 2165 bounded cleanup", "--region", "us-east-1"], check=True, capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContractError(f"ECS stop-task failed: {type(exc).__name__}") from exc
    for _ in range(24):
        after = _aws("ecs", "describe-tasks", "--cluster", cluster_arn, "--tasks", task_arn, runner=runner).get("tasks", [])
        if len(after) != 1 or after[0].get("taskArn") != task_arn:
            raise ContractError("task disappeared before STOPPED state was verified")
        if after[0].get("lastStatus") == "STOPPED":
            return
        time.sleep(5)
    raise ContractError("ECS task did not reach STOPPED within 120 seconds")


def _validate_operator_result(rows: list[dict[str, Any]], phase: str) -> None:
    if phase == "lifecycle":
        expected = {
            ("tenant_a", "activate"): {202},
            ("tenant_b", "activate"): {202},
            ("tenant_a", "cas-put"): {200, 201},
            ("tenant_b", "cas-put"): {200, 201},
            ("tenant_a", "cas-get"): {200},
            ("tenant_b", "cas-get"): {200},
            ("tenant_b_to_a", "cross-tenant-deny"): {403},
        }
        observed: set[tuple[str, str]] = set()
        object_digests: dict[str, str] = {}
        for row in rows:
            key = (row.get("slot"), row.get("step"))
            if key not in expected or key in observed:
                raise ContractError("operator lifecycle rows must uniquely match the bounded activate/CAS/tenant-isolation contract")
            observed.add(key)
            if row.get("schema") != "corelink.issue-2165-sidecar.v1" or row.get("phase") != phase or row.get("status") not in expected[key]:
                raise ContractError("operator lifecycle row has an unexpected phase, schema, or HTTP status")
            allowed_keys = {"schema", "phase", "slot", "step", "status", "observed_at_utc"} | ({"request_started_at_utc", "request_body_sha256"} if key[1] == "activate" else set()) | ({"digest"} if "digest" in row else set())
            if set(row) != allowed_keys:
                raise ContractError("operator lifecycle row contains unexpected fields")
            try:
                instant = datetime.fromisoformat(str(row.get("observed_at_utc", "")).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ContractError("operator lifecycle timestamp must be UTC ISO-8601") from exc
            if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
                raise ContractError("operator lifecycle timestamp must be UTC")
            if key[1] == "activate":
                try:
                    started = datetime.fromisoformat(str(row.get("request_started_at_utc", "")).replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ContractError("operator activation request start must be UTC ISO-8601") from exc
                if started.tzinfo is None or started.utcoffset() != timedelta(0) or started > instant:
                    raise ContractError("operator activation request start must be UTC and precede its response")
                request_body_sha256 = row.get("request_body_sha256")
                if not isinstance(request_body_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", request_body_sha256):
                    raise ContractError("operator activation must bind its exact request body SHA-256")
            if key[1] in {"cas-put", "cas-get", "cross-tenant-deny"}:
                digest = row.get("digest")
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ContractError("operator CAS lifecycle row must include an exact content digest")
                if key[1] == "cas-put":
                    object_digests[key[0]] = digest
            elif "digest" in row:
                raise ContractError("BYOK activation rows must not expose content digests")
        if observed != set(expected):
            raise ContractError("operator lifecycle observations are incomplete")
        cross_digest = next(row.get("digest") for row in rows if row.get("step") == "cross-tenant-deny")
        if object_digests.get("tenant_a") != cross_digest:
            raise ContractError("cross-tenant denial must reference tenant A's exact CAS object digest")
        for tenant_slot in ("tenant_a", "tenant_b"):
            put = next(row for row in rows if row.get("slot") == tenant_slot and row.get("step") == "cas-put")
            get = next(row for row in rows if row.get("slot") == tenant_slot and row.get("step") == "cas-get")
            if put.get("digest") != get.get("digest"):
                raise ContractError("CAS GET must read back the exact tenant PUT digest")
        return
    expected_status = {"pregrant-deny": 501, "lifecycle": 202, "cleanup": 200}[phase]
    expected_route = {"pregrant-deny": "/v1/admin/byok/activate", "lifecycle": "/v1/admin/byok/activate", "cleanup": "/v1/admin/byok/deactivate"}[phase]
    if len(rows) != 2:
        raise ContractError("both disposable tenants must return exactly one authenticated route observation")
    for row in rows:
        if row.get("schema") != "corelink.issue-2165-sidecar.v1" or row.get("phase") != phase or row.get("route") != expected_route or row.get("status") != expected_status:
            raise ContractError(f"operator route did not return the exact expected HTTP {expected_status} observation")
        try:
            instant = datetime.fromisoformat(str(row.get("observed_at_utc", "")).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError("operator route observation timestamp must be UTC ISO-8601") from exc
        if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
            raise ContractError("operator route observation timestamp must be UTC")


def _audit_source_receipts(rows: list[dict[str, Any]], execution: dict[str, Any]) -> list[dict[str, Any]]:
    """Project only source-backed authenticated HTTP records into GITHUB_OUTPUT."""
    _validate_operator_result(rows, "lifecycle")
    required_provenance = {"task_arn", "cluster_arn", "task_definition_arn", "image_uri", "image_digest", "execute_response_sha256", "response_rows_sha256"}
    if not isinstance(execution, dict) or set(execution) != required_provenance:
        raise ContractError("tenant isolation receipt requires complete ECS task/image/exec-response provenance")
    if any(not isinstance(execution.get(name), str) or not execution[name] for name in required_provenance):
        raise ContractError("ECS task/image/exec-response provenance fields must be nonempty strings")
    for digest_name in ("image_digest", "execute_response_sha256", "response_rows_sha256"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}" if digest_name == "image_digest" else r"[0-9a-f]{64}", execution[digest_name]):
            raise ContractError("ECS task/image/exec-response provenance digest is malformed")
    receipts: list[dict[str, Any]] = []
    for row in rows:
        step = None
        kind = None
        if row.get("step") == "cross-tenant-deny" and row.get("status") == 403:
            step, kind = "tenant_isolation", "runtime"
        if step is None:
            continue
        digest = row["digest"]
        row_digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        task_ref = hashlib.sha256(execution["task_arn"].encode("utf-8")).hexdigest()[:16]
        exec_ref = execution["execute_response_sha256"][:16]
        observation_ref = row_digest[:16]
        receipts.append({
            "step": step,
            "occurred_at_utc": row["observed_at_utc"],
            "source": {
                "kind": kind,
                "event_ref": f"ecs-task:{task_ref}/exec:{exec_ref}/obs:{observation_ref}",
                "digest": digest,
            },
        })
    return receipts


def _write_audit_source_receipts_output(receipts: list[dict[str, Any]]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT", "")
    if not output_path:
        raise ContractError("GITHUB_OUTPUT is required for source-backed runtime receipt handoff")
    with open(output_path, "a", encoding="utf-8") as stream:
        stream.write("audit_source_receipts_json=" + json.dumps(receipts, sort_keys=True, separators=(",", ":")) + "\n")


def _runtime_lifecycle_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Export only activation status/slot and request/response bounds for the D1 collector."""
    _validate_operator_result(rows, "lifecycle")
    activations = [row for row in rows if row.get("step") == "activate"]
    if len(activations) != 2:
        raise ContractError("runtime lifecycle collector requires both bounded activation observations")
    return [
        {
            "slot": row["slot"],
            "step": "activate",
            "status": row["status"],
            "request_started_at_utc": row["request_started_at_utc"],
            "observed_at_utc": row["observed_at_utc"],
        }
        for row in sorted(activations, key=lambda item: item["slot"])
    ]


def _write_runtime_lifecycle_rows_output(rows: list[dict[str, Any]]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT", "")
    if not output_path:
        raise ContractError("GITHUB_OUTPUT is required for runtime lifecycle collector handoff")
    with open(output_path, "a", encoding="utf-8") as stream:
        stream.write("runtime_lifecycle_rows_json=" + json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n")


def cleanup(m: dict[str, Any], evidence_dir: Path, runner: Callable[..., Any] = subprocess.run) -> None:
    """Stop and verify only the exact ECS task; KMS cleanup belongs to custodian."""
    aws = m["aws"]
    state = m.get("task", {})
    task_arn = state.get("task_arn")
    if task_arn is not None and not isinstance(task_arn, str):
        raise ContractError("task.task_arn must be a string")
    task_stopped = False
    cleanup_errors: list[str] = []
    if task_arn:
        try:
            if not isinstance(task_arn, str):
                raise ContractError("task.task_arn must be a string")
            before = _aws("ecs", "describe-tasks", "--cluster", aws["cluster_arn"], "--tasks", task_arn, runner=runner).get("tasks", [])
            if len(before) != 1 or before[0].get("taskArn") != task_arn or before[0].get("clusterArn") != aws["cluster_arn"]:
                raise ContractError("task.task_arn does not resolve to exactly one task in the bound ECS cluster")
            if before[0].get("lastStatus") != "STOPPED":
                runner(["aws", "ecs", "stop-task", "--cluster", aws["cluster_arn"], "--task", task_arn, "--reason", "Issue 2165 bounded cleanup", "--region", "us-east-1"], check=True, capture_output=True, text=True, timeout=45)
                after = _aws("ecs", "describe-tasks", "--cluster", aws["cluster_arn"], "--tasks", task_arn, runner=runner).get("tasks", [])
                if len(after) != 1 or after[0].get("taskArn") != task_arn or after[0].get("lastStatus") != "STOPPED":
                    raise ContractError("ECS task stop was requested but STOPPED status is not verified")
            task_stopped = True
        except (ContractError, OSError, subprocess.SubprocessError) as exc:
            cleanup_errors.append(f"task cleanup failed: {exc}")
    if cleanup_errors:
        raise ContractError("; ".join(cleanup_errors))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report = {"schema": SCHEMA, "phase": "cleanup", "task_stopped": task_stopped, "kms_cleanup": "delegated-to-custodian-role"}
    (evidence_dir / "cleanup.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=PHASES)
    parser.add_argument("--stage", choices=("run", "start", "observe", "cleanup"), default="run")
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = read_manifest(args.manifest, phase=args.phase, stage=args.stage)
        run_phase(args.phase, manifest, args.evidence_dir, stage=args.stage)
    except (ContractError, OSError) as exc:
        print(f"Issue #2165 KMS runtime: BLOCKED: {exc}", file=sys.stderr)
        return 1
    print(f"Issue #2165 KMS runtime: {args.phase} completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
