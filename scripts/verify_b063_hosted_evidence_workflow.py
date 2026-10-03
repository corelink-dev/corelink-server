#!/usr/bin/env python3
"""Fail-closed structural checks for the B-063 hosted evidence lane."""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import yaml


WORKFLOW = Path(".github/workflows/issue-1648-b063-read-only-evidence.yml")
PYTHON_HEREDOC = re.compile(r"(?m)^[ \t]*python3? - <<'PY'\n(.*?)^[ \t]*PY[ \t]*$", re.DOTALL)
D1_QUERY_ENDPOINT = "https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}/query"
ALLOWED_PYTHON_IMPORTS = {
    ("import", "json", ()),
    ("import", "os", ()),
    ("import", "sys", ()),
    ("import", "time", ()),
    ("from", "datetime", ("datetime", "timezone")),
    ("from", "urllib.error", ("HTTPError", "URLError")),
    ("from", "urllib.request", ("Request", "urlopen")),
}


def _sql_expression(node: ast.AST) -> str:
    """Return the static SQL text and reject unreviewed dynamic fragments."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _sql_expression(node.left) + _sql_expression(node.right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "cutoff"
        and not node.keywords
    ):
        return "<numeric-cutoff>"
    raise AssertionError("SQL expression contains an unapproved dynamic fragment")


def _d1_endpoint_expression(node: ast.AST) -> str:
    """Return the one reviewed D1 endpoint shape; reject alternate targets."""
    if not isinstance(node, ast.JoinedStr):
        raise AssertionError("D1 endpoint must use the reviewed Cloudflare query URL")
    parts = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif (
            isinstance(value, ast.FormattedValue)
            and isinstance(value.value, ast.Name)
            and value.value.id in {"account", "database"}
            and value.conversion == -1
            and value.format_spec is None
        ):
            parts.append("{" + value.value.id + "}")
        else:
            raise AssertionError("D1 endpoint contains an unapproved dynamic fragment")
    return "".join(parts)


def _verify_select_only_python(run: str) -> None:
    blocks = PYTHON_HEREDOC.findall(run)
    if "/d1/database/" in run and not blocks:
        raise AssertionError("D1 endpoint must be called only from a verified Python heredoc")
    if re.search(r"(?i)\b(?:curl|wget|wrangler|node|ruby|perl)\b|\bpython3?\s+-c\b", run):
        raise AssertionError("hosted evidence lane must not use shell network or archive clients")
    for block in blocks:
        tree = ast.parse(textwrap.dedent(block))
        imports = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imports.update(("import", alias.name, ()) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(("from", node.module or "", tuple(alias.name for alias in node.names)))
        if imports != ALLOWED_PYTHON_IMPORTS:
            raise AssertionError("Python heredoc imports must remain on the reviewed read-only allowlist")
        if any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
            for node in ast.walk(tree)
        ):
            raise AssertionError("Python heredoc must not use dynamic code loading")
        request_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Request"
        ]
        urlopen_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "urlopen"
        ]
        endpoint_assignments = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "endpoint" for target in node.targets)
        ]
        sql_assignments = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "sql" for target in node.targets)
        ]
        has_network_traffic = bool(request_calls or urlopen_calls or endpoint_assignments)
        if has_network_traffic:
            if len(endpoint_assignments) != 1 or _d1_endpoint_expression(endpoint_assignments[0]) != D1_QUERY_ENDPOINT:
                raise AssertionError("Python network traffic must target only the reviewed Cloudflare D1 query endpoint")
            if len(request_calls) != 1 or len(urlopen_calls) != 1:
                raise AssertionError("Python network traffic must use one auditable D1 request")
            request = request_calls[0]
            if (
                len(request.args) != 1
                or not isinstance(request.args[0], ast.Name)
                or request.args[0].id != "endpoint"
            ):
                raise AssertionError("D1 request must use the reviewed endpoint")
            if (
                len(urlopen_calls[0].args) != 1
                or not isinstance(urlopen_calls[0].args[0], ast.Name)
                or urlopen_calls[0].args[0].id != "request"
            ):
                raise AssertionError("D1 request must be sent through the audited request object")
            if len(sql_assignments) != 1:
                raise AssertionError("every D1 network block must have one auditable SQL assignment")
        elif sql_assignments:
            raise AssertionError("SQL assignment is not bound to the reviewed D1 network path")
        if not sql_assignments:
            continue
        sql = _sql_expression(sql_assignments[0]).lstrip()
        if not re.match(r"(?i)^SELECT\b", sql):
            raise AssertionError("D1 query must be a SELECT statement")
        if ";" in sql or re.search(r"(?i)\b(?:INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|CREATE|TRUNCATE)\b", sql):
            raise AssertionError("D1 query contains a mutating SQL statement")

        query_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "query"
        ]
        if not query_calls or any(
            len(call.args) != 1 or not isinstance(call.args[0], ast.Name) or call.args[0].id != "sql"
            for call in query_calls
        ):
            raise AssertionError("D1 query calls must use the audited SQL assignment")

        query_functions = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "query"
        ]
        if len(query_functions) != 1:
            raise AssertionError("audited SQL must use exactly one query function")
        query_function = query_functions[0]
        posts_sql = False
        for call in ast.walk(query_function):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "Request":
                continue
            post_method = any(
                keyword.arg == "method" and isinstance(keyword.value, ast.Constant) and keyword.value.value == "POST"
                for keyword in call.keywords
            )
            sends_sql = any(
                isinstance(node, ast.Dict)
                and any(
                    isinstance(key, ast.Constant)
                    and key.value == "sql"
                    and isinstance(value, ast.Name)
                    and value.id == "sql"
                    for key, value in zip(node.keys, node.values)
                )
                for node in ast.walk(call)
            )
            posts_sql = posts_sql or (post_method and sends_sql)
        if not posts_sql:
            raise AssertionError("query function must POST the audited SQL field to D1")


def verify(source: str) -> None:
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    if not isinstance(workflow, dict):
        raise AssertionError("B-063 workflow must be a YAML mapping")

    triggers = workflow.get("on", {})
    if not isinstance(triggers, dict) or "workflow_dispatch" not in triggers or "pull_request" not in triggers:
        raise AssertionError("both dispatch and pull-request contract paths are required")
    pull_request_paths = triggers["pull_request"].get("paths", [])
    for required_path in (
        str(WORKFLOW),
        "scripts/verify_b063_hosted_evidence_workflow.py",
        "scripts/test_verify_b063_hosted_evidence_workflow.py",
    ):
        if required_path not in pull_request_paths:
            raise AssertionError(f"PR path filter must include {required_path}")

    dispatch_inputs = triggers["workflow_dispatch"].get("inputs", {})
    if "environment" in dispatch_inputs:
        raise AssertionError("live-read approval environment must not be user-selectable")
    if dispatch_inputs.get("run_live", {}).get("default") != "false":
        raise AssertionError("live D1 reads must default to disabled")
    if dispatch_inputs.get("read_only", {}).get("options") != ["true"]:
        raise AssertionError("dispatch must not admit a non-read-only mode")
    if dispatch_inputs.get("lag_hours", {}).get("options") != ["3"]:
        raise AssertionError("dispatch must keep the approved three-hour threshold")

    permissions = [workflow.get("permissions", {})]
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        raise AssertionError("workflow jobs must be a mapping")
    permissions.extend(job.get("permissions", {}) for job in jobs.values() if isinstance(job, dict))
    for permission_set in permissions:
        if not isinstance(permission_set, dict) or any(value != "read" for value in permission_set.values()):
            raise AssertionError("workflow permissions must remain read-only")
    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError("workflow must grant contents: read only")

    live = jobs.get("live-read-only", {})
    if not isinstance(live, dict):
        raise AssertionError("live-read-only job must be a mapping")
    if live.get("environment") != "staging":
        raise AssertionError("credentialed reads must bind to the reviewed staging approval environment")
    if live.get("runs-on") != "ubuntu-24.04":
        raise AssertionError("live-read-only job must use the approved hosted runner")
    live_env = live.get("env", {})
    if not isinstance(live_env, dict) or live_env.get("EVIDENCE_ENVIRONMENT") != "production":
        raise AssertionError("receipt must identify the production D1 target")
    live_gate = live.get("if", "")
    for required_gate in (
        "github.repository_id == '",
        "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'",
        "github.ref_protected == true",
        "inputs.run_live == 'true'",
    ):
        if required_gate not in live_gate:
            raise AssertionError(f"live-read-only gate is missing {required_gate}")

    run_steps: list[str] = []
    actions: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            if isinstance(step.get("run"), str):
                run_steps.append(step["run"])
            if isinstance(step.get("uses"), str):
                actions.append(step["uses"])

    source_text = source
    required = (
        "CF_ACCOUNT_ID",
        "CF_API_TOKEN",
        "AUDIT_D1_DATABASE_ID",
        "SELECT o.tenant_id",
        "tenant_prefix",
        "rows_written",
        "actions/upload-artifact@",
    )
    for marker in required:
        if marker not in source_text:
            raise AssertionError(f"missing B-063 hosted-lane contract: {marker}")

    for run in run_steps:
        _verify_select_only_python(run)
    for forbidden in ("PAGERDUTY", "pagerduty", "events.pagerduty.com", "event_action", "/_internal/audit/archive"):
        if forbidden in source_text:
            raise AssertionError(f"workflow must not contain PagerDuty mutation: {forbidden}")

    unpinned = [action for action in actions if not re.search(r"@[0-9a-f]{40}$", action)]
    if unpinned:
        raise AssertionError(f"unpinned action references: {unpinned}")

    if '[[ "${READ_ONLY}" == "true" ]]' not in source_text:
        raise AssertionError("live lane must fail closed unless READ_ONLY=true")
    if 'str(row.get("tenant_id") or "")[:8]' not in source_text:
        raise AssertionError("receipt must retain only the eight-character tenant prefix")


def main() -> int:
    verify(WORKFLOW.read_text(encoding="utf-8"))
    print("B-063 hosted read-only evidence workflow contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
