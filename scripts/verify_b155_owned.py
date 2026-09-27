#!/usr/bin/env python3
"""Semantic, target-bound checks for the B-155 Luna batch.

The checks in this file intentionally do not search BACKLOG.md or execute a
shell pipeline.  Each check names its complete target set and parses the
target's active syntax, so comments, strings, missing files, duplicate
declarations, and ambiguous values fail closed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from verify_b035_tls_surfaces import inventory as b035_inventory

ROOT = Path(__file__).resolve().parents[1]
LEGAL_TLS = (
    "legal/dpa/v1.0.0.en-US.md", "legal/dpa/v1.0.0.pt-BR.md",
    "legal/dpa/v1.0.0.es-419.md", "legal/dpa/STANDARD-CONTRACTUAL-CLAUSES-EU.md",
    "legal/dpa/SUB-PROCESSOR-COMMITMENTS.md", "legal/privacy-notice/v1.0.0/en-US.md",
    "legal/privacy-notice/v1.0.0/pt-BR.md", "legal/privacy-notice/v1.0.0/es-MX.md",
)
MIRROR_URL = "https://corelink-artifacts.humangr.com/tlaplus/v1.8.0/eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a/tla2tools.jar"
MIRROR_SHA256_PINNED = "eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a"
MIRROR_BYTES_PINNED = 4_487_757
MIRROR_USER_AGENT = "CoreLink-B039-Verifier/1.0"
MIRROR_READ_CHUNK_BYTES = 1024 * 1024
MIRROR_MAX_BYTES = 128 * 1024 * 1024
UPSTREAM_RE = re.compile(r"https://github\.com/tlaplus/tlaplus/releases/download/[^\s\"']+/tla2tools\.jar")
B039_TARGETS = (".github/workflows/nightly.yml", ".github/workflows/tla_check.yml", "scripts/run_tlc_corelink.sh")
B014_FIXTURE = "tests/fixtures/b014_webhook_endpoints.json"
B014_EVIDENCE_SOURCE = "docs/handoff/2026-07-03-REPLY-from-clw-coordinator-webhook-reconcile-DONE-and-no-stray-endpoint-exists.md"
B014_EVIDENCE_SOURCE_SHA256 = "8bd1f966922874cd06c3a2445867983fccde30ed19af3476769d17b12cbe3548"
B014_EVIDENCE_SCOPE = "stripe.v1.webhook_endpoints"
B014_EVIDENCE_OBSERVED_AT = "2026-07-03"
B014_LEAKED_ENDPOINT = "we_1TcaMDLh0hhAZjwol9KDCJTp"
B014_EXPECTED_ENDPOINTS = (
    {"id": "we_1ToligLh0hhAZjwoI8PERw8x", "url": "https://corelink-signup.humangr.com/webhooks/stripe", "event_count": 7, "payload_style": "snapshot"},
    {"id": "we_1Tfh8PLh0hhAZjwoCnqvruqC", "url": "https://corelink-api.humangr.com/v1/billing/stripe-webhook", "event_count": 236, "payload_style": "snapshot"},
    {"id": "we_1TJ1YZLh0hhAZjwoTXnh9mTD", "url": "https://api.humangr.com/_wallet/stripe/webhook", "event_count": 4, "payload_style": "snapshot"},
)


class VerificationError(RuntimeError):
    pass


def _raw_string_end(text: str, start: int) -> int | None:
    """Return the end of a Rust raw string beginning at ``start``, if any."""
    if start >= len(text) or text[start] != "r":
        return None
    cursor = start + 1
    while cursor < len(text) and text[cursor] == "#":
        cursor += 1
    if cursor >= len(text) or text[cursor] != '"':
        return None
    hashes = text[start + 1:cursor]
    close = text.find('"' + hashes, cursor + 1)
    if close < 0:
        raise VerificationError("unterminated Rust raw string")
    return close + len(hashes) + 1


def _read(root: Path, rel: str, overrides: dict[str, str] | None = None) -> str:
    if overrides and rel in overrides:
        return overrides[rel]
    path = root / rel
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"missing/non-regular target: {rel}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read target {rel}: {exc}") from exc


def _strip_code_comments(text: str, line_comments=()) -> str:
    """Remove comments and quoted strings, retaining line boundaries."""
    out: list[str] = []
    i = 0
    block = False
    quote = ""
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if block:
            if c == "*" and n == "/":
                block = False; i += 2; out.append("  "); continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
        if quote:
            if c == "\\":
                out.append("  "); i += 2; continue
            if c == quote: quote = ""
            out.append(" "); i += 1; continue
        if c in ('"', "`"):
            quote = c; out.append(" "); i += 1; continue
        if c == "/" and n == "*":
            block = True; out.extend(("  ")); i += 2; continue
        if any(text.startswith(marker, i) for marker in line_comments):
            while i < len(text) and text[i] != "\n": out.append(" "); i += 1
            continue
        raw_end = _raw_string_end(text, i)
        if raw_end is not None:
            out.extend("\n" if char == "\n" else " " for char in text[i:raw_end])
            i = raw_end; continue
        out.append(c); i += 1
    if block or quote:
        raise VerificationError("unterminated comment or string")
    return "".join(out)


def _active_lines(text: str, line_comments=("//", "#")) -> list[str]:
    return _strip_code_comments(text, line_comments).splitlines()


def _active_config_lines(text: str, line_comment="#") -> list[str]:
    """Drop config comments while retaining quoted values and strings."""
    lines = []
    for raw in text.splitlines():
        out = []
        quote = ""
        escaped = False
        for char in raw:
            if quote:
                out.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
            elif char in ('"', "'"):
                quote = char
                out.append(char)
            elif char == line_comment:
                break
            else:
                out.append(char)
        # YAML block scalars and shell snippets may legitimately carry a
        # quote to the next physical line; retaining the remainder is safer
        # than interpreting a comment-looking token as executable syntax.
        lines.append("".join(out))
    return lines


def _active_code_lines(text: str, line_comments=("//",)) -> list[str]:
    """Remove comments but retain literals needed by explicit-target checks."""
    out=[]; i=0; block=False; quote=""
    while i < len(text):
        c=text[i]; n=text[i+1] if i+1 < len(text) else ""
        if block:
            if c == "*" and n == "/": block=False; i += 2; out.extend("  "); continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
        if quote:
            out.append(c)
            if c == "\\" and i+1 < len(text): out.append(text[i+1]); i += 2; continue
            if c == quote: quote=""
            i += 1; continue
        if c in ('"', "`"):
            quote=c; out.append(c); i += 1; continue
        if c == "/" and n == "*": block=True; out.extend("  "); i += 2; continue
        if any(text.startswith(marker, i) for marker in line_comments):
            while i < len(text) and text[i] != "\n": out.append(" "); i += 1
            continue
        raw_end = _raw_string_end(text, i)
        if raw_end is not None:
            out.extend("\n" if char == "\n" else " " for char in text[i:raw_end])
            i = raw_end; continue
        out.append(c); i += 1
    if block or quote: raise VerificationError("unterminated comment or string")
    return "".join(out).splitlines()


def _rust_include_paths(text: str) -> list[str]:
    """Return active static ``include!("...")`` paths from Rust source.

    This scanner skips comments, ordinary strings, and raw strings before
    recognizing a macro.  A dynamic or malformed include is rejected rather
    than silently omitted from the census, so a path can never drift behind a
    comment/string decoy or an expression that this verifier cannot resolve.
    """
    paths: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1; index += 2
                elif text.startswith("*/", index):
                    depth -= 1; index += 2
                else:
                    index += 1
            if depth:
                raise VerificationError("unterminated Rust block comment while reading includes")
            continue
        raw_end = _raw_string_end(text, index)
        if raw_end is not None:
            index = raw_end
            continue
        if text[index] == '"':
            index += 1
            escaped = False
            while index < length:
                char = text[index]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    index += 1
                    break
                index += 1
            else:
                raise VerificationError("unterminated Rust string while reading includes")
            continue
        if text.startswith("include!", index):
            end = index + len("include!")
            if index and (text[index - 1].isalnum() or text[index - 1] == "_"):
                index = end
                continue
            while end < length and text[end].isspace():
                end += 1
            if end >= length or text[end] != "(":
                index = end
                continue
            end += 1
            while end < length and text[end].isspace():
                end += 1
            if end >= length or text[end] != '"':
                raise VerificationError("dynamic or malformed Rust include is not auditable")
            start = end + 1
            end = start
            escaped = False
            while end < length:
                char = text[end]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
                end += 1
            if end >= length:
                raise VerificationError("unterminated Rust include path")
            path = text[start:end]
            if not path or "\\" in path:
                raise VerificationError("Rust include path is empty or escaped")
            end += 1
            while end < length and text[end].isspace():
                end += 1
            if end >= length or text[end] != ")":
                raise VerificationError("Rust include must use a static single-string argument")
            paths.append(path)
            index = end + 1
            continue
        index += 1
    return paths


def _rust_include_closure(
    root: Path, entry: str, overrides: dict[str, str] | None = None
) -> set[str]:
    """Resolve an active Rust include tree with path and cycle checks."""
    root = root.resolve()
    visiting: list[Path] = []
    visited: set[Path] = set()

    def visit(relative: str) -> None:
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise VerificationError(f"Rust include escapes repository root: {relative}") from exc
        canonical = path.relative_to(root).as_posix()
        if path in visiting:
            chain = " -> ".join(str(item.relative_to(root)) for item in (*visiting, path))
            raise VerificationError(f"Rust include cycle detected: {chain}")
        if path in visited:
            return
        source = _read(root, canonical, overrides)
        visiting.append(path)
        try:
            visited.add(path)
            for include in _rust_include_paths(source):
                child = (path.parent / include).resolve()
                try:
                    child_relative = child.relative_to(root).as_posix()
                except ValueError as exc:
                    raise VerificationError(
                        f"Rust include escapes repository root: {canonical} -> {include}"
                    ) from exc
                visit(child_relative)
        finally:
            visiting.pop()

    visit(entry)
    return {path.relative_to(root).as_posix() for path in visited}


def _active_route_literals(text: str) -> list[str]:
    """Return route literals whose ``.route`` call is executable code."""
    masked = _strip_code_comments(text, ("//",))
    found=[]
    for match in re.finditer(r"\.route\s*\(", masked):
        line_end=masked.find("\n", match.end())
        if line_end < 0: line_end=len(masked)
        # The comment/string mask preserves offsets, so this slice starts at
        # the executable call while retaining its literal argument.
        argument=text[match.start():line_end]
        value=re.match(r"\.route\s*\(\s*\"([^\"]+)\"", argument)
        if value: found.append(value.group(1))
    return found


def _active_decl_string_values(text: str, declaration: str, value: str) -> list[str]:
    """Capture values from declarations whose syntax is outside literals."""
    masked=_strip_code_comments(text, ("//",)).splitlines()
    preserved=_active_code_lines(text, ("//",))
    found=[]
    for masked_line, preserved_line in zip(masked, preserved):
        if not re.search(declaration, masked_line): continue
        match=re.search(value, preserved_line)
        if match: found.append(match.group(1))
    return found


def _markdown_body(text: str, *, ignore_headings: bool = True) -> list[str]:
    lines = text.splitlines(); result=[]; fence=False; html=False
    for line in lines:
        s=line.strip()
        if s.startswith("```"):
            fence=not fence; continue
        if fence: continue
        if html:
            if "-->" not in line: continue
            line=line.split("-->",1)[1]; html=False; s=line.strip()
        if "<!--" in line:
            before, after=line.split("<!--",1)
            line=before
            if "-->" in after:
                line += after.split("-->",1)[1]
            else:
                html=True
            s=line.strip()
        if not s or (ignore_headings and s.startswith("#")):
            continue
        result.append(line)
    if fence or html:
        raise VerificationError("unterminated Markdown fence/comment")
    return result


def _assert_b014_payload(payload: object, root: Path) -> list[str]:
    if not isinstance(payload, dict):
        raise VerificationError("B-014 endpoint evidence must be a JSON object")
    if set(payload) != {"schema", "source", "observed_at", "asserted_absent", "data"}:
        raise VerificationError("B-014 endpoint evidence has an unexpected schema")
    if payload.get("schema") != "b014.offline.webhook-endpoints.v2":
        raise VerificationError("B-014 endpoint evidence schema is missing or changed")
    source = payload.get("source")
    if not isinstance(source, dict) or set(source) != {"path", "sha256", "scope"}:
        raise VerificationError("B-014 evidence provenance is missing or malformed")
    if source != {"path": B014_EVIDENCE_SOURCE, "sha256": B014_EVIDENCE_SOURCE_SHA256, "scope": B014_EVIDENCE_SCOPE}:
        raise VerificationError("B-014 evidence provenance is not the canonical read-only source")
    source_bytes = _read(root, B014_EVIDENCE_SOURCE).encode("utf-8")
    if hashlib.sha256(source_bytes).hexdigest() != B014_EVIDENCE_SOURCE_SHA256:
        raise VerificationError("B-014 evidence source digest changed; refresh the snapshot explicitly")
    if payload.get("observed_at") != B014_EVIDENCE_OBSERVED_AT:
        raise VerificationError("B-014 evidence observation date is missing or changed")
    if payload.get("asserted_absent") != B014_LEAKED_ENDPOINT:
        raise VerificationError("B-014 evidence does not assert the exact leaked endpoint is absent")
    endpoints = payload.get("data")
    if endpoints != list(B014_EXPECTED_ENDPOINTS):
        raise VerificationError("B-014 endpoint evidence population is missing, reordered, or altered")
    return [endpoint["id"] for endpoint in endpoints]


def _assert_b014_live_payload(payload: object) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise VerificationError("B-014 live endpoint response is malformed")
    ids = [endpoint.get("id") for endpoint in payload["data"] if isinstance(endpoint, dict)]
    if B014_LEAKED_ENDPOINT in ids:
        raise VerificationError("the leaked Stripe endpoint is still present")
    if any(isinstance(identifier, str) and identifier.startswith("we_1Tca") for identifier in ids):
        raise VerificationError("a webhook endpoint sharing the leaked identifier prefix is present")


def _b014(root: Path, live: bool) -> str:
    if not live:
        fixture = _read(root, B014_FIXTURE)
        try:
            payload = json.loads(fixture)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"B-014 offline endpoint evidence is invalid JSON: {exc}") from exc
        _assert_b014_payload(payload, root)
        return "B-014 offline evidence PASS (fixture proves the exact leaked endpoint is absent)"
    env = _read(root, ".env.local")
    values=[]
    for line in env.splitlines():
        if not line.strip() or line.lstrip().startswith("#"): continue
        m=re.fullmatch(r"STRIPE_LIVE_SECRET_KEY\s*=\s*([^#\s]+)", line.strip())
        if m: values.append(m.group(1))
    if len(values) != 1: raise VerificationError(".env.local must contain exactly one active STRIPE_LIVE_SECRET_KEY")
    if not values[0]: raise VerificationError("STRIPE_LIVE_SECRET_KEY is empty")
    request=urllib.request.Request("https://api.stripe.com/v1/webhook_endpoints?limit=20")
    token=base64.b64encode((values[0]+":").encode()).decode()
    request.add_header("Authorization", "Basic "+token)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload=json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise VerificationError(f"Stripe endpoint query failed: {exc}") from exc
    _assert_b014_live_payload(payload)
    return "B-014 PASS (the leaked endpoint is absent from the live endpoint response)"


def _b015(root: Path) -> str:
    # The mount is an identifier, not a string literal: masking literals is
    # what prevents a dead string containing `audit_archive::router(` from
    # graduating the item.
    main="\n".join(_active_lines(_read(root,"crates/corelink-container/src/main.rs")))
    wf=_read(root,".github/workflows/audit-chain-daily-verify.yml")
    mounts=re.findall(r"\baudit_archive::router\s*\(",main)
    buckets=_active_decl_string_values(
        _read(root,"crates/corelink-container/src/routes/audit_archive.rs"),
        r"\bpub\s+const\s+DEFAULT_AUDIT_BUCKET\b",
        r"DEFAULT_AUDIT_BUCKET\s*:\s*&str\s*=\s*\"([^\"]+)\"",
    )
    active=[line for line in _active_config_lines(wf) if re.match(r"\s*AUDIT_R2_BUCKET_DEFAULT\s*:",line)]
    if len(mounts)!=1 or len(buckets)!=1 or len(active)!=1: raise VerificationError("B-015 mount/constant/workflow declaration missing or ambiguous")
    if buckets[0]!="corelink-audit-weur" or not re.search(r"AUDIT_R2_BUCKET_DEFAULT\s*:\s*\"corelink-audit-weur\"",active[0]): raise VerificationError("B-015 bucket values diverge")
    return "B-015 PASS (active mount, bucket constant, and workflow bucket agree)"


def _b035(root: Path) -> str:
    report = b035_inventory(root)
    if report["status"] != "truthful_exact_inventory" or report["instrument_count"] != 8:
        raise VerificationError("B-035 exact eight-instrument TLS 1.2/1.3 contract drifted")
    return "B-035 done PASS (eight truthful TLS 1.2-minimum claims; TLS 1.3 where supported)"


def _read_mirror_digest() -> tuple[int, str]:
    """Read the pinned mirror object and return its size and SHA-256.

    The mirror's WAF rejects urllib's default ``Python-urllib/...`` user agent,
    while allowing the explicit verifier identity used here.  Streaming keeps
    the live check bounded and hashing the complete response preserves the
    supply-chain check instead of treating any 2xx response as sufficient.
    """
    request = urllib.request.Request(
        MIRROR_URL,
        headers={"User-Agent": MIRROR_USER_AGENT},
    )
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=30) as response:
        status = getattr(response, "status", None)
        if not isinstance(status, int) or not (200 <= status < 300):
            raise VerificationError(f"mirror status {status!r}")
        while True:
            chunk = response.read(MIRROR_READ_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            if size > MIRROR_MAX_BYTES:
                raise VerificationError(
                    f"mirror response exceeds {MIRROR_MAX_BYTES} bytes"
                )
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != MIRROR_SHA256_PINNED:
        raise VerificationError(
            "mirror SHA-256 mismatch: "
            f"expected {MIRROR_SHA256_PINNED}, got {actual}"
        )
    return size, actual


def _b039(root: Path, live: bool) -> str:
    hits=[]
    for rel in B039_TARGETS:
        for line in _active_config_lines(_read(root,rel)):
            if UPSTREAM_RE.search(line): hits.append(rel)
    if hits: raise VerificationError("mutable upstream URL remains in active target(s): "+", ".join(hits))
    if f"/{MIRROR_SHA256_PINNED}/" not in MIRROR_URL:
        raise VerificationError("mirror URL and SHA-256 pin diverge")
    if not live:
        return "B-039 static PASS (mirror availability unverified; query skipped)"
    try:
        size, actual = _read_mirror_digest()
    except VerificationError:
        raise
    except OSError as exc: raise VerificationError(f"artifact mirror query failed: {exc}") from exc
    if size != MIRROR_BYTES_PINNED:
        raise VerificationError(
            f"mirror byte-count mismatch: expected {MIRROR_BYTES_PINNED}, got {size}"
        )
    return f"B-039 PASS (mirror HTTP 2xx and SHA-256 verified; bytes={size}, sha256={actual})"


def _b045(root: Path) -> str:
    files=("specs/_compliance/ISO27001-STATEMENT-OF-APPLICABILITY-2026-05-15.md","specs/_compliance/ISO27001-CROSSWALK-2026-05-15.md","specs/_compliance/FEDRAMP-MODERATE-CROSSWALK-2026-05-15.md","specs/_compliance/LGPD-FULL-AUDIT-2026-05-15.md","specs/_compliance/GA-GATE-CRITERIA.md","specs/03_architecture/failure_modes.md","specs/03_architecture/invariant_registry.md","specs/03_architecture/security_model.md","specs/03_architecture/remote_cache_product_profile.md","specs/_templates/production_readiness_review.md","specs/00_framework.md","ARCHITECTURE.md")
    bad=[]
    for rel in files:
        for line in _markdown_body(_read(root,rel)):
            if re.search(r"SLSA L3|SLSA Level 3",line) and not re.search(r"defer|adiad|B-031|requires|exige|SolarWinds|motiv|não é o alvo",line,re.I): bad.append((rel,line.strip()))
    if bad: raise VerificationError("active SLSA L3 claims remain: "+str(bad[:3]))
    return "B-045 PASS (no active SLSA L3 claims in 12 explicit live targets)"


EXPECTED_EDGE_SECTIONS=frozenset({"env.prod", "env.prod-sam.vars", "env.prod-lhr.vars", "env.prod-nrt.vars", "env.prod-syd.vars"})


def _b047_population(text: str) -> dict[str,list[str]]:
    expected=EXPECTED_EDGE_SECTIONS
    entries: dict[str,list[str]]={}
    section=None
    for line in _active_config_lines(text):
        header=re.fullmatch(r"\s*\[([^\]]+)\]\s*",line)
        if header: section=header.group(1); continue
        if section not in expected: continue
        if section == "env.prod":
            matches=re.findall(r"(?:^|[{,])\s*EDGE_FIND_MISSING\s*=\s*\"([^\"]+)\"",line)
        else:
            matches=re.findall(r"^\s*EDGE_FIND_MISSING\s*=\s*\"([^\"]+)\"\s*$",line)
        if matches: entries.setdefault(section,[]).extend(matches)
    return entries


def _b047(root: Path) -> str:
    entries=_b047_population(_read(root,"wrangler.toml"))
    if set(entries) != EXPECTED_EDGE_SECTIONS or any(len(values)!=1 for values in entries.values()):
        raise VerificationError(f"B-047 expected one active EDGE_FIND_MISSING per complete regional population, got {entries}")
    values=[entries[name][0] for name in sorted(EXPECTED_EDGE_SECTIONS)]
    # Every production environment is deliberately enabled.  A single on→off
    # drift must fail even when the other regions remain enabled.
    if any(value != "on" for value in values):
        raise VerificationError(f"B-047 EDGE_FIND_MISSING population is not uniformly enabled: {entries}")
    routes=_active_route_literals(_read(root,"crates/corelink-container/src/routes/audit_cas_attempted.rs"))
    if routes.count("/_internal/audit/cas-attempted")!=1: raise VerificationError("B-047 enabled find-missing lacks exactly one audit route")
    return "B-047 PASS (active config parsed; audit route is present only with enabled mode)"


def _b050(root: Path) -> str:
    main="\n".join(_active_lines(_read(root,"crates/corelink-container/src/main.rs")))
    # The route module is an explicit target; do not let prose in sibling
    # modules or a future glob expansion satisfy the proof.
    scrub_path="crates/corelink-container/src/routes/cas_scrub.rs"
    found=sum("scrub" in route for route in _active_route_literals(_read(root,scrub_path)))
    mounted=len(re.findall(r"\bcas_scrub::router\s*\(",main))
    if found!=1 or mounted!=1: raise VerificationError(f"B-050 executable scrub route/mount expected 1/1, got {found}/{mounted}")
    return "B-050 PASS (one active scrub route and one active main mount)"


CAS_ROUTE_ENTRY = "crates/corelink-container/src/routes/cas.rs"
CAS_FOUNDATION_PATHS = frozenset((
    "crates/corelink-container/src/routes/cas/foundation_core.rs",
    "crates/corelink-container/src/routes/cas/foundation_state.rs",
))
CAS_SINGLE_PATHS = frozenset((
    "crates/corelink-container/src/routes/cas/single_setup.rs",
    "crates/corelink-container/src/routes/cas/single_handlers.rs",
))


def _cas_module_paths(
    root: Path, expected: frozenset[str], label: str,
    overrides: dict[str, str] | None = None,
) -> set[str]:
    closure = _rust_include_closure(root, CAS_ROUTE_ENTRY, overrides)
    actual = {
        path for path in closure
        if path.startswith("crates/corelink-container/src/routes/cas/")
        and Path(path).name.startswith(label)
    }
    if actual != expected:
        missing = sorted(expected - actual)
        drift = sorted(actual - expected)
        raise VerificationError(f"{label} path census drift: missing={missing}, unexpected={drift}")
    return closure


def _b051(root: Path, overrides: dict[str, str] | None = None) -> str:
    closure = _cas_module_paths(root, CAS_FOUNDATION_PATHS, "foundation", overrides)
    f="\n".join(
        line
        for path in sorted(CAS_FOUNDATION_PATHS)
        for line in _active_lines(_read(root, path, overrides))
    )
    c="\n".join(_active_lines(_read(root,"crates/corelink-container/src/storage/r2_s3_parts/cas_core.rs")))
    const=re.findall(r"\bpub\s+const\s+CAS_READ_MAX_OBJECT_BYTES\s*:\s*u64\s*=",f)
    capped=re.findall(r"\.get_capped\s*\(",c)
    if len(const)!=1 or len(capped)<1: raise VerificationError("B-051 size constant or capped read missing/ambiguous")
    return "B-051 PASS (active size ceiling and capped read path present)"


def _b052(root: Path, overrides: dict[str, str] | None = None) -> str:
    closure = _cas_module_paths(root, CAS_SINGLE_PATHS, "single", overrides)
    text="\n".join(_read(root,path,overrides) for path in sorted(CAS_SINGLE_PATHS))
    code=_strip_code_comments(text,("//",))
    matches=list(re.finditer(r"\basync\s+fn\s+handle_read\s*\(",code))
    if len(matches)!=1: raise VerificationError("B-052 handle_read missing or ambiguous")
    start=matches[0].start()
    open_brace=code.find("{", matches[0].end())
    if open_brace < 0: raise VerificationError("B-052 handle_read body is incomplete")
    depth=0; end=-1
    for pos in range(open_brace, len(code)):
        if code[pos] == "{": depth += 1
        elif code[pos] == "}":
            depth -= 1
            if depth == 0:
                end=pos
                break
    if end < 0: raise VerificationError("B-052 handle_read body is incomplete")
    signature=code[start:open_brace]
    guard=re.findall(r"_read_concurrency\s*:\s*CasReadConcurrencyGuard",signature)
    if len(guard)!=1: raise VerificationError("B-052 active handle_read lacks exactly one concurrency guard")
    return "B-052 PASS (active handle_read signature carries one pre-body concurrency guard)"


def _b060_executable(code: str) -> bool:
    n=len(re.findall(r"\bfn\s+every_registry_table_is_actually_created_by_a_migration\s*\(",code))
    if n != 1: return False
    lines=code.splitlines()
    fn_line=next(index for index,line in enumerate(lines) if re.search(r"\bfn\s+every_registry_table_is_actually_created_by_a_migration\s*\(",line))
    attrs=[]; index=fn_line-1
    while index >= 0 and (not lines[index].strip() or lines[index].lstrip().startswith("#[")):
        if lines[index].strip(): attrs.append(lines[index].strip())
        index -= 1
    return "#[test]" in attrs and "#[ignore]" not in attrs


def _b060(root: Path) -> str:
    code=_strip_code_comments(_read(root,"crates/corelink-container/src/routes/dsr/adapter_d1_tests.rs"),("//",))
    if not _b060_executable(code):
        raise VerificationError("B-060 mirror function is not an executable, non-ignored test")
    return "B-060 PASS (active migration mirror assertion present)"


CHECKS={"B-014":_b014,"B-015":_b015,"B-035":_b035,"B-039":_b039,"B-045":_b045,"B-047":_b047,"B-050":_b050,"B-051":_b051,"B-052":_b052,"B-060":_b060}


TARGET_IDS = tuple(sorted(CHECKS))


def _self_test() -> int:
    # Every semantic target is mutation-backed in memory: comments and strings
    # cannot satisfy an active declaration, while deleting the declaration does.
    offline_fixture = {
        "schema": "b014.offline.webhook-endpoints.v2",
        "source": {"path": B014_EVIDENCE_SOURCE, "sha256": B014_EVIDENCE_SOURCE_SHA256, "scope": B014_EVIDENCE_SCOPE},
        "observed_at": B014_EVIDENCE_OBSERVED_AT,
        "asserted_absent": B014_LEAKED_ENDPOINT,
        "data": list(B014_EXPECTED_ENDPOINTS),
    }
    _assert_b014_payload(offline_fixture, ROOT)
    for label, mutation in (
        ("B-014 fixture source", {**offline_fixture, "source": {**offline_fixture["source"], "sha256": "0" * 64}}),
        ("B-014 fixture schema", {**offline_fixture, "schema": "wrong"}),
        ("B-014 fixture population", {**offline_fixture, "data": list(B014_EXPECTED_ENDPOINTS[:-1])}),
        ("B-014 leaked endpoint", {**offline_fixture, "asserted_absent": "we_fixture"}),
        ("B-014 endpoint mutation", {**offline_fixture, "data": [{**B014_EXPECTED_ENDPOINTS[0], "id": B014_LEAKED_ENDPOINT}, *B014_EXPECTED_ENDPOINTS[1:]]}),
    ):
        try:
            _assert_b014_payload(mutation, ROOT)
        except VerificationError:
            pass
        else:
            raise VerificationError(f"{label} mutation self-test passed unexpectedly")

    live_fixture = {"data": [{"id": B014_EXPECTED_ENDPOINTS[0]["id"]}]}
    _assert_b014_live_payload(live_fixture)
    for label, mutation in (
        ("B-014 live response shape", {}),
        ("B-014 live leaked endpoint", {"data": [{"id": B014_LEAKED_ENDPOINT}]}),
        ("B-014 live leaked prefix", {"data": [{"id": "we_1Tca_future"}]}),
    ):
        try:
            _assert_b014_live_payload(mutation)
        except VerificationError:
            pass
        else:
            raise VerificationError(f"{label} mutation self-test passed unexpectedly")

    cases=[
        ("B-014", "# STRIPE_LIVE_SECRET_KEY=comment\nSTRIPE_LIVE_SECRET_KEY=fixture", _active_config_lines, r"^STRIPE_LIVE_SECRET_KEY=", 1),
        ("B-015", "// audit_archive::router(\nconst bait = \"audit_archive::router(\";", _active_lines, r"audit_archive::router\s*\(", 0),
        ("B-035", "<!-- TLS 1.3+ -->\n# TLS 1.3+", _markdown_body, r"TLS 1\.3", 0),
        ("B-039", "# https://github.com/tlaplus/tlaplus/releases/download/v1/tla2tools.jar\nurl=\"https://github.com/tlaplus/tlaplus/releases/download/v1/tla2tools.jar\"", _active_config_lines, UPSTREAM_RE, 1),
        ("B-045", "<!-- SLSA L3 -->\n# SLSA L3", _markdown_body, r"SLSA L3", 0),
        ("B-047", "# EDGE_FIND_MISSING = \"on\"\nEDGE_FIND_MISSING = \"off\"", _active_config_lines, r"EDGE_FIND_MISSING\s*=", 1),
        ("B-050", '// .route("/_internal/cas/scrub")\nconst bait = ".route(/_internal/cas/scrub)";', lambda s: _active_route_literals(s), r"scrub", 0),
        ("B-051", "// pub const CAS_READ_MAX_OBJECT_BYTES: u64 =\npub const CAS_READ_MAX_OBJECT_BYTES: u64 =", _active_code_lines, r"CAS_READ_MAX_OBJECT_BYTES\s*:", 1),
        ("B-052", "// async fn handle_read(\nasync fn handle_read(", lambda s: [_strip_code_comments(s, ("//",))], r"async\s+fn\s+handle_read\s*\(", 1),
        ("B-060", 'const x = "fn every_registry_table_is_actually_created_by_a_migration()";', lambda s: [_strip_code_comments(s, ("//",))], r"every_registry_table_is_actually_created_by_a_migration\s*\(", 0),
    ]
    for ident,text,parser,pattern,expected in cases:
        active="\n".join(parser(text))
        count=len(list(pattern.finditer(active))) if isinstance(pattern,re.Pattern) else len(list(re.finditer(pattern,active,re.M)))
        if count != expected: raise VerificationError(f"{ident} semantic mutation self-test failed: expected {expected}, got {count}")
    fixture="""[env.prod]
vars = { EDGE_FIND_MISSING = \"on\" }
[env.prod-sam.vars]
EDGE_FIND_MISSING = \"on\"
[env.prod-lhr.vars]
EDGE_FIND_MISSING = \"on\"
[env.prod-nrt.vars]
EDGE_FIND_MISSING = \"on\"
[env.prod-syd.vars]
EDGE_FIND_MISSING = \"on\"
"""
    population=_b047_population(fixture)
    if set(population) != EXPECTED_EDGE_SECTIONS or any(values != ["on"] for values in population.values()):
        raise VerificationError("B-047 complete enabled population mutation self-test failed")
    off_population=_b047_population(fixture.replace('env.prod-sam.vars]\nEDGE_FIND_MISSING = "on"', 'env.prod-sam.vars]\nEDGE_FIND_MISSING = "off"'))
    if all(values == ["on"] for values in off_population.values()):
        raise VerificationError("B-047 on-to-off mutation self-test failed")
    incomplete=_b047_population(fixture.replace('[env.prod-syd.vars]\nEDGE_FIND_MISSING = "on"\n', ''))
    if set(incomplete) == EXPECTED_EDGE_SECTIONS:
        raise VerificationError("B-047 missing-region mutation self-test failed")
    if _b060_executable(_strip_code_comments("fn every_registry_table_is_actually_created_by_a_migration() {}", ("//",))):
        raise VerificationError("B-060 unannotated test mutation self-test failed")
    if _b060_executable(_strip_code_comments("#[test]\n#[ignore]\nfn every_registry_table_is_actually_created_by_a_migration() {}", ("//",))):
        raise VerificationError("B-060 ignored-test mutation self-test failed")
    # The CAS source is intentionally split into include fragments.  A stale
    # verifier that opens the pre-split foundation.rs/single.rs names can pass
    # only by missing the active implementation entirely, so keep exact path
    # drift mutations red in the same semantic self-test.
    cas_entry = _read(ROOT, CAS_ROUTE_ENTRY)
    for label, check, old_path, replacement in (
        ("B-051 foundation include drift", _b051, "cas/foundation_core.rs", "cas/foundation_state.rs"),
        ("B-052 single include drift", _b052, "cas/single_handlers.rs", "cas/single_setup.rs"),
    ):
        mutated = cas_entry.replace(old_path, replacement, 1)
        if mutated == cas_entry:
            raise VerificationError(f"{label} mutation marker is absent")
        try:
            check(ROOT, {CAS_ROUTE_ENTRY: mutated})
        except VerificationError:
            pass
        else:
            raise VerificationError(f"{label} unexpectedly passed")
    # Keep the focal mutation inventory explicit so a new broad grep cannot
    # silently replace this batch's semantic checks.
    if set(TARGET_IDS) != {"B-014", "B-015", "B-035", "B-039", "B-045", "B-047", "B-050", "B-051", "B-052", "B-060"}:
        raise VerificationError("focal mutation inventory does not cover exactly the owned batch")
    return len(cases) + 14


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", choices=sorted(CHECKS), required=True)
    parser.add_argument("--expect", choices=("done","open"), default="done")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--offline", action="store_true", help="skip live provider checks (self-test/local mutation only)")
    args=parser.parse_args(argv)
    try:
        if args.self_test: mutations=_self_test()
        else: mutations=0
        # Offline self-tests validate parser mutations without requiring local
        # credentials or making provider calls.  The repository check itself
        # retains its original live/static polarity.
        result=CHECKS[args.id](ROOT, live=not args.offline) if args.id in {"B-014","B-039"} else CHECKS[args.id](ROOT)
        # B-039 is closed only by the live mirror read. Offline mode remains a
        # useful static check, but it cannot satisfy the done polarity.
        is_open = args.id == "B-039" and args.offline
        if args.expect == "open" and not is_open:
            raise VerificationError(f"{args.id} has done polarity but --expect open was requested")
        if args.expect == "done" and is_open:
            raise VerificationError(f"{args.id} has open polarity but --expect done was requested")
        print(result+ (f"; mutations={mutations} rejected" if args.self_test else ""))
        return 0
    except VerificationError as exc:
        print(f"{args.id} semantic verifier: FAIL: {exc}",file=sys.stderr); return 1


if __name__ == "__main__": raise SystemExit(main())
