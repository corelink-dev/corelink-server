#!/usr/bin/env python3
"""CLI entrypoint for the customer-facing docs reality gate."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_docs_reality_core as _core
from validate_docs_reality_core import *
from validate_docs_reality_core import (
    _endpoint_method,
    _is_generic_catchall,
    _iter_doc_files,
    _normalise_endpoint,
    _route_to_regex,
    _strip_source_comments,
)


def collect_route_inventory() -> RouteInventory:
    """Preserve the historical module API and its monkeypatch seam."""
    _core.ROUTE_SOURCE_ROOTS = ROUTE_SOURCE_ROOTS
    return _core.collect_route_inventory()

HOST_SCAN_ROOTS = [
    REPO_ROOT / "marketing",
    REPO_ROOT / "apps" / "docs",          # includes i18n/ (translated dead hosts
                                          # are still dead hosts)
    REPO_ROOT / "openapi",
    REPO_ROOT / "sdks",
    REPO_ROOT / "examples",
    REPO_ROOT / "templates",
    REPO_ROOT / "legal",
    REPO_ROOT / "corelink-go",
    REPO_ROOT / "tools",
    REPO_ROOT / "worker" / "src",
]
# Live source trees, expanded by glob so a new app/crate is covered automatically.
HOST_SCAN_SRC_GLOBS = ["apps/*/src", "crates/*/src"]
# Repo-root markdown (README.md and friends), non-recursive — same rationale as
# ROOT_DOC_GLOBS: the most-read files in the project sit outside every root.
HOST_ROOT_GLOBS = ["*.md"]

HOST_SCAN_EXTS = {
    ".md", ".mdx", ".mdc", ".html", ".htm", ".txt", ".json", ".yaml", ".yml",
    ".toml", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs", ".rs", ".go",
    ".py", ".sh", ".sql", ".proto", ".css", ".svg", ".tmpl", ".hbs", ".rb",
}
HOST_EXCLUDE_DIRS = {
    "node_modules", ".git", "target", "dist", "build", ".open-next", ".wrangler",
    ".docusaurus", "coverage", "vendor", "_archive", "releases", "reports",
    "tests", "test", "__tests__", "testdata", "fixtures", "conformance", "specs",
    "snapshots", "__snapshots__",
}
HOST_EXCLUDE_REL_PREFIXES = ("docs/findings/",)
HOST_EXCLUDE_FILENAMES = {"CHANGELOG.md"}
# `*_test*`, `*.test.*`, `*.spec.*` — test-shaped filenames anywhere.
_TEST_FILENAME_RE = re.compile(r"(_test|\.test\.|\.spec\.|^test_)", re.IGNORECASE)
# Dated handoff / relay / session / incident documents: point-in-time records, not
# shipped copy. `2026-08-18-erasure-handoff.md`, `RELAY-2026-08-12.md`, ...
_DATED_DOC_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}.*"
    r"(handoff|hand-off|relay|session|dossier|incident|postmortem|post-mortem|"
    r"audit|report|brief|snapshot|triage|retro)"
    r"|(handoff|hand-off|relay|session|dossier|incident|postmortem|post-mortem|"
    r"audit|report|brief|snapshot|triage|retro).*\d{4}-\d{2}-\d{2}",
    re.IGNORECASE,
)

# The scan MUST inspect a plausible corpus. A glob that silently stops matching
# (a directory renamed, a root moved) would otherwise turn this gate into a
# permanent green that proves NOTHING — the exact failure mode of the daily
# billing cron that reported success for a month because the table it read was
# empty. Both floors are deliberately far below the current tree (measured
# 2026-08-22: ~1.4k files, ~500 hostname mentions) so ordinary cleanup never
# trips them, and a broken glob always does.
MIN_HOST_SCAN_FILES = 300
MIN_HOST_MENTIONS = 25

# Hostnames under the domain we own. The lookbehind refuses a match that is
# preceded by a template/URL-ish character, so `{region}.corelink-api.humangr.com`
# (a placeholder, not a literal) is not reported as a phantom `region.` host.
_HUMANGR_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9._{$*%<-])((?:[A-Za-z0-9_-]+\.)*humangr\.com)\b")


@dataclass
class HostRef:
    file: str
    line: int
    host: str
    excerpt: str


def _host_file_excluded(rel: str, name: str) -> bool:
    parts = rel.split("/")
    if any(p in HOST_EXCLUDE_DIRS for p in parts):
        return True
    if any(p.startswith("mutants.out") for p in parts):
        return True
    if rel.startswith(HOST_EXCLUDE_REL_PREFIXES):
        return True
    if name in HOST_EXCLUDE_FILENAMES:
        return True
    if _TEST_FILENAME_RE.search(name):
        return True
    if _DATED_DOC_RE.search(name):
        return True
    return False


def iter_host_scan_files(repo_root: Path | None = None) -> list[Path]:
    """Every SHIPPED file whose hostnames are customer-reachable. Deterministic
    order; excluded paths (tests, sealed specs, history, build output) dropped."""
    root = repo_root or REPO_ROOT
    roots: list[Path] = []
    for r in HOST_SCAN_ROOTS:
        roots.append(root / r.relative_to(REPO_ROOT) if repo_root else r)
    for pattern in HOST_SCAN_SRC_GLOBS:
        roots.extend(sorted(p for p in root.glob(pattern) if p.is_dir()))

    seen: set[Path] = set()
    out: list[Path] = []

    def _consider(p: Path) -> None:
        if not p.is_file() or p.suffix.lower() not in HOST_SCAN_EXTS:
            return
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            return
        if _host_file_excluded(rel, p.name):
            return
        if p in seen:
            return
        seen.add(p)
        out.append(p)

    for r in roots:
        if not r.exists():
            continue
        for p in sorted(r.rglob("*")):
            _consider(p)
    for pattern in HOST_ROOT_GLOBS:
        for p in sorted(root.glob(pattern)):
            _consider(p)
    return out


def extract_host_refs(path: Path, rel: str) -> list[HostRef]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    refs: list[HostRef] = []
    for idx, ln in enumerate(text.splitlines(), start=1):
        for m in _HUMANGR_HOST_RE.finditer(ln):
            refs.append(HostRef(rel, idx, m.group(1).lower(), ln.strip()[:160]))
    return refs


def host_is_allowed(host: str, live_allow: set[str],
                    live_patterns: list[re.Pattern]) -> bool:
    if host in live_allow:
        return True
    return any(rx.match(host) for rx in live_patterns)


def _parse_iso_date(value: str) -> tuple[int, int, int] | None:
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", value.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def verify_dns(hosts: list[str], timeout: float = 4.0) -> list[tuple[str, str]]:
    """MANUAL mode only (`--verify-dns`). Re-derives the live-host allowlist by
    actually resolving + handshaking each host.

    This is deliberately NOT part of the gate: CI here runs on the founder's own
    Mac, and a network-dependent gate is a flaky gate that trains everyone to
    re-run it. The gate compares against the CHECKED-IN allowlist; a human runs
    this mode, eyeballs the output, and updates `hostname.live_allow` in
    scripts/docs_reality_allowlist.json with the date in the reason string."""
    import socket
    import ssl

    results: list[tuple[str, str]] = []
    ctx = ssl.create_default_context()
    for host in hosts:
        try:
            socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            results.append((host, f"DEAD nxdomain/unresolvable ({exc.__class__.__name__})"))
            continue
        try:
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
            results.append((host, "LIVE dns+tls"))
        except ssl.SSLError as exc:
            results.append((host, f"DNS-ONLY tls-handshake-failed ({exc.__class__.__name__})"))
        except OSError as exc:
            results.append((host, f"DNS-ONLY connect-failed ({exc.__class__.__name__})"))
    return results


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------
def load_allowlist(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"warning: could not parse allowlist {path}: {exc}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# okf-deferred-coherence rules
# ---------------------------------------------------------------------------
@dataclass
class DeferredFinding:
    rule_id: str
    file: str
    line: int
    excerpt: str
    reason: str


def _file_has_marker(rel: str, marker: str) -> bool:
    p = REPO_ROOT / rel
    if not p.exists():
        return False
    try:
        return marker.lower() in p.read_text(encoding="utf-8").lower()
    except (OSError, UnicodeDecodeError):
        return False


def run_deferred_coherence(rules: list[dict], docs: list[DocFile],
                           warnings: list[str]) -> list[DeferredFinding]:
    """Each rule:
        id, grounding: {okf_concept|cli_source, marker},
        forbidden: [regex,...], allow: [regex,...] (skip a line matching any),
        scope_globs: [path-prefix,...] (optional), reason.
    A rule that no longer grounds (marker gone / capability shipped) is reported as
    WARN:stale and SKIPPED — so building the capability + updating OKF auto-retires
    the rule with a nudge to delete it."""
    findings: list[DeferredFinding] = []
    for rule in rules:
        rid = rule.get("id", "?")
        grounding = rule.get("grounding", {})
        src = grounding.get("okf_concept") or grounding.get("cli_source")
        marker = grounding.get("marker", "deferred")
        if src is not None and not _file_has_marker(src, marker):
            warnings.append(
                f"[okf-deferred-coherence] rule '{rid}' STALE: grounding marker "
                f"'{marker}' no longer present in {src} — capability may have "
                f"shipped; delete or update this rule.")
            continue

        forbidden = [re.compile(p, re.IGNORECASE) for p in rule.get("forbidden", [])]
        allow = [re.compile(p, re.IGNORECASE) for p in rule.get("allow", [])]
        scope = rule.get("scope_globs", [])
        for doc in docs:
            if scope and not any(doc.rel.startswith(s) for s in scope):
                continue
            for idx, ln in enumerate(doc.text.splitlines(), start=1):
                if not any(fx.search(ln) for fx in forbidden):
                    continue
                if any(ax.search(ln) for ax in allow):
                    continue
                findings.append(DeferredFinding(
                    rid, doc.rel, idx, ln.strip()[:160], rule.get("reason", "")))
    return findings


@dataclass
class HostnameResult:
    """Outcome of [hostname-liveness]. `scan_errors`, `expiry_failures` and
    `scope_errors` are check-integrity failures (the scan or the allowlist is
    untrustworthy); `failures` are shipped surfaces naming an unproven host;
    `scope_failures` are mentions of a suppressed host in a file its suppression
    does not declare; `tracked` are the suppressed ones (fatal only under
    --strict)."""
    files: list[Path] = field(default_factory=list)
    refs: list[HostRef] = field(default_factory=list)
    failures: list[tuple[str, HostRef]] = field(default_factory=list)
    scope_failures: list[tuple[str, HostRef]] = field(default_factory=list)
    tracked: list[tuple[str, HostRef]] = field(default_factory=list)
    tracked_strict: list[tuple[str, HostRef]] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)
    expiry_failures: list[str] = field(default_factory=list)
    scope_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_fail(self) -> int:
        return (len(self.failures) + len(self.scope_failures) +
                len(self.scan_errors) + len(self.expiry_failures) +
                len(self.scope_errors) + len(self.tracked_strict))


def run_hostname_liveness(host_cfg: dict, *, repo_root: Path | None = None,
                          strict: bool = False,
                          today: tuple[int, int, int] | None = None,
                          min_files: int | None = None,
                          min_mentions: int | None = None) -> HostnameResult:
    """[hostname-liveness]: every `*.humangr.com` hostname on a SHIPPED surface
    must be on the checked-in proven-live allowlist.

    STATIC by design — no DNS, no HTTP. CI here runs on the founder's own Mac; a
    networked gate is a flaky gate, and a flaky gate is a gate people learn to
    re-run until it is green. `--verify-dns` is the manual refresh path.

    FAIL-LOUD by design — a scan that matched (almost) nothing is an ERROR, not a
    pass. A gate that reports success because it looked at nothing manufactures
    confidence; this repo has already been burned by exactly that shape."""
    root = repo_root or REPO_ROOT
    res = HostnameResult()

    live_allow = {h.strip().lower() for h in host_cfg.get("live_allow", {})}
    live_patterns = [re.compile(p["pattern"], re.IGNORECASE)
                     for p in host_cfg.get("live_patterns", [])
                     if isinstance(p, dict) and p.get("pattern")]
    tracked_cfg = host_cfg.get("tracked_dead", {})
    tracked_dead = {h.strip().lower() for h in tracked_cfg}

    # [suppression-scope]: a suppression names the EXACT repo-relative files it
    # covers. A host-wide mute would silence a NEW mention of the same dead host
    # on any other page — e.g. renewing a dead host because a historical ledger
    # still narrates it must not also mute that host on a customer quickstart.
    # A missing, empty or non-string `files` list is a hard failure, exactly
    # like a missing `expires`.
    scopes: dict[str, set[str]] = {}
    for host, meta in sorted(tracked_cfg.items()):
        files = meta.get("files") if isinstance(meta, dict) else None
        if (not isinstance(files, list) or not files
                or not all(isinstance(f, str) and f.strip() for f in files)):
            res.scope_errors.append(
                f"[hostname-liveness] suppression `{host}` has no valid `files` "
                f"list — every hostname suppression must name the exact "
                f"repo-relative files it covers.")
            continue
        scopes[host.strip().lower()] = {f.strip() for f in files}

    res.files = iter_host_scan_files(root)
    for p in res.files:
        res.refs.extend(extract_host_refs(p, p.relative_to(root).as_posix()))

    floor_files = MIN_HOST_SCAN_FILES if min_files is None else min_files
    floor_mentions = MIN_HOST_MENTIONS if min_mentions is None else min_mentions
    if len(res.files) < floor_files:
        res.scan_errors.append(
            f"[hostname-liveness] SCAN TOO SMALL: inspected {len(res.files)} "
            f"shipped files, floor is {floor_files}. A root or glob in "
            f"HOST_SCAN_ROOTS/HOST_SCAN_SRC_GLOBS has stopped matching — this is "
            f"an ERROR, not a pass.")
    if len(res.refs) < floor_mentions:
        res.scan_errors.append(
            f"[hostname-liveness] SCAN FOUND ALMOST NOTHING: {len(res.refs)} "
            f"hostname mentions across {len(res.files)} files, floor is "
            f"{floor_mentions}. Either the corpus moved or the hostname regex "
            f"broke — this is an ERROR, not a pass.")
    if not live_allow:
        res.scan_errors.append(
            "[hostname-liveness] EMPTY ALLOWLIST: `hostname.live_allow` is empty, "
            "so every hostname would be judged against nothing — this is an "
            "ERROR, not a pass.")

    used: set[str] = set()
    used_files: set[tuple[str, str]] = set()
    seen: set[tuple] = set()
    for r in res.refs:
        if host_is_allowed(r.host, live_allow, live_patterns):
            continue
        if r.host in tracked_dead:
            scope = scopes.get(r.host)
            if scope is not None and r.file not in scope:
                key = (r.host, r.file, r.line)
                if key not in seen:
                    seen.add(key)
                    res.scope_failures.append((r.host, r))
                continue
            used.add(r.host)
            used_files.add((r.host, r.file))
            key = (r.host, r.file)
            if key not in seen:
                seen.add(key)
                res.tracked.append((r.host, r))
            continue
        key = (r.host, r.file, r.line)
        if key in seen:
            continue
        seen.add(key)
        res.failures.append((r.host, r))

    # An expiring suppression that never expires is a permanent mute wearing a
    # date. Missing or past `expires` -> hard failure.
    now = today or _parse_iso_date(datetime.date.today().isoformat())
    for host, meta in sorted(tracked_cfg.items()):
        meta = meta if isinstance(meta, dict) else {"reason": str(meta)}
        exp_raw = meta.get("expires")
        exp = _parse_iso_date(exp_raw) if isinstance(exp_raw, str) else None
        if exp is None:
            res.expiry_failures.append(
                f"[hostname-liveness] suppression `{host}` has no valid ISO "
                f"`expires` date — every hostname suppression must expire.")
        elif now and exp < now:
            res.expiry_failures.append(
                f"[hostname-liveness] suppression `{host}` EXPIRED on {exp_raw} — "
                f"fix the hostname (or the DNS/TLS behind it) or re-justify it "
                f"with a new expiry. Reason on file: {meta.get('reason', '')}")

    if strict:
        res.tracked_strict = res.tracked
        res.tracked = []

    # [suppression-hygiene], same contract as the CLI buckets: a suppression that
    # suppressed NOTHING is dead, and a dead suppression stands armed to
    # re-silence the same defect the day it recurs. Each landing dead-host-sweep
    # PR should delete its entry and shrink this list toward zero.
    for host in sorted(tracked_dead):
        if host in used:
            continue
        res.warnings.append(
            f"[suppression-hygiene] allowlist hostname.tracked_dead entry "
            f"`{host}` never matched — dead suppression; delete it (record the "
            f"removal in hostname._retired) or state why it must stay armed.")
    # The same contract one level down: a declared file that no longer mentions
    # the host is a stale scope entry, armed to re-silence that file later.
    for host in sorted(scopes):
        if host not in used:
            continue  # already reported above as a whole-entry dead suppression
        for rel in sorted(scopes[host]):
            if (host, rel) in used_files:
                continue
            res.warnings.append(
                f"[suppression-hygiene] allowlist hostname.tracked_dead entry "
                f"`{host}` declares file `{rel}`, which no longer mentions it — "
                f"remove that file from the entry's `files`.")
    return res


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Validate customer-facing claims "
                                             "against shipped reality.")
    ap.add_argument("--strict", action="store_true",
                    help="also FAIL on tracked_drift (the known-drift punch-list).")
    ap.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST))
    ap.add_argument("--list-refs", action="store_true",
                    help="print every CLI reference discovered, then exit 0.")
    ap.add_argument("--list-hosts", action="store_true",
                    help="print every *.humangr.com hostname found on a shipped "
                         "surface (with verdict), then exit 0.")
    ap.add_argument("--verify-dns", action="store_true",
                    help="MANUAL, opt-in, NETWORKED: resolve + TLS-handshake every "
                         "hostname found (and every allowlisted one) to re-derive "
                         "the live-host allowlist. Never run in CI — the gate "
                         "itself is a static comparison on purpose.")
    args = ap.parse_args()

    allow = load_allowlist(Path(args.allowlist))
    cli_allow = allow.get("cli", {})
    roadmap_allow = {k.strip() for k in cli_allow.get("roadmap_allow", {})}
    tracked_drift = {k.strip() for k in cli_allow.get("tracked_drift", {})}

    # --- [hostname-liveness] corpus (needed early for --list-hosts/--verify-dns) ---
    host_cfg = allow.get("hostname", {})
    live_allow = {h.strip().lower() for h in host_cfg.get("live_allow", {})}
    live_patterns = [re.compile(p["pattern"], re.IGNORECASE)
                     for p in host_cfg.get("live_patterns", [])
                     if isinstance(p, dict) and p.get("pattern")]
    tracked_dead_cfg = host_cfg.get("tracked_dead", {})
    tracked_dead = {h.strip().lower() for h in tracked_dead_cfg}

    if args.verify_dns or args.list_hosts:
        host_files = iter_host_scan_files()
        host_refs: list[HostRef] = []
        for p in host_files:
            host_refs.extend(
                extract_host_refs(p, p.relative_to(REPO_ROOT).as_posix()))

    if args.verify_dns:
        targets = sorted({r.host for r in host_refs} | live_allow | tracked_dead)
        print(f"-- --verify-dns: probing {len(targets)} hostnames "
              f"(DNS + TLS handshake on :443) --\n")
        for host, verdict in verify_dns(targets):
            print(f"  {verdict:<44} {host}")
        print("\nRefresh recipe: every host reported LIVE belongs in "
              "`hostname.live_allow` of scripts/docs_reality_allowlist.json with "
              "the probe date in its reason string; every DEAD/DNS-ONLY host must "
              "be REMOVED FROM THE DOCS (preferred) or carry a `hostname."
              "tracked_dead` entry with a reason, an owner, the exact `files` it "
              "covers and an `expires` date.")
        return 0

    if args.list_hosts:
        for h in sorted({r.host for r in host_refs}):
            if host_is_allowed(h, live_allow, live_patterns):
                tag = "LIVE"
            elif h in tracked_dead:
                tag = "DEAD*"
            else:
                tag = "DEAD"
            n = sum(1 for r in host_refs if r.host == h)
            print(f"[{tag:<5}] {h}  ({n} mention(s))")
        print(f"\nscanned {len(host_files)} shipped files, "
              f"{len(host_refs)} hostname mentions")
        return 0

    try:
        model = parse_cli_model(CLI_MAIN)
    except (OSError, UnicodeDecodeError, SourceSyntaxError) as exc:
        print(f"DOCS-REALITY INVALID: source parse failure: {exc}")
        return 1
    docs = _iter_doc_files()

    all_refs: list[CliRef] = []
    for d in docs:
        all_refs.extend(extract_cli_refs(d))

    if args.list_refs:
        for r in sorted(all_refs, key=lambda x: (x.cmd, x.file, x.line)):
            tag = "OK" if model.is_valid_top(r.cmd) else "??"
            act = f" {r.action}" if r.action else ""
            print(f"[{tag}] corelink {r.cmd}{act}  ({r.file}:{r.line})")
        print(f"\nvalid top-level commands: {sorted(model.top)}")
        print(f"groups: { {k: sorted(v) for k, v in model.groups.items()} }")
        return 0

    # --- [cli-existence] ---
    cli_failures: list[tuple[str, CliRef, str]] = []
    cli_tracked: list[tuple[str, CliRef]] = []
    # Every allowlist key that actually suppressed something on this run. A key
    # that suppresses NOTHING is a DEAD suppression: the defect it was written
    # for is gone (or was never reachable), and all it does now is stand ready to
    # re-silence the same defect the day it recurs. See [suppression-hygiene].
    used_suppressions: set[str] = set()
    for r in all_refs:
        if model.is_valid_top(r.cmd):
            if model.is_group(r.cmd) and r.action and not r.action.startswith("-"):
                key2 = f"{r.cmd} {r.action}"
                if not model.is_valid_action(r.cmd, r.action):
                    if key2 in roadmap_allow:
                        used_suppressions.add(key2)
                        continue
                    if key2 in tracked_drift:
                        used_suppressions.add(key2)
                        cli_tracked.append((key2, r))
                        continue
                    cli_failures.append(
                        (key2, r,
                         f"`corelink {r.cmd} {r.action}` — '{r.action}' is not a "
                         f"valid `{r.cmd}` action (valid: "
                         f"{sorted(model.groups[r.cmd])})"))
            continue
        if r.cmd in roadmap_allow:
            used_suppressions.add(r.cmd)
            continue
        if r.cmd in tracked_drift:
            used_suppressions.add(r.cmd)
            cli_tracked.append((r.cmd, r))
            continue
        cli_failures.append(
            (r.cmd, r,
             f"`corelink {r.cmd}` — not in CLI `enum Commands` "
             f"(valid: {sorted(model.top)})"))

    strict_tracked_fail: list[tuple[str, CliRef]] = []
    if args.strict:
        strict_tracked_fail = cli_tracked
        cli_tracked = []

    # --- [suppression-hygiene] ---
    # An allowlist with no expiry is a permanent mute button. Report every
    # suppression key that matched NOTHING on this run so a dead entry is visible
    # instead of dormant — the difference between "known and accepted" and "known
    # and forgotten". Non-fatal by design (the corpus legitimately shrinks); the
    # remedy is to DELETE the entry, recording why, not to leave it armed.
    warnings: list[str] = []
    for key in sorted(roadmap_allow | tracked_drift):
        if key in used_suppressions:
            continue
        bucket = "roadmap_allow" if key in roadmap_allow else "tracked_drift"
        warnings.append(
            f"[suppression-hygiene] allowlist {bucket} entry `corelink {key}` "
            f"never matched — dead suppression; delete it (record the removal in "
            f"cli._retired) or state why it must stay armed.")

    # --- [okf-deferred-coherence] ---
    deferred_rules = allow.get("deferred_coherence", [])
    deferred_findings = run_deferred_coherence(deferred_rules, docs, warnings)
    deferred_tracked_ids = {r["id"] for r in deferred_rules if r.get("tracked")}
    deferred_fatal = [f for f in deferred_findings
                      if f.rule_id not in deferred_tracked_ids or args.strict]
    deferred_softtracked = [f for f in deferred_findings
                            if f.rule_id in deferred_tracked_ids and not args.strict]

    # --- [endpoint-existence] (best-effort, WARN unless flagship) ---
    try:
        route_inventory = collect_route_inventory()
    except (OSError, UnicodeDecodeError, SourceSyntaxError) as exc:
        print(f"DOCS-REALITY INVALID: route source parse failure: {exc}")
        return 1
    endpoint_cfg = allow.get("endpoint", {})
    flagship_files = set(endpoint_cfg.get("flagship_files", []))
    ignore_prefixes = tuple(endpoint_cfg.get("ignore_path_prefixes", []))
    ignore_paths = set(endpoint_cfg.get("ignore_paths", []))
    endpoint_warns: list[str] = []
    endpoint_fatal: list[str] = []
    seen_ep: set[tuple] = set()
    for d in docs:
        doc_lines = d.text.splitlines()
        for ln, raw in extract_doc_endpoints(d):
            norm = _normalise_endpoint(raw)
            if norm is None:
                continue
            if ignore_prefixes and norm.startswith(ignore_prefixes):
                continue
            if norm in ignore_paths:
                continue
            line_text = doc_lines[ln - 1] if ln <= len(doc_lines) else ""
            # The flagship inventory intentionally documents future operations;
            # `planned` is a typed non-runtime claim, not a promise that should
            # be resolved against today's router.
            if re.search(r"\bplanned\b", line_text, re.IGNORECASE):
                continue
            if endpoint_resolves(norm, route_inventory,
                                 method=_endpoint_method(line_text, raw)):
                continue
            key = (d.rel, norm)
            if key in seen_ep:
                continue
            seen_ep.add(key)
            msg = (f"[endpoint-existence] {d.rel}:{ln} — path `{norm}` "
                   f"resolves to no wired route")
            if d.rel in flagship_files:
                endpoint_fatal.append(msg)
            else:
                endpoint_warns.append(msg)

    # --- [hostname-liveness] ---
    # A path that resolves to a wired route proves nothing when the HOST in front
    # of it is NXDOMAIN. Static comparison against the checked-in allowlist (see
    # `--verify-dns` for the manual refresh path).
    hostres = run_hostname_liveness(host_cfg, strict=args.strict)
    host_failures = hostres.failures
    host_scope_fail = hostres.scope_failures
    host_tracked = hostres.tracked
    host_strict_fail = hostres.tracked_strict
    host_scan_errors = hostres.scan_errors
    host_expiry_fail = hostres.expiry_failures
    host_scope_errors = hostres.scope_errors
    warnings.extend(hostres.warnings)

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    # The hostname share comes from the result object's own `total_fail`, so a
    # bucket added there can never be counted in the report but left out here.
    total_fail = (len(cli_failures) + len(strict_tracked_fail) +
                  len(deferred_fatal) + len(endpoint_fatal) +
                  hostres.total_fail)

    if cli_failures:
        print("== [cli-existence] FAIL — documented command does not exist ==")
        for _k, r, msg in sorted(cli_failures, key=lambda x: (x[0], x[1].file)):
            print(f"  {r.file}:{r.line}: {msg}")
        print()

    if strict_tracked_fail:
        print("== [cli-existence] --strict — tracked drift (would fail the gate) ==")
        for key, r in sorted(strict_tracked_fail, key=lambda x: x[0]):
            note = cli_allow.get("tracked_drift", {}).get(key, {})
            reason = note.get("reason", "") if isinstance(note, dict) else str(note)
            print(f"  {r.file}:{r.line}: `corelink {key}` — {reason}")
        print()

    if deferred_fatal:
        print("== [okf-deferred-coherence] FAIL — claim contradicts OKF/code ==")
        for f in deferred_fatal:
            print(f"  {f.file}:{f.line}: [{f.rule_id}] {f.reason}")
            print(f"      > {f.excerpt}")
        print()

    if endpoint_fatal:
        print("== [endpoint-existence] FAIL — flagship recipe path is not wired ==")
        for m in endpoint_fatal:
            print(f"  {m}")
        print()

    if host_scan_errors:
        print("== [hostname-liveness] ERROR — the scan itself is not trustworthy ==")
        for m in host_scan_errors:
            print(f"  {m}")
        print()

    if host_expiry_fail:
        print("== [hostname-liveness] FAIL — expired/undated hostname suppression ==")
        for m in host_expiry_fail:
            print(f"  {m}")
        print()

    if host_scope_errors:
        print("== [hostname-liveness] FAIL — hostname suppression with no file scope ==")
        for m in host_scope_errors:
            print(f"  {m}")
        print()

    if host_failures:
        print("== [hostname-liveness] FAIL — shipped surface names a host that is "
              "not on the proven-live allowlist ==")
        for host, r in sorted(host_failures, key=lambda x: (x[0], x[1].file, x[1].line)):
            print(f"  {r.file}:{r.line}: `{host}` is not in hostname.live_allow "
                  f"(verified-live registry). Repoint it at a real host, or add a "
                  f"hostname.tracked_dead entry with a reason, files + expiry.")
            print(f"      > {r.excerpt}")
        print()

    if host_scope_fail:
        print("== [hostname-liveness] FAIL — suppressed dead host named in a file "
              "its suppression does not declare ==")
        for host, r in sorted(host_scope_fail, key=lambda x: (x[0], x[1].file, x[1].line)):
            print(f"  {r.file}:{r.line}: `{host}` is suppressed only for the files "
                  f"listed in its hostname.tracked_dead `files`; this file is not "
                  f"one of them. Remove the dead host here (preferred), or justify "
                  f"this file in the entry.")
            print(f"      > {r.excerpt}")
        print()

    if host_strict_fail:
        print("== [hostname-liveness] --strict — tracked dead hosts (would fail) ==")
        for host, r in sorted(host_strict_fail, key=lambda x: (x[0], x[1].file)):
            note = host_cfg.get("tracked_dead", {}).get(host, {})
            reason = note.get("reason", "") if isinstance(note, dict) else str(note)
            print(f"  {r.file}:{r.line}: `{host}` — {reason}")
        print()

    if host_tracked:
        print(f"-- tracked dead hosts (non-fatal; --strict to fail): "
              f"{len(host_tracked)} --")
        for host, rel in sorted({(h, rr.file) for h, rr in host_tracked}):
            print(f"  tracked: `{host}`  ({rel})")

    if cli_tracked:
        print(f"-- tracked CLI drift (non-fatal; --strict to fail): "
              f"{len(cli_tracked)} --")
        for key, rel in sorted({(k, rr.file) for k, rr in cli_tracked}):
            print(f"  tracked: `corelink {key}`  ({rel})")
    if deferred_softtracked:
        print(f"-- tracked claim drift (non-fatal; --strict to fail): "
              f"{len(deferred_softtracked)} --")
        for f in deferred_softtracked:
            print(f"  tracked: {f.file}:{f.line} [{f.rule_id}]")
    if warnings:
        print(f"-- warnings: {len(warnings)} --")
        for w in warnings:
            print(f"  {w}")
    if endpoint_warns:
        print(f"-- [endpoint-existence] unresolved (best-effort WARN): "
              f"{len(endpoint_warns)} --")
        for m in endpoint_warns[:40]:
            print(f"  {m}")
        if len(endpoint_warns) > 40:
            print(f"  ... and {len(endpoint_warns) - 40} more")

    print()
    if total_fail == 0:
        soft = len(warnings) + len(endpoint_warns) + len(deferred_softtracked)
        print(f"OK docs-reality: {len(all_refs)} CLI refs, "
              f"{len(hostres.refs)} hostname mentions in {len(hostres.files)} shipped "
              f"files, {len(cli_tracked) + len(host_tracked)} tracked, "
              f"{soft} warnings, 0 drift")
        return 0
    print(f"DOCS-REALITY INVALID: {total_fail} failures")
    return 1


if __name__ == "__main__":
    sys.exit(main())
