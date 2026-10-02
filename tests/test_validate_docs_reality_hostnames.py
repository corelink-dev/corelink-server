#!/usr/bin/env python3
"""
test_validate_docs_reality_hostnames.py — pytest suite for the
`[hostname-liveness]` dimension of `scripts/validate_docs_reality.py`.

Scope:

The Docs Reality Gate cross-checks documented CLI verbs against the clap enum and
documented HTTP PATHS against wired routes. It had no hostname or DNS dimension at
all, and it was PASSING ON MAIN the whole time the following shipped to real
users: the deployed docs site served NXDOMAIN hostnames on 9+ live pages,
`README.md` sent new users to a dead host, `openapi/corelink-v1.yaml` pointed
`termsOfService`/`contact.url`/`license.url` at a dead host, and six
regulator-facing breach-notification templates promised post-mortems on a dead
host. A path that resolves to a wired route is still a 404 for the customer when
the host in front of it does not exist — that is the coverage gap this suite
guards.

The regression targets, one test each:

  * a dead host on a SHIPPED surface FAILS (the defect above);
  * an allowlisted, proven-live host PASSES (no false positives on the corpus);
  * a dead host in an EXCLUDED path — a test fixture, a sealed `specs/` audit, a
    dated handoff document, `CHANGELOG.md` — does NOT fail. Sealed audits and
    history are load-bearing exclusions: rewriting history is forbidden in this
    repo, so a gate that reddened on them could only be satisfied illegally or by
    weakening itself;
  * an EMPTY (or implausibly small) scan is an ERROR, never a pass. This repo has
    just been burned by a daily billing cron that reported success for a month
    because the table it read was empty; a gate that greenlights because it looked
    at nothing manufactures confidence;
  * a suppression that matched NOTHING is reported ([suppression-hygiene]), and a
    suppression with a missing or past `expires` is fatal — an expiring
    suppression that never expires is a permanent mute wearing a date;
  * a suppression is scoped to the exact `files` it names: a missing `files`
    list is fatal, a mention of the suppressed host in any OTHER file fails,
    and a declared file that no longer mentions the host is reported — so a
    renewal justified by one historical record cannot mute the same dead host
    on a customer page;
  * a console path written in place of a retired host names a page the admin
    console actually RENDERS, decided against the App Router table — not a
    redirect handler, and not a path with no page at all;
  * the gate performs NO network I/O (DNS/TLS live only in the opt-in
    `--verify-dns` mode), because CI here runs on the founder's own Mac and a
    networked gate is a flaky gate.

The script is loaded via `importlib` (it is a `scripts/` module, not a package)
and registered in `sys.modules` so its `@dataclass` definitions resolve. Fixture
repos are built under `tmp_path` and passed through the `repo_root=` seam, so no
test mutates the real tree.

Run:
    python3 -m pytest tests/test_validate_docs_reality_hostnames.py -v
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_docs_reality.py"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "docs_reality_allowlist.json"


def _load_script_module():
    spec = importlib.util.spec_from_file_location(
        "validate_docs_reality", SCRIPT_PATH
    )
    assert spec is not None, f"could not load {SCRIPT_PATH}"
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Registered BEFORE exec: @dataclass resolves the defining module by name.
    sys.modules["validate_docs_reality"] = module
    spec.loader.exec_module(module)
    return module


SCRIPT = _load_script_module()

DEAD = "status.corelink.humangr.com"
LIVE = "corelink-api.humangr.com"

# A minimal, deliberately permissive config: `corelink-api.humangr.com` is on the
# proven-live registry, nothing is suppressed.
BASE_CFG = {
    "live_allow": {LIVE: "verified live in the fixture"},
    "live_patterns": [
        {"pattern": r"^[A-Za-z0-9_-]+\._domainkey\.humangr\.com$",
         "reason": "DKIM selector family"},
    ],
    "tracked_dead": {},
}


# --- fixture-repo helpers -----------------------------------------------------


def _write(repo: Path, rel: str, text: str) -> Path:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _run(repo: Path, cfg: dict | None = None, **kwargs):
    """Run the check against a fixture repo with the scan floors relaxed (the
    real floors are exercised by their own tests below)."""
    kwargs.setdefault("min_files", 1)
    kwargs.setdefault("min_mentions", 1)
    return SCRIPT.run_hostname_liveness(
        cfg if cfg is not None else BASE_CFG, repo_root=repo, **kwargs
    )


def _hosts(result) -> set[str]:
    return {h for h, _ref in result.failures}


# --- the core contract --------------------------------------------------------


def test_dead_host_on_shipped_surface_fails(tmp_path: Path):
    """The defect this dimension exists for: a dead host in shipped copy."""
    _write(tmp_path, "README.md", f"Check status at https://{DEAD}/\n")
    res = _run(tmp_path)
    assert DEAD in _hosts(res)
    assert res.total_fail >= 1
    offender = next(r for h, r in res.failures if h == DEAD)
    assert offender.file == "README.md"
    assert offender.line == 1


@pytest.mark.parametrize(
    "rel",
    [
        "README.md",
        "openapi/corelink-v1.yaml",
        "legal/breach-notification/template.md",
        "apps/docs/docs/quickstart.md",
        "apps/docs/i18n/pt-BR/docusaurus-plugin-content-docs/current/trust/index.mdx",
        "marketing/launch/FAQ.md",
        "examples/bazel-starter/README.md",
        "templates/ci/config.yml",
        "sdks/python/client.py",
        "corelink-go/corelink.go",
        "tools/cli/src/telemetry.rs",
        "worker/src/index.ts",
        "apps/admin-ui/src/config.ts",
        "crates/corelink-ops/src/deploy.rs",
    ],
)
def test_every_shipped_surface_is_scanned(tmp_path: Path, rel: str):
    """Requirement 1's surface list, asserted one path at a time — including the
    docs-site `i18n/` tree (a translated dead host is still a dead host) and the
    live `src/` trees reached by the `apps/*/src` + `crates/*/src` globs."""
    _write(tmp_path, rel, f"url = https://{DEAD}/x\n")
    res = _run(tmp_path)
    assert DEAD in _hosts(res), f"{rel} was not scanned"


def test_allowlisted_live_host_passes(tmp_path: Path):
    _write(tmp_path, "README.md",
           f"POST https://{LIVE}/v1/cas/blobs — and mail us at hi@humangr.com\n")
    res = _run(tmp_path, cfg={**BASE_CFG,
                              "live_allow": {LIVE: "live", "humangr.com": "apex"}})
    assert res.failures == []
    assert res.total_fail == 0


def test_live_pattern_allows_the_dkim_family(tmp_path: Path):
    """DKIM selectors are a family of TXT records, not an enumerable set of
    serving hosts — pattern-allowed rather than listed one by one."""
    _write(tmp_path, "README.md", "resend._domainkey.humangr.com TXT ...\n")
    assert _run(tmp_path).failures == []


def test_unknown_subdomain_of_an_allowlisted_host_still_fails(tmp_path: Path):
    """The allowlist is exact-match + explicit patterns; it must NOT act as a
    suffix wildcard, or one live host would launder every dead child under it."""
    _write(tmp_path, "README.md", f"https://weur.{LIVE}/v1\n")
    assert f"weur.{LIVE}" in _hosts(_run(tmp_path))


def test_templated_placeholder_host_is_not_reported(tmp_path: Path):
    """`{region}.corelink-api.humangr.com` is a placeholder, not a literal; the
    gate must not invent a phantom `region.` host out of it."""
    _write(tmp_path, "README.md", "https://{region}.corelink-api.humangr.com/v1\n")
    res = _run(tmp_path, min_mentions=0)
    assert res.failures == []


# --- exclusions ---------------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        "tests/e2e/isolation.md",                       # tests/
        "conformance/reapi/cases.md",                   # conformance/
        "specs/_audits/sealed/2026-05-16-ga-1.md",      # sealed audits
        "tools/cli/src/webauthn_test.rs",               # *_test*
        "apps/docs/src/pages/trust.test.tsx",           # *.test.*
        "sdks/js/client.spec.ts",                       # *.spec.*
        "CHANGELOG.md",                                 # historical ledger
        "docs/findings/dead-hosts.md",                  # findings
        "reports/2026-08-audit.md",                     # reports/
        "marketing/2026-08-18-erasure-handoff.md",      # dated handoff
        "marketing/RELAY-2026-08-12.md",                # dated relay
        "_archive/old-site/index.html",                 # not authored
        "releases/v1.0.0/notes.md",                     # not authored
        "apps/docs/node_modules/pkg/readme.md",         # deps
        "crates/corelink-ops/target/doc/x.html",        # build output
        "mutants.out/log.md",                           # mutation output
    ],
)
def test_dead_host_in_excluded_path_does_not_fail(tmp_path: Path, rel: str):
    """A dead host in a fixture, a sealed audit or a history file harms nobody —
    and `evil.corelink.humangr.com` NOT existing is the POINT of an isolation
    test. A floor breach is expected here (the scan legitimately sees nothing),
    but there must be no hostname FAILURE."""
    _write(tmp_path, rel, f"https://{DEAD}/ and https://evil.{DEAD}/\n")
    res = _run(tmp_path, min_files=0, min_mentions=0)
    assert res.failures == [], f"{rel} should be excluded from the scan"
    assert res.refs == []


# --- fail loud, never silently green -----------------------------------------


def test_empty_scan_is_an_error_not_a_pass(tmp_path: Path):
    """The billing-cron failure mode: report success because the corpus read back
    empty. An empty scan must be an ERROR."""
    res = SCRIPT.run_hostname_liveness(BASE_CFG, repo_root=tmp_path)
    assert res.files == []
    assert res.refs == []
    assert res.failures == []
    assert res.scan_errors, "an empty scan must be an ERROR, not a pass"
    assert res.total_fail > 0
    assert any("SCAN TOO SMALL" in e for e in res.scan_errors)


def test_scan_below_the_mention_floor_is_an_error(tmp_path: Path):
    """A corpus of files with no hostnames in it means the regex or the corpus
    moved — also an error, not a pass."""
    for i in range(3):
        _write(tmp_path, f"marketing/f{i}.md", "no hostnames here\n")
    res = SCRIPT.run_hostname_liveness(BASE_CFG, repo_root=tmp_path,
                                       min_files=1, min_mentions=25)
    assert any("ALMOST NOTHING" in e for e in res.scan_errors)
    assert res.total_fail > 0


def test_empty_live_allow_is_an_error(tmp_path: Path):
    """Judging every hostname against an empty registry is not a check."""
    _write(tmp_path, "README.md", f"https://{LIVE}/\n")
    res = _run(tmp_path, cfg={"live_allow": {}, "live_patterns": [],
                              "tracked_dead": {}})
    assert any("EMPTY ALLOWLIST" in e for e in res.scan_errors)
    assert res.total_fail > 0


def test_the_real_repo_scan_clears_both_floors():
    """The floors must be satisfied by the ACTUAL tree, not only by fixtures —
    otherwise the guard is theatre. Uses the real constants."""
    files = SCRIPT.iter_host_scan_files()
    assert len(files) >= SCRIPT.MIN_HOST_SCAN_FILES
    cfg = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))["hostname"]
    res = SCRIPT.run_hostname_liveness(cfg)
    assert res.scan_errors == []
    assert len(res.refs) >= SCRIPT.MIN_HOST_MENTIONS


# --- suppression machinery ----------------------------------------------------


def _tracked(host: str, expires: str = "2099-01-01",
             files: list[str] | None = None) -> dict:
    return {**BASE_CFG, "tracked_dead": {
        host: {"reason": "TODO(dead-host-sweep): fixture",
               "added": "2026-08-22", "owner": "fixture", "expires": expires,
               "files": ["README.md"] if files is None else files}}}


def test_tracked_dead_host_is_suppressed_but_visible(tmp_path: Path):
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    res = _run(tmp_path, cfg=_tracked(DEAD))
    assert res.failures == []
    assert res.total_fail == 0
    assert [h for h, _ in res.tracked] == [DEAD]


def test_tracked_dead_host_is_fatal_under_strict(tmp_path: Path):
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    res = _run(tmp_path, cfg=_tracked(DEAD), strict=True)
    assert res.tracked == []
    assert [h for h, _ in res.tracked_strict] == [DEAD]
    assert res.total_fail == 1


def test_suppression_that_matched_nothing_is_reported(tmp_path: Path):
    """[suppression-hygiene]: the sweep landed, so the entry must be DELETED —
    a dead suppression stands armed to re-silence the same defect on recurrence.
    Non-fatal, exactly like the CLI buckets."""
    _write(tmp_path, "README.md", f"https://{LIVE}/\n")
    res = _run(tmp_path, cfg=_tracked(DEAD))
    assert any("[suppression-hygiene]" in w and DEAD in w and "never matched" in w
               for w in res.warnings)
    assert res.total_fail == 0


def test_suppression_without_expiry_is_fatal(tmp_path: Path):
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    cfg = {**BASE_CFG, "tracked_dead": {DEAD: {"reason": "no expiry"}}}
    res = _run(tmp_path, cfg=cfg)
    assert any("no valid ISO" in m for m in res.expiry_failures)
    assert res.total_fail > 0


def test_expired_suppression_is_fatal(tmp_path: Path):
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    res = _run(tmp_path, cfg=_tracked(DEAD, expires="2020-01-01"))
    assert any("EXPIRED" in m for m in res.expiry_failures)
    assert res.total_fail > 0


@pytest.mark.parametrize(
    "files",
    [None, [], [""], ["README.md", 7], "README.md"],
    ids=["missing", "empty", "blank", "non-string", "not-a-list"],
)
def test_suppression_without_a_file_scope_is_fatal(tmp_path: Path, files):
    """[suppression-scope]: an entry that does not name the files it covers is a
    host-wide mute. Every malformed spelling of `files` is a hard failure that
    names the host — never a silently unscoped suppression."""
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    cfg = _tracked(DEAD)
    meta = dict(cfg["tracked_dead"][DEAD])
    if files is None:
        del meta["files"]
    else:
        meta["files"] = files
    cfg = {**cfg, "tracked_dead": {DEAD: meta}}
    res = _run(tmp_path, cfg=cfg)
    assert any(DEAD in m and "`files`" in m for m in res.scope_errors), res.scope_errors
    assert res.total_fail > 0


def test_tracked_host_in_an_undeclared_file_fails(tmp_path: Path):
    """The defect the scope exists for: a dead host renewed because ONE file
    legitimately keeps it must still FAIL the moment it reappears anywhere else
    — here a customer quickstart — and the failure names that file and line."""
    _write(tmp_path, "README.md", f"history: https://{DEAD}/ was retired\n")
    _write(tmp_path, "apps/docs/docs/quickstart.md", f"\nVisit https://{DEAD}/\n")
    res = _run(tmp_path, cfg=_tracked(DEAD, files=["README.md"]))
    assert [(h, r.file, r.line) for h, r in res.scope_failures] == \
        [(DEAD, "apps/docs/docs/quickstart.md", 2)]
    assert [(h, r.file) for h, r in res.tracked] == [(DEAD, "README.md")]
    assert res.failures == []
    assert res.total_fail == 1


def test_declared_file_that_no_longer_mentions_the_host_is_reported(tmp_path: Path):
    """[suppression-hygiene] one level down: a stale file in `files` stands armed
    to re-silence that file later, so it is reported by name (non-fatal, like the
    whole-entry hygiene warning)."""
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    _write(tmp_path, "marketing/swept.md", f"https://{LIVE}/\n")
    res = _run(tmp_path, cfg=_tracked(DEAD, files=["README.md", "marketing/swept.md"]))
    stale = [w for w in res.warnings if "[suppression-hygiene]" in w]
    assert len(stale) == 1 and DEAD in stale[0] and "marketing/swept.md" in stale[0]
    assert res.total_fail == 0


def test_suppression_expiry_is_evaluated_against_today(tmp_path: Path):
    """Frozen `today` so the test does not drift into failing on a calendar."""
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    ok = _run(tmp_path, cfg=_tracked(DEAD, expires="2026-09-30"),
              today=(2026, 8, 22))
    assert ok.expiry_failures == []
    late = _run(tmp_path, cfg=_tracked(DEAD, expires="2026-09-30"),
                today=(2026, 10, 1))
    assert any("EXPIRED" in m for m in late.expiry_failures)


# --- the shipped allowlist itself --------------------------------------------


def test_shipped_allowlist_hostname_section_is_wellformed():
    cfg = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))["hostname"]
    assert cfg["live_allow"], "live_allow must not be empty"
    for host, meta in cfg["tracked_dead"].items():
        assert isinstance(meta, dict), f"{host}: suppression must be an object"
        for key in ("reason", "added", "owner", "expires", "files"):
            assert meta.get(key), f"{host}: suppression is missing `{key}`"
        assert SCRIPT._parse_iso_date(meta["expires"]), \
            f"{host}: `expires` must be an ISO date"
        # A declared file that does not exist is a typo that scopes nothing.
        for rel in meta["files"]:
            assert (REPO_ROOT / rel).is_file(), f"{host}: declared file {rel} is missing"


def test_status_host_suppression_records_the_real_root_cause():
    """Requirement: `status.corelink.humangr.com` gets an explicit, EXPIRING
    suppression that records WHY it is dead — DNS resolves, TLS does not, because
    it is a third-level name outside Cloudflare Universal SSL's one-level `*.`
    coverage and BetterUptime 403s the Host (the custom domain was never
    registered there), so neither side holds a certificate."""
    cfg = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))["hostname"]
    entry = cfg["tracked_dead"].get("status.corelink.humangr.com")
    assert entry, "the status host must be suppressed EXPLICITLY, not silently"
    reason = entry["reason"].lower()
    for token in ("tls", "third-level", "universal ssl", "betteruptime", "403"):
        assert token in reason, f"root cause omits `{token}`"
    assert SCRIPT._parse_iso_date(entry["expires"])


def test_shipped_allowlist_holds_the_gate_green_on_the_real_tree():
    """The dimension must ship GREEN on the current tree (the sweep is landing
    concurrently) while still being MEANINGFUL — i.e. green only because every
    outstanding dead host is TRACKED, and red under --strict."""
    cfg = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))["hostname"]
    assert SCRIPT.run_hostname_liveness(cfg).total_fail == 0
    assert SCRIPT.run_hostname_liveness(cfg, strict=True).total_fail > 0


# --- replacement destinations must render a console page ----------------------
#
# Retiring a dead host is honest only if what replaces it is reachable. Two
# replacements in the 2026-10-01 sweep named console paths that render no page:
# the PCI-DSS CSP self-check curled `/corelink/pricing`, which is the
# apps/admin-ui/src/app/pricing/route.ts 307 redirect (its headers say nothing
# about any page), and status-page component C8 named `/corelink/admin`, which
# has no page at all (only `/[locale]/admin/{tenants,audit}` exist). An HTTP
# probe cannot settle this for an auth-gated path, because the middleware
# redirects a signed-out client before routing, so the authority is the App
# Router table itself.

ADMIN_APP_DIR = REPO_ROOT / "apps" / "admin-ui" / "src" / "app"
ADMIN_LOCALES_SRC = REPO_ROOT / "apps" / "admin-ui" / "src" / "i18n" / "request.ts"
# `humangr.com/corelink[/path]`, with or without a scheme. The lookbehind refuses
# a match inside another host (`x.humangr.com/corelink`); the lookahead refuses
# `/corelinkfoo`. Group 1 is the path below the `/corelink` basePath.
CONSOLE_URL_RE = re.compile(
    r"(?<![A-Za-z0-9.-])humangr\.com/corelink(?![A-Za-z0-9-])(/[^\s`'\"|)]*)?")
_PAGE_FILES = ("page.tsx", "page.ts", "page.jsx", "page.js")
_ROUTE_FILES = ("route.ts", "route.tsx", "route.js")


def _admin_locales() -> frozenset[str]:
    text = ADMIN_LOCALES_SRC.read_text(encoding="utf-8")
    m = re.search(r"export const LOCALES = \[([^\]]*)\] as const", text)
    assert m, f"`LOCALES` not found in {ADMIN_LOCALES_SRC}"
    locales = frozenset(re.findall(r'"([A-Za-z-]+)"', m.group(1)))
    assert locales, f"`LOCALES` in {ADMIN_LOCALES_SRC} parsed empty"
    return locales


def _is_route_group(d: Path) -> bool:
    return d.name.startswith("(") and d.name.endswith(")")


def _segment_dirs(d: Path) -> list[Path]:
    """Child directories that consume a URL segment; `(group)` dirs are
    transparent, so their children are lifted to this level."""
    out: list[Path] = []
    for child in sorted(p for p in d.iterdir() if p.is_dir()):
        out.extend(_segment_dirs(child) if _is_route_group(child) else [child])
    return out


def _leaf_kind(d: Path) -> str | None:
    if any((d / name).is_file() for name in _PAGE_FILES):
        return "page"
    if any((d / name).is_file() for name in _ROUTE_FILES):
        return "route"
    for group in sorted(p for p in d.iterdir() if p.is_dir() and _is_route_group(p)):
        kind = _leaf_kind(group)
        if kind:
            return kind
    return None


def _resolve(d: Path, segs: list[str], locales: frozenset[str]) -> str | None:
    kids = _segment_dirs(d)
    if not segs:
        kind = _leaf_kind(d)
        if kind:
            return kind
        # An optional catch-all (`[[...x]]`) also matches zero segments.
        for kid in kids:
            if kid.name.startswith("[[..."):
                return _leaf_kind(kid)
        return None
    head, rest = segs[0], segs[1:]
    # App Router precedence: a static segment, then a dynamic one, then a
    # catch-all.
    for kid in kids:
        if kid.name == head:
            kind = _resolve(kid, rest, locales)
            if kind:
                return kind
    for kid in kids:
        name = kid.name
        if name.startswith("[") and not name.startswith(("[...", "[[")):
            # `[locale]` is only a page for a shipped locale.
            if name == "[locale]" and head not in locales:
                continue
            kind = _resolve(kid, rest, locales)
            if kind:
                return kind
    for kid in kids:
        if kid.name.startswith(("[...", "[[...")):
            kind = _leaf_kind(kid)
            if kind:
                return kind
    return None


def _console_leaf(path: str) -> str | None:
    """`page`, `route` (a handler such as a redirect) or None for a path below
    the `/corelink` basePath of the admin console."""
    path = path.split("?", 1)[0].split("#", 1)[0].rstrip(".,;:")
    segs = [s for s in path.split("/") if s]
    return _resolve(ADMIN_APP_DIR, segs, _admin_locales())


def _console_paths(text: str) -> list[str]:
    return [m.group(1) or "/" for m in CONSOLE_URL_RE.finditer(text)]


def test_console_route_resolver_sees_pages_redirects_and_gaps():
    """The resolver must be able to say NO before a YES from it means anything:
    positive and negative controls on the real router table."""
    assert _console_leaf("/") == "page"
    assert _console_leaf("/en/pricing") == "page"
    assert _console_leaf("/en/admin/tenants") == "page"
    assert _console_leaf("/en/admin/audit") == "page"
    assert _console_leaf("/sign-up") == "page"           # optional catch-all
    assert _console_leaf("/pricing") == "route"          # the 307 redirect
    assert _console_leaf("/admin") is None
    assert _console_leaf("/en/admin") is None
    assert _console_leaf("/xx/pricing") is None          # not a shipped locale
    assert _console_paths("see https://humangr.com/corelink/en/pricing |") == [
        "/en/pricing"]
    assert _console_paths("`humangr.com/corelink` and x.humangr.com/corelink/a") == [
        "/"]


PCI_DSS_PAGES = [
    "apps/docs/docs/trust/pci-dss.mdx",
    *(f"apps/docs/i18n/{loc}/docusaurus-plugin-content-docs/current/trust/pci-dss.mdx"
      for loc in ("de", "es-419", "pt-BR")),
]


@pytest.mark.parametrize("rel", PCI_DSS_PAGES)
def test_pci_csp_check_inspects_the_rendered_pricing_page(rel: str):
    """The PCI-DSS self-check must read the CSP the rendered pricing page is
    served with: it fetches a console PAGE (not the redirect handler), refuses
    anything but a 200 HTML response, does not follow redirects, and greps the
    header dump of that same response."""
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    m = re.search(r"^# 2\. Inspect the Content-Security-Policy.*?(?=^# Expected)",
                  text, re.S | re.M)
    assert m, f"{rel}: the CSP self-verification step is missing"
    command = "\n".join(line for line in m.group(0).splitlines()
                        if not line.lstrip().startswith("#"))
    paths = _console_paths(command)
    assert len(paths) == 1, f"{rel}: want exactly one console URL, got {paths}"
    assert _console_leaf(paths[0]) == "page", \
        f"{rel}: `/corelink{paths[0]}` does not render a console page"
    assert "-w '%{http_code} %{content_type}\\n'" in command, \
        f"{rel}: the check does not report the status and content type"
    assert "grep -E '^200 text/html' &&" in command, \
        f"{rel}: the check does not refuse a non-200 or non-HTML response"
    assert not re.search(r"(?:^|\s)(?:-[A-Za-z]*L[A-Za-z]*|--location)\b", command), \
        f"{rel}: following a redirect would inspect another response"
    dump = re.search(r"\s-D\s+(\S+)", command)
    assert dump, f"{rel}: the check does not dump the response headers"
    assert f"grep -i '^content-security-policy:' {dump.group(1)}" in command, \
        f"{rel}: the CSP is not read from the fetched page's own headers"


@pytest.mark.parametrize("rel", ["marketing/launch/STATUS-PAGE-SPEC.md",
                                 "marketing/launch/STATUSPAGE-INIT.md"])
def test_status_page_admin_console_component_names_an_implemented_page(rel: str):
    """Status-page component C8 must name an admin-console page that exists."""
    rows = [line for line in (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines()
            if re.match(r"^\|\s*(?:\*\*)?C8(?:\*\*)?\s*\|", line)]
    assert len(rows) == 1, f"{rel}: want exactly one C8 row, got {len(rows)}"
    paths = _console_paths(rows[0])
    assert len(paths) == 1, f"{rel}: want exactly one console URL in C8, got {paths}"
    assert _console_leaf(paths[0]) == "page", \
        f"{rel}: `/corelink{paths[0]}` does not render a console page"


# --- no network at CI time ----------------------------------------------------


def test_the_gate_performs_no_dns_or_tls(tmp_path: Path, monkeypatch):
    """CI here runs on the founder's own Mac. Live DNS would make the gate
    flaky and network-dependent; resolution lives only in `--verify-dns`."""
    import socket

    def _boom(*_a, **_k):  # pragma: no cover - must never be reached
        raise AssertionError("the gate must not touch the network")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    _write(tmp_path, "README.md", f"https://{DEAD}/\n")
    assert DEAD in _hosts(_run(tmp_path))


def test_verify_dns_is_opt_in_and_reports_per_host(monkeypatch):
    """`--verify-dns` is the MANUAL refresh path — it is the only code path
    allowed to resolve, and it classifies DEAD vs DNS-ONLY (resolves but no TLS)
    so a host like the status page cannot be mistaken for healthy by `dig`."""
    import socket

    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: (_ for _ in ()).throw(socket.gaierror("nxdomain"))
        if host == "nope.humangr.com" else [(2, 1, 6, "", ("192.0.2.1", 443))])

    def _no_tcp(*_a, **_k):
        raise TimeoutError("blocked in test")

    monkeypatch.setattr(socket, "create_connection", _no_tcp)
    verdicts = dict(SCRIPT.verify_dns(["nope.humangr.com", "resolves.humangr.com"]))
    assert verdicts["nope.humangr.com"].startswith("DEAD")
    assert verdicts["resolves.humangr.com"].startswith("DNS-ONLY")
