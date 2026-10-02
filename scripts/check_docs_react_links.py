#!/usr/bin/env python3
"""Resolve every internal link written by hand in the docs React pages.

WHY THIS GATE EXISTS (measured, 2026-08-31)
-------------------------------------------
`apps/docs/docusaurus.config.ts` sets `onBrokenLinks: "throw"`, so the docs
build is green. That setting only covers links Docusaurus itself resolves:
Markdown/MDX links and `<Link>` elements whose target it can see. It does NOT
cover a raw `<a href="/...">` typed into a React page under
`apps/docs/src/pages/**`. Four such links on the LIVE legal pages were 404
in production while every gate in the repo was green:

    /explanation/compliance/dpa   (x6)  -- file exists but is `draft: true`
                                         AND declares `slug: "/compliance/dpa"`
    /explanation/privacy/gdpr           -- ditto, slug `/privacy/gdpr`
    /explanation/privacy/lgpd-full      -- ditto, slug `/privacy/lgpd-full`
    /explanation/sre/slo                -- no such directory at all

This script closes that hole: it classifies every `href=` / `to=` attribute in
JSX opening tags under `apps/docs/src/**/*.{tsx,jsx}`. Site-root string
literals (single- or double-quoted) are resolved against destinations the
PRODUCTION build actually serves; empty/malformed literals fail. Balanced
dynamic expressions are explicitly counted and reported as unverified rather
than being silently mistaken for a checked route.

ANTI-VACUITY CONTRACT
---------------------
A gate that cannot find anything must SCREAM, never pass. Every way of
failing to obtain a list is a named, loud `fail()` here:

  * a required directory or file is missing            -> named failure
  * a glob matches zero files                          -> named failure
  * front-matter is unparseable / not a mapping        -> named failure
  * zero doc destinations, zero page destinations,
    zero static destinations, zero redirects, or zero
    scanned hrefs                                      -> named failure
  * a live source population below the measured B-168 floor -> named failure
  * `routeBasePath` / `baseUrl` cannot be read from
    docusaurus.config.ts                               -> named failure

Front-matter is parsed with PyYAML, never with a regex.

Run: python3 scripts/check_docs_react_links.py [--verbose]
Exit 0 = every internal href resolves. Exit 1 = at least one does not, or the
gate could not establish its own inputs.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment failure must be loud
    print("FAIL[dependency]: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    raise SystemExit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_APP = REPO_ROOT / "apps" / "docs"
CONFIG_FILE = DOCS_APP / "docusaurus.config.ts"
DOCS_DIR = DOCS_APP / "docs"
BLOG_DIR = DOCS_APP / "blog"
PAGES_DIR = DOCS_APP / "src" / "pages"
STATIC_DIR = DOCS_APP / "static"
SCAN_DIR = DOCS_APP / "src"

DOC_EXTS = (".md", ".mdx")
PAGE_EXTS = (".tsx", ".jsx", ".ts", ".js", ".md", ".mdx")
SCAN_EXTS = (".tsx", ".jsx")

# Route base paths, mirrored from docusaurus.config.ts. Asserted against the
# config file below rather than trusted -- if the config moves the docs off
# `/` this gate must fail loudly, not silently resolve against a stale map.
DOCS_ROUTE_BASE = "/"
BLOG_ROUTE_BASE = "/blog"

# Routes Docusaurus generates for the blog plugin itself (listing, archive,
# tag index). Not derived from files, so they are declared here explicitly.
BLOG_GENERATED_ROUTES = ("/blog", "/blog/archive", "/blog/tags")

# Docusaurus `numberPrefixParser` default: `01-foo` / `1.foo` -> `foo`.
NUMBER_PREFIX_RE = re.compile(r"^\d+[-._]\s*")

# This is deliberately a small JSX *attribute* scanner rather than a whole
# TypeScript parser.  The previous regex only recognised double-quoted values,
# and silently ignored a single quote, an empty value, a malformed attribute,
# and every expression.  Parsing opening tags means strings/comments elsewhere
# in a .tsx file are not mistaken for links, while keeping this gate dependency
# free on the runner.
LINK_ATTRIBUTE_NAMES = frozenset(("href", "to"))
ATTRIBUTE_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-."
)

FAILURES: list[str] = []


@dataclass(frozen=True)
class LinkAttribute:
    """One href/to attribute found in a JSX opening tag.

    ``kind`` is one of ``literal``, ``dynamic``, or ``malformed``.  Dynamic
    expressions are intentionally *classified*, printed in the population, and
    never treated as a route this source-only gate has resolved.  A code review
    must establish their runtime target; a new literal site-root route is
    covered here automatically.  Empty and malformed values are failures.
    """

    path: Path
    line: int
    name: str
    kind: str
    value: str | None = None
    detail: str = ""


def fail(kind: str, message: str) -> None:
    FAILURES.append(f"FAIL[{kind}]: {message}")


def require_dir(path: Path, kind: str) -> bool:
    if not path.is_dir():
        fail(kind, f"required directory does not exist: {path}")
        return False
    return True


def read_front_matter(path: Path) -> dict:
    """Parse YAML front-matter. Any unreadable/odd shape is a LOUD failure."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail("front-matter", f"{path}: unreadable ({exc})")
        return {}
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        fail("front-matter", f"{path}: opening '---' with no closing '---'")
        return {}
    raw = text[3:end]
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        fail("front-matter", f"{path}: YAML parse error ({exc})")
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        fail("front-matter", f"{path}: front-matter is {type(data).__name__}, expected a mapping")
        return {}
    return data


def join_route(base: str, rel: str) -> str:
    joined = "/" + "/".join(p for p in f"{base}/{rel}".split("/") if p)
    return joined


def strip_number_prefixes(rel: str) -> str:
    return "/".join(NUMBER_PREFIX_RE.sub("", seg) for seg in rel.split("/") if seg)


def normalize(route: str) -> str:
    """Site-absolute, no trailing slash (`trailingSlash: false`), no case fold."""
    if not route.startswith("/"):
        route = "/" + route
    route = re.sub(r"/{2,}", "/", route)
    if len(route) > 1:
        route = route.rstrip("/")
    return route


def assert_config(verbose: bool) -> str:
    """Read baseUrl + assert the docs/blog routeBasePath this gate assumes."""
    if not CONFIG_FILE.is_file():
        fail("config", f"docusaurus config not found: {CONFIG_FILE}")
        return ""
    text = CONFIG_FILE.read_text(encoding="utf-8")

    base_url_match = re.search(r'const\s+BASE_URL\s*=\s*"([^"]+)"', text)
    if not base_url_match:
        fail("config", f"{CONFIG_FILE}: could not read `const BASE_URL = \"...\"`")
        base_url = ""
    else:
        base_url = base_url_match.group(1)

    route_bases = re.findall(r'routeBasePath:\s*"([^"]*)"', text)
    if not route_bases:
        fail("config", f"{CONFIG_FILE}: no `routeBasePath:` found -- route map cannot be trusted")
    else:
        expected = {DOCS_ROUTE_BASE, BLOG_ROUTE_BASE}
        actual = {normalize(r) if r else "/" for r in route_bases}
        # `docsRouteBasePath` of the search plugin repeats "/" -- set compare.
        if not expected.issubset(actual):
            fail(
                "config",
                f"{CONFIG_FILE}: routeBasePath set {sorted(actual)} does not contain the "
                f"{sorted(expected)} this gate assumes -- update DOCS_ROUTE_BASE/BLOG_ROUTE_BASE",
            )
    if verbose:
        print(f"  config: BASE_URL={base_url!r} routeBasePath={sorted(set(route_bases))}")
    return base_url


def collect_doc_routes(root: Path, route_base: str, kind: str, verbose: bool) -> set[str]:
    """Published routes for a content dir, EXCLUDING `draft: true` files."""
    routes: set[str] = set()
    if not require_dir(root, kind):
        return routes
    files = sorted(p for p in root.rglob("*") if p.suffix in DOC_EXTS and p.is_file())
    if not files:
        fail(kind, f"glob matched ZERO {DOC_EXTS} files under {root}")
        return routes
    drafts = 0
    for path in files:
        # Docusaurus ignores `_`-prefixed files and partials directories.
        rel_parts = path.relative_to(root).parts
        if any(part.startswith("_") for part in rel_parts):
            continue
        fm = read_front_matter(path)
        if fm.get("draft") is True:
            drafts += 1
            continue
        rel = path.relative_to(root).with_suffix("").as_posix()
        rel = strip_number_prefixes(rel)
        segments = rel.split("/")
        if segments[-1].lower() in ("index", "readme"):
            segments = segments[:-1]
        elif isinstance(fm.get("id"), str) and fm["id"]:
            segments[-1] = fm["id"]
        parent = "/".join(segments[:-1]) if segments else ""

        slug = fm.get("slug")
        if isinstance(slug, str) and slug:
            if slug.startswith("/"):
                route = join_route(route_base, slug)
            else:
                route = join_route(route_base, f"{parent}/{slug}")
        else:
            route = join_route(route_base, "/".join(segments))
        routes.add(normalize(route))
    if not routes:
        fail(kind, f"ZERO published routes derived from {len(files)} files under {root}")
    if verbose:
        print(f"  {kind}: {len(routes)} published routes from {len(files)} files ({drafts} draft, excluded)")
    return routes


def collect_page_routes(verbose: bool) -> set[str]:
    routes: set[str] = set()
    if not require_dir(PAGES_DIR, "pages"):
        return routes
    files = sorted(p for p in PAGES_DIR.rglob("*") if p.suffix in PAGE_EXTS and p.is_file())
    if not files:
        fail("pages", f"glob matched ZERO {PAGE_EXTS} files under {PAGES_DIR}")
        return routes
    for path in files:
        name = path.name
        if name.startswith("_") or ".test." in name or ".spec." in name or ".module." in name:
            continue
        if any(part.startswith("_") for part in path.relative_to(PAGES_DIR).parts[:-1]):
            continue
        rel = path.relative_to(PAGES_DIR).with_suffix("").as_posix()
        segments = [s for s in rel.split("/") if s]
        if segments and segments[-1].lower() == "index":
            segments = segments[:-1]
        routes.add(normalize("/" + "/".join(segments)))
    if not routes:
        fail("pages", f"ZERO routes derived from {len(files)} files under {PAGES_DIR}")
    if verbose:
        print(f"  pages: {len(routes)} routes from {len(files)} files")
    return routes


def collect_static_routes(verbose: bool) -> set[str]:
    routes: set[str] = set()
    if not require_dir(STATIC_DIR, "static"):
        return routes
    files = [p for p in STATIC_DIR.rglob("*") if p.is_file()]
    if not files:
        fail("static", f"ZERO files under {STATIC_DIR}")
        return routes
    for path in files:
        routes.add(normalize("/" + path.relative_to(STATIC_DIR).as_posix()))
    if verbose:
        print(f"  static: {len(routes)} asset routes")
    return routes


def collect_redirect_sources(verbose: bool) -> set[str]:
    """`from:` sources of @docusaurus/plugin-client-redirects."""
    routes: set[str] = set()
    if not CONFIG_FILE.is_file():
        return routes
    text = CONFIG_FILE.read_text(encoding="utf-8")
    if "plugin-client-redirects" not in text:
        if verbose:
            print("  redirects: plugin not configured (0 sources)")
        return routes
    for match in re.finditer(r'\bfrom:\s*"([^"]+)"', text):
        routes.add(normalize(match.group(1)))
    if not routes:
        fail(
            "redirects",
            f"{CONFIG_FILE}: plugin-client-redirects IS configured but ZERO `from:` entries "
            "were parsed -- the redirect map cannot be trusted",
        )
    if verbose:
        print(f"  redirects: {len(routes)} `from:` sources")
    return routes


SCANNED_FILE_COUNT = 0

# Floors measured on the live source tree at B-168's repair (2026-09-01).
# These are lower bounds, not a frozen inventory: adding pages/links is fine;
# deleting the population that gives this gate something to prove is not.
# Re-measured for B-316 (2026-10-02): the /legal/sub-processors and
# /trust/sub-processor-register pages now render their vendor links from the
# shared sub-processors JSON instead of hard-coding them, which moved those
# attributes from literal (62 -> 55) to dynamic-classified (12 -> 17). The
# literal floor follows the measured population down by exactly that move and
# the dynamic floor rises by the same amount; internal hrefs are unchanged.
MIN_SCANNED_FILE_COUNT = 20
MIN_LITERAL_ATTRIBUTE_COUNT = 55
MIN_DYNAMIC_ATTRIBUTE_COUNT = 17
MIN_INTERNAL_HREF_COUNT = 30


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _skip_quoted(text: str, start: int) -> int | None:
    """Return the offset after a JS/JSX quoted string, or ``None`` if open."""
    quote = text[start]
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return None


def _skip_expression(text: str, start: int) -> int | None:
    """Return after a balanced JSX expression, respecting quoted strings."""
    if text[start] != "{":
        raise ValueError("expression must begin with '{'")
    depth = 1
    index = start + 1
    while index < len(text):
        char = text[index]
        if char in "'\"`":
            end = _skip_quoted(text, index)
            if end is None:
                return None
            index = end
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline == -1 else newline + 1
            continue
        if text.startswith("/*", index):
            end_comment = text.find("*/", index + 2)
            if end_comment == -1:
                return None
            index = end_comment + 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _literal_expression_value(expression: str) -> str | None:
    """Return a static value for ``{\"/route\"}``; otherwise it is dynamic."""
    match = re.fullmatch(r"\s*(['\"])(.*)\1\s*", expression, flags=re.DOTALL)
    return match.group(2) if match else None


def _parse_jsx_opening_tag(text: str, start: int, path: Path) -> tuple[list[LinkAttribute], int]:
    """Parse one JSX opening tag, returning attributes and the next offset.

    The caller enters only while in executable JSX/TS code (not a JS string or
    comment). A complete ``>``/``/>`` is mandatory once a link attribute has
    been seen: accepting a value from an unclosed tag would turn malformed JSX
    into a false green.
    """
    attributes: list[LinkAttribute] = []
    cursor = start + 1
    while cursor < len(text) and text[cursor] in ATTRIBUTE_NAME_CHARS:
        cursor += 1
    tag_line = _line_number(text, start)
    saw_link = False

    def malformed(name: str, line: int, detail: str) -> None:
        nonlocal saw_link
        saw_link = True
        attributes.append(LinkAttribute(path, line, name, "malformed", detail=detail))

    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if text.startswith("/>", cursor):
            return attributes, cursor + 2
        if cursor < len(text) and text[cursor] == ">":
            return attributes, cursor + 1
        if cursor >= len(text):
            break
        if text[cursor] == "{":
            end = _skip_expression(text, cursor)
            if end is None:
                if saw_link:
                    malformed("jsx", tag_line, "unbalanced JSX expression in opening tag")
                return attributes, len(text)
            cursor = end
            continue
        if text[cursor] not in ATTRIBUTE_NAME_CHARS:
            # A nested '<' cannot occur in an opening tag. Stop here rather
            # than accidentally treating the following child tag as attrs.
            if saw_link:
                malformed("jsx", tag_line, "opening tag has no closing '>'")
            return attributes, cursor + 1

        name_start = cursor
        while cursor < len(text) and text[cursor] in ATTRIBUTE_NAME_CHARS:
            cursor += 1
        name = text[name_start:cursor]
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        line = _line_number(text, name_start)
        if cursor >= len(text) or text[cursor] != "=":
            if name in LINK_ATTRIBUTE_NAMES:
                malformed(name, line, "attribute has no assigned value")
            continue

        cursor += 1
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            if name in LINK_ATTRIBUTE_NAMES:
                malformed(name, line, "attribute ends after '='")
            break
        if text[cursor] in "'\"":
            value_start = cursor + 1
            end = _skip_quoted(text, cursor)
            if end is None:
                if name in LINK_ATTRIBUTE_NAMES:
                    malformed(name, line, "unterminated quoted value")
                return attributes, len(text)
            if name in LINK_ATTRIBUTE_NAMES:
                saw_link = True
                attributes.append(LinkAttribute(path, line, name, "literal", value=text[value_start:end - 1]))
            cursor = end
            continue
        if text[cursor] == "{":
            expression_start = cursor + 1
            end = _skip_expression(text, cursor)
            if end is None:
                if name in LINK_ATTRIBUTE_NAMES:
                    malformed(name, line, "unbalanced JSX expression")
                return attributes, len(text)
            if name in LINK_ATTRIBUTE_NAMES:
                expression = text[expression_start:end - 1]
                if not expression.strip():
                    malformed(name, line, "empty JSX expression")
                else:
                    saw_link = True
                    literal = _literal_expression_value(expression)
                    if literal is None:
                        attributes.append(LinkAttribute(path, line, name, "dynamic",
                                                        detail="balanced nonempty JSX expression"))
                    else:
                        attributes.append(LinkAttribute(path, line, name, "literal", value=literal))
            cursor = end
            continue
        if name in LINK_ATTRIBUTE_NAMES:
            malformed(name, line, "value must be quoted or a nonempty JSX expression")
        while cursor < len(text) and not text[cursor].isspace() and text[cursor] not in ">":
            cursor += 1

    if saw_link:
        malformed("jsx", tag_line, "opening tag has no closing '>'")
    return attributes, len(text)


def scan_jsx_link_attributes(text: str, path: Path) -> list[LinkAttribute]:
    """Classify every href/to on JSX opening tags in one .tsx/.jsx source.

    Closed-world policy: quoted values (single or double) and ``{\"literal\"}``
    are literals; balanced non-literal ``{...}`` values are explicitly reported
    as dynamic; an empty, bare, or unclosed value is malformed and fails.
    """
    attributes: list[LinkAttribute] = []
    index = 0
    jsx_depth = 0
    while index < len(text):
        in_jsx_text = jsx_depth > 0
        # In executable JS/TS code, a JSX-looking snippet in a string or
        # comment must not contribute to (or poison) the population. In JSX
        # text those same characters are prose (e.g. `region's storage`) and
        # must not switch the lexer into a fake JS-string state.
        if not in_jsx_text and text[index] in "'\"`":
            end = _skip_quoted(text, index)
            index = len(text) if end is None else end
            continue
        if not in_jsx_text and text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline == -1 else newline + 1
            continue
        if not in_jsx_text and text.startswith("/*", index):
            end_comment = text.find("*/", index + 2)
            index = len(text) if end_comment == -1 else end_comment + 2
            continue
        if in_jsx_text and text.startswith("{/*", index):
            end_comment = text.find("*/}", index + 3)
            index = len(text) if end_comment == -1 else end_comment + 3
            continue
        if in_jsx_text and text.startswith("</", index):
            close = text.find(">", index + 2)
            if close == -1:
                # No link can be safely reported past a syntactically open
                # closing tag; leave the compiler to diagnose the unrelated
                # JSX error rather than inventing an attribute population.
                break
            jsx_depth -= 1
            index = close + 1
            continue
        if text[index] != "<" or index + 1 >= len(text) or not (
            text[index + 1].isalpha() or text[index + 1] == "_"
        ):
            index += 1
            continue
        # `Array<Foo>` / `value<T>` is TypeScript generic syntax, not JSX. A
        # tag may follow punctuation/whitespace/`return`, but not an identifier
        # character, dot, or closing bracket immediately before '<'.
        if not in_jsx_text and index and (text[index - 1].isalnum() or text[index - 1] in "_.$])"):
            index += 1
            continue
        parsed, next_index = _parse_jsx_opening_tag(text, index, path)
        attributes.extend(parsed)
        if next_index <= len(text) and text[max(index, next_index - 2):next_index] != "/>":
            jsx_depth += 1
        index = max(next_index, index + 1)
    return attributes


def collect_hrefs(verbose: bool) -> list[LinkAttribute]:
    global SCANNED_FILE_COUNT
    found: list[LinkAttribute] = []
    if not require_dir(SCAN_DIR, "scan"):
        return found
    files = sorted(p for p in SCAN_DIR.rglob("*") if p.suffix in SCAN_EXTS and p.is_file())
    if not files:
        fail("scan", f"glob matched ZERO {SCAN_EXTS} files under {SCAN_DIR}")
        return found
    SCANNED_FILE_COUNT = len(files)
    for path in files:
        try:
            found.extend(scan_jsx_link_attributes(path.read_text(encoding="utf-8"), path))
        except OSError as exc:
            fail("scan", f"{path}: unreadable ({exc})")
    if not found:
        fail("scan", f"ZERO href=/to= attributes found across {len(files)} files under {SCAN_DIR}")
    for attribute in (item for item in found if item.kind == "malformed"):
        fail(
            "jsx",
            f"{attribute.path.relative_to(REPO_ROOT)}:{attribute.line}: malformed {attribute.name}= "
            f"({attribute.detail})",
        )
    if verbose:
        literals = sum(attribute.kind == "literal" for attribute in found)
        dynamics = [attribute for attribute in found if attribute.kind == "dynamic"]
        print(
            f"  scan: {literals} literal + {len(dynamics)} dynamic-classified href/to attributes "
            f"across {len(files)} tsx/jsx files"
        )
        if dynamics:
            print("  dynamic policy: expressions below are counted, but not route-resolved by this static gate")
            for attribute in dynamics:
                print(
                    f"    {attribute.path.relative_to(REPO_ROOT)}:{attribute.line}: "
                    f"{attribute.name}={{{attribute.detail}}}"
                )
    return found


def is_internal(href: str) -> bool:
    if not href:
        return False
    lowered = href.lower()
    if lowered.startswith(("http://", "https://", "mailto:", "tel:", "//", "#", "data:")):
        return False
    return href.startswith("/")


def enforce_population_floor(
    *, scanned_files: int, literals: int, dynamics: int, internal: int
) -> None:
    """Fail if the live population shrinks below B-168's measured baseline."""
    floors = (
        ("tsx/jsx files scanned", scanned_files, MIN_SCANNED_FILE_COUNT),
        ("literal href/to attributes", literals, MIN_LITERAL_ATTRIBUTE_COUNT),
        ("dynamic-classified href/to attributes", dynamics, MIN_DYNAMIC_ATTRIBUTE_COUNT),
        ("internal site-root href/to literals", internal, MIN_INTERNAL_HREF_COUNT),
    )
    for label, actual, minimum in floors:
        if actual < minimum:
            fail(
                "population",
                f"{label} fell to {actual}, below the measured B-168 floor {minimum}; "
                "the gate may have stopped seeing live source",
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    # Unit tests invoke main repeatedly against temporary source trees.
    FAILURES.clear()
    print("docs React-page internal-link gate")
    base_url = assert_config(args.verbose)

    doc_routes = collect_doc_routes(DOCS_DIR, DOCS_ROUTE_BASE, "docs", args.verbose)
    blog_routes = collect_doc_routes(BLOG_DIR, BLOG_ROUTE_BASE, "blog", args.verbose)
    blog_routes |= {normalize(r) for r in BLOG_GENERATED_ROUTES}
    page_routes = collect_page_routes(args.verbose)
    static_routes = collect_static_routes(args.verbose)
    redirect_routes = collect_redirect_sources(args.verbose)

    known = doc_routes | blog_routes | page_routes | static_routes | redirect_routes
    if not known:
        fail("destinations", "ZERO published destinations were derived -- gate would be vacuous")

    attributes = collect_hrefs(args.verbose)
    literals = [attribute for attribute in attributes if attribute.kind == "literal"]
    dynamics = [attribute for attribute in attributes if attribute.kind == "dynamic"]
    empty = [attribute for attribute in literals if attribute.value == ""]
    for attribute in empty:
        fail(
            "jsx",
            f"{attribute.path.relative_to(REPO_ROOT)}:{attribute.line}: empty {attribute.name}= is not a route",
        )
    unsupported_relative = [
        attribute
        for attribute in literals
        if attribute.value and not is_internal(attribute.value)
        and not attribute.value.lower().startswith(("http://", "https://", "mailto:", "tel:", "//", "#", "data:"))
    ]
    for attribute in unsupported_relative:
        fail(
            "jsx",
            f"{attribute.path.relative_to(REPO_ROOT)}:{attribute.line}: {attribute.name}={attribute.value!r} "
            "is a relative/unsupported literal; use a site-root route, an allowed external scheme, or a "
            "documented dynamic expression",
        )
    internal = [attribute for attribute in literals if attribute.value and is_internal(attribute.value)]
    if literals and not internal:
        fail("scan", f"{len(literals)} literal href/to attributes found but ZERO are internal '/'-rooted -- gate would be vacuous")
    enforce_population_floor(
        scanned_files=SCANNED_FILE_COUNT,
        literals=len(literals),
        dynamics=len(dynamics),
        internal=len(internal),
    )

    if FAILURES:
        print()
        for line in FAILURES:
            print(line, file=sys.stderr)
        print(
            "\nThe gate could not establish its inputs. This is a FAILURE, not a pass.",
            file=sys.stderr,
        )
        return 1

    base_prefix = normalize(base_url) if base_url and base_url != "/" else ""
    broken: list[tuple[Path, int, str]] = []
    for attribute in internal:
        path, lineno, href = attribute.path, attribute.line, attribute.value
        assert href is not None
        target = href.split("#", 1)[0].split("?", 1)[0]
        if not target:
            continue
        target = normalize(target)
        candidates = {target}
        if base_prefix and target.startswith(base_prefix + "/"):
            candidates.add(normalize(target[len(base_prefix):]))
        if not (candidates & known):
            broken.append((path, lineno, href))

    print()
    print(
        f"POPULATION: {len(internal)} internal hrefs "
        f"({len(literals)} literal href/to attributes; {len(dynamics)} dynamic-classified (not route-resolved) "
        f"in {len({attribute.path for attribute in attributes})} of {SCANNED_FILE_COUNT} scanned tsx/jsx files "
        f"under apps/docs/src), "
        f"resolved against {len(known)} published destinations "
        f"(docs={len(doc_routes)}, blog={len(blog_routes)}, pages={len(page_routes)}, "
        f"static={len(static_routes)}, redirects={len(redirect_routes)})."
    )
    print(
        "FLOOR: "
        f"files>={MIN_SCANNED_FILE_COUNT}, literals>={MIN_LITERAL_ATTRIBUTE_COUNT}, "
        f"dynamic>={MIN_DYNAMIC_ATTRIBUTE_COUNT}, internal>={MIN_INTERNAL_HREF_COUNT}."
    )

    if broken:
        print()
        print(f"BROKEN: {len(broken)} internal href(s) resolve to no published destination:", file=sys.stderr)
        for path, lineno, href in broken:
            print(f"  {path.relative_to(REPO_ROOT)}:{lineno}: dead link -> {href}", file=sys.stderr)
        print(
            "\nEach href above must either point at a published (non-draft) route or be "
            "replaced with prose. Note: a page that exists on disk but is `draft: true`, "
            "or that declares a different `slug:` in its front-matter, is NOT published.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: all {len(internal)} internal hrefs resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
