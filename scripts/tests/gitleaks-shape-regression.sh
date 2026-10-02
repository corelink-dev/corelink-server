#!/usr/bin/env bash
# Executable regression for the custom raw-hex gitleaks rule, and for the
# generic-api-key allowlist that admits the B-156 published-claims digests.
#
# This invokes the pinned scanner supplied by the workflow.  It deliberately
# exercises every path class in the rule, legacy and opaque names, boundary
# values, and a rule-removal mutation; then each conjunct of the digest
# allowlist, with one mutation per conjunct.  A missing scanner/config or
# malformed mutation is an error; it must never degrade to a green skip.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="${repo_root}/.gitleaks.toml"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/corelink-gitleaks-shape.XXXXXX")"
trap 'rm -rf -- "$tmpdir"' EXIT

command -v gitleaks >/dev/null || { echo "gitleaks is required" >&2; exit 2; }
[[ -f "$config" ]] || { echo "missing .gitleaks.toml" >&2; exit 2; }

probe="6b73d8c0f5a19e2b4d6087c3a9f1b5e7c2d4a6f8091b3d5e7f9a0c2e4b6d8f01"

run_scan() {
  local source="$1" config_path="$2" expected="$3" label="$4" output status
  output="${tmpdir}/${label}.out"
  set +e
  gitleaks detect --no-git --source "$source" --config "$config_path" \
    --redact --no-banner --exit-code 1 >"$output" 2>&1
  status=$?
  set -e
  if [[ "$status" != "$expected" ]]; then
    echo "${label}: expected scanner exit ${expected}, got ${status}" >&2
    sed -n '1,80p' "$output" >&2
    exit 1
  fi
}

positive_root="${tmpdir}/positive"
mkdir -p "$positive_root/.github/workflows" "$positive_root/reports/audits" \
  "$positive_root/tests" "$positive_root/public"
printf 'opaque_material = "%s"\n' "$probe" >"${positive_root}/wrangler.toml"
printf '{"opaque material":"%s"}\n' "$probe" >"${positive_root}/wrangler.json"
printf '{"opaque material":"%s"}\n' "$probe" >"${positive_root}/wrangler.jsonc"
printf 'opaque_material="%s"\n' "$probe" >"${positive_root}/.env.production"
printf 'opaque_material = "%s"\n' "$probe" >"${positive_root}/deploy-secrets.conf"
printf 'opaque_material = "%s"\n' "$probe" >"${positive_root}/deploy-credentials.toml"
printf 'opaque_material: %s\n' "$probe" >"${positive_root}/deploy-secrets.yaml"
printf 'name: fixture\non:\n  workflow_dispatch:\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    env:\n      opaque_material: %s\n' \
  "$probe" >"${positive_root}/.github/workflows/secrets-fixture.yml"
printf 'opaque_material = "%s"\n' "$probe" >"${positive_root}/reports/audits/incident.md"
printf 'CORELINK_INTERNAL_AUTH_KEY = "%s"\nPAT_SIGNING_KEY_NEXT = "%s"\n' \
  "$probe" "$probe" >"${positive_root}/legacy.toml"

negative_root="${tmpdir}/negative"
mkdir -p "$negative_root/reports" "$negative_root/tests"
printf 'sha256: %s\nchecksum: %s\ndigest: %s\n' "$probe" "$probe" "$probe" \
  >"${negative_root}/reports/public-digests.md"
printf 'opaque_material = "%s"\n' "$probe" >"${negative_root}/tests/fixture.toml"
short32="${probe:0:32}"
short63="${probe:0:63}"
long65="${probe}a"
hyphenated="${probe:0:32}-${probe:32}"
printf 'short32 = "%s"\nshort63 = "%s"\nlong65 = "%s"\nprefixed = "0x%s"\nhyphenated = "%s"\n' \
  "$short32" "$short63" "$long65" "$probe" "$hyphenated" \
  >"${negative_root}/wrangler.toml"

run_scan "$positive_root" "$config" 1 "all-deployable-path-classes"
run_scan "$negative_root/reports" "$config" 0 "public-audit-outside-rule"
run_scan "$negative_root/tests" "$config" 0 "versioned-fixture-allowlist"
# Boundary values are not the continuous bare 64-hex assignment shape.
run_scan "$negative_root" "$config" 0 "shape-boundaries"

# The custom rule is the only detector expected to catch this opaque value.
# Removing it must make the positive fixture green, proving the regression has
# a real tooth and is not merely exercising a default rule.
mutated="${tmpdir}/without-shape-rule.toml"
python3 - "$config" "$mutated" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("# Raw-hex secret material is identified")
end = source.index("# ── Upstream rules re-declared", start)
pathlib.Path(sys.argv[2]).write_text(source[:start] + source[end:], encoding="utf-8")
PY
grep -q 'corelink-secret-shaped-hex' "$config"
! grep -q 'corelink-secret-shaped-hex' "$mutated"
run_scan "$positive_root/wrangler.toml" "$mutated" 0 "removed-rule-mutation"

# An invalid replacement must fail closed during scanner configuration parsing.
broken="${tmpdir}/broken.toml"
python3 - "$config" "$broken" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index('id = "corelink-secret-shaped-hex"')
prefix, block = source[:start], source[start:]
mutated, count = re.subn(r"(?m)^regex = .*$", "regex = '''([a-'''", block, count=1)
if count != 1 or mutated == block:
    raise SystemExit("invalid-regex mutation was not applied")
pathlib.Path(sys.argv[2]).write_text(prefix + mutated, encoding="utf-8")
PY
run_scan "$positive_root" "$broken" 2 "invalid-regex-mutation"

# ── B-156 published-claims digest allowlist (generic-api-key) ────────────────
# That allowlist is keyed on a REPO-RELATIVE path, so these cells scan with a
# relative source from inside each fixture root, as the CI range scan does at
# the repo root. With an absolute source `^scripts/...` can never match and a
# cell would pass on the line shape alone. Every scan must report EXACTLY the
# expected number of findings, all from generic-api-key: another rule firing,
# or a line that never tripped the heuristic, cannot stand in for this one.
run_rel_scan() {
  local root="$1" config_path="$2" expected="$3" label="$4" report status
  report="${tmpdir}/${label}.json"
  set +e
  (cd "$root" && gitleaks detect --no-git --source . --config "$config_path" \
    --redact --no-banner --exit-code 1 --report-format json \
    --report-path "$report") >"${tmpdir}/${label}.out" 2>&1
  status=$?
  set -e
  if ! python3 - "$report" "$expected" "$label" "$status" <<'PY'
import json
import sys

report, expected, label, status = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
if status not in (0, 1):
    raise SystemExit(f"{label}: scanner exit {status} is neither clean nor findings")
findings = json.load(open(report, encoding="utf-8"))
rules = sorted({finding["RuleID"] for finding in findings})
count_ok = len(findings) > 0 if expected == "some" else len(findings) == int(expected)
if not count_ok or (findings and rules != ["generic-api-key"]):
    raise SystemExit(
        f"{label}: expected {expected} generic-api-key finding(s), got {len(findings)} {rules}"
    )
if (status == 1) != bool(findings):
    raise SystemExit(f"{label}: scanner exit {status} disagrees with {len(findings)} finding(s)")
PY
  then
    sed -n '1,80p' "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

claims_rel="scripts/published_claims_inventory.json"
# README.md carries no keyword; the other three keys each trip the heuristic,
# exactly as `apps/docs/tests/reapi-gen.test.ts` did on PR #2872. Script
# extensions are used on purpose: upstream already lets a keyword key ending
# `.md`/`.mdx`/`.html` through (measured on 8.30.1), so such a cell would be
# green without this allowlist.
write_claims_digests() {
  mkdir -p "$(dirname "$1")"
  printf '{\n  "population": {\n    "file_hashes": {\n      "README.md": "%s",\n      "apps/docs/tests/reapi-gen.test.ts": "%s",\n      "legal/api-terms.js": "%s",\n      "marketing/launch/token-pricing.tsx": "%s"\n    }\n  }\n}\n' \
    "$probe" "$probe" "$probe" "$probe" >"$1"
}
# Derived at run time so no credential-shaped literal is committed here.
opaque_value="$(printf '%s' "${probe:0:40}" | tr 'abcdef0123' 'QwErTyUiOp')"
upper_probe="$(printf '%s' "$probe" | tr 'a-f' 'A-F')"

claims_root="${tmpdir}/claims"
write_claims_digests "${claims_root}/digest/${claims_rel}"
write_claims_digests "${claims_root}/elsewhere/scripts/other_inventory.json"
write_claims_digests "${claims_root}/nested/vendor/${claims_rel}"
mkdir -p "${claims_root}/real/scripts"
cp "${repo_root}/${claims_rel}" "${claims_root}/real/${claims_rel}"
mkdir -p "${claims_root}/real-elsewhere/scripts"
cp "${repo_root}/${claims_rel}" "${claims_root}/real-elsewhere/scripts/other_inventory.json"
# Each line misses exactly one conjunct of the line shape: a non-path key, a
# root outside the census, an uppercase value, a character outside the key
# alphabet, an extension outside the census.
mkdir -p "${claims_root}/reject/scripts"
printf '{\n  "api_key": "%s",\n  "scripts/deploy-api.ts": "%s",\n  "apps/docs/api.ts": "%s",\n  "apps/docs/api notes.ts": "%s",\n  "apps/docs/api.py": "%s"\n}\n' \
  "$opaque_value" "$probe" "$upper_probe" "$probe" "$probe" \
  >"${claims_root}/reject/${claims_rel}"

run_rel_scan "${claims_root}/elsewhere" "$config" 3 "claims-digest-lines-trip-elsewhere"
run_rel_scan "${claims_root}/nested" "$config" 3 "claims-path-anchored-at-root"
run_rel_scan "${claims_root}/digest" "$config" 0 "claims-digest-lines-allowlisted"
run_rel_scan "${claims_root}/real-elsewhere" "$config" some "claims-real-inventory-trips-elsewhere"
run_rel_scan "${claims_root}/real" "$config" 0 "claims-real-inventory-allowlisted"
run_rel_scan "${claims_root}/reject" "$config" 5 "claims-non-digest-lines-still-fire"

# Three content mutations of that one block, each asserted to apply exactly once.
claims_mutant() {
  python3 - "$config" "$1" "$2" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
marker = "description = \"B-156's generated published-claims file digests"
if source.count(marker) != 1:
    raise SystemExit("B-156 allowlist marker must occur exactly once")
start = source.rindex("[[rules.allowlists]]", 0, source.index(marker))
end = source.index("\n[", start + 1) + 1
block = source[start:end]
kind = sys.argv[3]
if kind == "drop-and":
    needle, replacement = 'condition = "AND"\n', ""
elif kind == "unanchor-path":
    needle = "paths = ['''^scripts/published_claims_inventory\\.json$''']"
    replacement = needle.replace("'''^", "'''")
elif kind == "remove-block":
    needle, replacement = block, ""
else:
    raise SystemExit(f"unknown mutation {kind}")
if block.count(needle) != 1:
    raise SystemExit(f"{kind}: needle matched {block.count(needle)} times, expected 1")
mutated = source[:start] + block.replace(needle, replacement) + source[end:]
if mutated == source:
    raise SystemExit(f"{kind}: mutation did not change the config")
pathlib.Path(sys.argv[2]).write_text(mutated, encoding="utf-8")
PY
}
claims_mutant "${tmpdir}/claims-or.toml" drop-and
claims_mutant "${tmpdir}/claims-unanchored.toml" unanchor-path
claims_mutant "${tmpdir}/claims-removed.toml" remove-block
# Default OR: the path alone mutes every line of the reject fixture.
run_rel_scan "${claims_root}/reject" "${tmpdir}/claims-or.toml" 0 "claims-or-mutation"
# Unanchored: a same-named file in a subtree is admitted.
run_rel_scan "${claims_root}/nested" "${tmpdir}/claims-unanchored.toml" 0 "claims-unanchored-mutation"
# Removed: the generated digests fire again.
run_rel_scan "${claims_root}/digest" "${tmpdir}/claims-removed.toml" 3 "claims-removed-mutation"

echo "gitleaks shape regression: PASS (path classes, opaque/legacy names, boundaries, allowlist, published-claims digests, fail-closed mutations)"
