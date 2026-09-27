from pathlib import Path
import hashlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_backlog_wp_ledger as ledger

from verify_backlog_wp_ledger import (
    LedgerError,
    compare,
    contract_section,
    declared_wp_names,
    parse_catalog,
    validate_contract_section,
    validate_predecessors,
    parse_structured_allowlist,
    validate_structured_allowlist,
    parse_workflow_ownership,
    validate_workflow_ownership,
    validate_workflow_population,
    parse_ledger_state,
    load_snapshot_manifest,
    validate_snapshot_manifest,
    validate_ledger_state,
    parse_wp_dependency_order,
    validate_wp_dependency_order,
)


def test_catalog_requires_one_nonempty_parseable_fence():
    with pytest.raises(LedgerError, match="exactly one"):
        parse_catalog("no fence", "x.md", 1, 45)
    with pytest.raises(LedgerError, match="empty"):
        parse_catalog("```wp-coverage\n```\n", "x.md", 1, 45)
    with pytest.raises(LedgerError, match="unparseable"):
        parse_catalog("```wp-coverage\nB-008\n```\n", "x.md", 1, 45)
    with pytest.raises(LedgerError, match="nested"):
        parse_catalog(
            "````markdown\n```wp-coverage\nB-008 WP-B008\n```\n````\n",
            "x.md",
            1,
            45,
        )
    with pytest.raises(LedgerError, match="closing must be exactly"):
        parse_catalog("```wp-coverage\nB-008 WP-B008\n``` suffix\n", "x.md", 1, 45)


def test_catalog_rejects_noncanonical_and_out_of_range_ids():
    with pytest.raises(LedgerError, match="non-canonical"):
        parse_catalog("```wp-coverage\nB-08 WP-B008\n```\n", "x.md", 1, 45)
    with pytest.raises(LedgerError, match="outside"):
        parse_catalog("```wp-coverage\nB-046 WP-B046\n```\n", "x.md", 1, 45)


def test_fence_scanner_handles_tildes_lengths_and_delimiter_mismatches():
    assert parse_catalog(
        "~~~~wp-coverage\nB-008 WP-B008\n~~~~~\n", "x.md", 1, 45
    ) == [("B-008", "WP-B008")]
    with pytest.raises(LedgerError, match="unterminated"):
        parse_catalog("~~~~wp-coverage\nB-008 WP-B008\n~~~\n", "x.md", 1, 45)
    with pytest.raises(LedgerError, match="unterminated"):
        parse_catalog("```wp-coverage\nB-008 WP-B008\n~~~\n", "x.md", 1, 45)
    with pytest.raises(LedgerError, match="nested"):
        parse_catalog(
            "~~~markdown\n```wp-coverage\nB-008 WP-B008\n```\n~~~\n",
            "x.md",
            1,
            45,
        )


def test_fence_scanner_ignores_fake_wp_headings_and_fields_inside_code():
    text = """
```markdown
## WP-FAKE
**Scope / allowlist.** fake
**Read first.** fake
**Decided change.** fake
**Invariants.** fake
```
~~~text
### WP-ALSO-FAKE
**Completeness.** fake
**Definition of Done.** fake
~~~
## WP-REAL — real contract
**Scope / allowlist.** real only
"""
    assert declared_wp_names(text, "fixture.md") == {"WP-REAL"}
    section = contract_section(text, "WP-REAL", "fixture.md")
    assert "WP-FAKE" not in section
    with pytest.raises(LedgerError, match="missing contract fields"):
        validate_contract_section(section, "WP-REAL", "fixture.md")


def test_compare_accepts_exact_partition():
    compare(
        {"B-008", "B-012"},
        [("B-008", "WP-B008", "a.md"), ("B-012", "WP-B012", "a.md")],
    )


def test_compare_rejects_phantom_wp_name():
    with pytest.raises(LedgerError, match="phantom WP names"):
        compare(
            {"B-008"},
            [("B-008", "WP-NOT-DECLARED", "a.md")],
            {"WP-B008"},
        )


def test_contract_requires_all_execution_fields():
    complete = """
    **Scope / allowlist.** `scripts/example.py` only.
    **Read first.** `docs/example.md`.
    **Decided change.** Apply the specified repair.
    **Non-goals.** No unrelated changes.
    **Invariants.** Fail closed.
    **Completeness.** Empty input is indeterminate.
    **Definition of Done.** Behavior test and review.
    **Quality.** Mutation and lint are green.
    **Predecessor / integration.** None; integrate after review.
    **Return card.** Base, head, paths, results, and residual.
    """
    validate_contract_section(complete, "WP-EXAMPLE", "fixture.md")
    for field, pattern in (
        ("Read first", r"\*\*Read first\.\*\*[^\n]*\n"),
        ("Decided change", r"\*\*Decided change\.\*\*[^\n]*\n"),
        ("Non-goals", r"\*\*Non-goals\.\*\*[^\n]*\n"),
        ("Invariants", r"\*\*Invariants\.\*\*[^\n]*\n"),
        ("Completeness", r"\*\*Completeness\.\*\*[^\n]*\n"),
        ("Definition of Done", r"\*\*Definition of Done\.\*\*[^\n]*\n"),
        ("Quality", r"\*\*Quality\.\*\*[^\n]*\n"),
        ("Predecessor / integration", r"\*\*Predecessor / integration\.\*\*[^\n]*\n"),
        ("Return card", r"\*\*Return card\.\*\*[^\n]*\n"),
    ):
        import re

        broken = re.sub(pattern, "", complete, count=1)
        with pytest.raises(LedgerError, match="missing contract fields"):
            validate_contract_section(broken, "WP-EXAMPLE", "fixture.md")


@pytest.mark.parametrize(
    ("assignments", "message"),
    [
        ([("B-008", "WP-A", "a.md")], "missing open IDs"),
        (
            [
                ("B-008", "WP-A", "a.md"),
                ("B-008", "WP-B", "b.md"),
                ("B-012", "WP-C", "a.md"),
            ],
            "duplicate assignments",
        ),
        (
            [
                ("B-008", "WP-A", "a.md"),
                ("B-012", "WP-B", "a.md"),
                ("B-013", "WP-C", "a.md"),
            ],
            "assigned non-open IDs",
        ),
    ],
)
def test_compare_rejects_incomplete_duplicate_or_terminal(assignments, message):
    with pytest.raises(LedgerError, match=message):
        compare({"B-008", "B-012"}, assignments)


def test_compare_rejects_terminal_done_or_parked_redispatch():
    with pytest.raises(LedgerError, match="assigned non-open IDs"):
        compare(
            {"B-008"},
            [("B-008", "WP-A", "a.md"), ("B-168", "WP-B", "b.md")],
        )


def test_dependency_order_is_executable_and_rejects_cycle():
    valid = {"WP-140", "WP-146", "WP-148", "WP-150"}
    order = parse_wp_dependency_order(
        """```wp-dependency-order
WP-140 | none
WP-146 | none
WP-148 | WP-140,WP-146
WP-150 | WP-148
```""",
        "ledger.md",
    )
    required = {
        "WP-140": (),
        "WP-146": (),
        "WP-148": ("WP-140", "WP-146"),
        "WP-150": ("WP-148",),
    }
    validate_wp_dependency_order(order, valid, "ledger.md", required=required)
    with pytest.raises(LedgerError, match="cyclic"):
        validate_wp_dependency_order(
            [("WP-148", ("WP-150",)), ("WP-150", ("WP-148",))],
            valid,
            "ledger.md",
        )
    with pytest.raises(LedgerError, match="outside order"):
        validate_wp_dependency_order(
            [("WP-148", ("WP-140",))],
            valid,
            "ledger.md",
        )
    with pytest.raises(LedgerError, match="required executable order"):
        validate_wp_dependency_order(
            [
                ("WP-140", ()),
                ("WP-146", ()),
                ("WP-148", ("WP-146",)),
                ("WP-150", ("WP-148",)),
            ],
            valid,
            "ledger.md",
            required=required,
        )


def test_ledger_state_rejects_stale_base_and_population():
    state = parse_ledger_state(
        """```ledger-state
base-ref: 8a8c19d06f398cbec6e73eb95fd3ebcfb5ccbe94
base-sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
observed-at: 2026-09-06
item-count: 168
open-count: 107
done-count: 60
parked-count: 1
catalog-counts: B001-B045=8,B046-B090=31,B091-B130=36,B131-B167=32
```""",
        "ledger.md",
    )
    kwargs = dict(
        source="ledger.md",
        item_count=168,
        status_counts={"open": 107, "done": 60, "parked": 1},
        catalog_counts={"B001-B045": 8, "B046-B090": 31, "B091-B130": 36, "B131-B167": 32},
        expected_base_sha="a" * 40,
    )
    validate_ledger_state(state, **kwargs)
    stale_ref = dict(state, **{"base-ref": "origin/main"})
    with pytest.raises(LedgerError, match="ledger base-ref must be"):
        parse_ledger_state(
            "```ledger-state\n"
            + "\n".join(f"{key}: {value}" for key, value in stale_ref.items())
            + "\n```\n",
            "ledger.md",
        )
    stale_base = dict(state, **{"base-sha": "b" * 40})
    with pytest.raises(LedgerError, match="stale ledger base-sha"):
        validate_ledger_state(stale_base, **kwargs)
    stale_population = dict(state, **{"open-count": "108"})
    with pytest.raises(LedgerError, match="stale ledger open-count"):
        validate_ledger_state(stale_population, **kwargs)


def test_live_ledger_uses_immutable_candidate_anchor():
    assert ledger.LEDGER_BASE_REF == "8a8c19d06f398cbec6e73eb95fd3ebcfb5ccbe94"
    assert ledger.LEDGER_BASE_SHA == "8a8c19d06f398cbec6e73eb95fd3ebcfb5ccbe94"
    assert ledger.POSTMERGE_BASE_SHA == "6be19a2e525dad045ad8404d722905afde7ad7bd"


def _committed_preimage_file(path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{ledger.POSTMERGE_BASE_SHA}:{path}"], cwd=ledger.REPO_ROOT,
        check=True, capture_output=True,
    ).stdout


def _live_snapshot_manifest():
    state = parse_ledger_state(ledger.LEDGER_PATH.read_text(), "live-ledger.md")
    return (
        ledger.load_postmerge_snapshot_manifest()
        if state["base-ref"] == ledger.POSTMERGE_BASE_SHA
        else load_snapshot_manifest()
    )


def test_postmerge_snapshot_accepts_versioned_b373_only_transition():
    if not ledger.POSTMERGE_SNAPSHOT_PATH.is_file():
        pytest.skip("versioned post-merge data is not present in the candidate tree")
    manifest = ledger.load_postmerge_snapshot_manifest()
    backlog = ledger.REPO_ROOT.joinpath("BACKLOG.md").read_text()
    state = parse_ledger_state(
        ledger.LEDGER_PATH.read_text(),
        "postmerge-ledger.md",
    )
    validate_snapshot_manifest(manifest, backlog, state, source="postmerge-ledger.md")
    validate_ledger_state(
        state, source="postmerge-ledger.md", item_count=373,
        status_counts={"done": 328, "open": 13, "parked": 32},
        catalog_counts={"B001-B045": 4, "B046-B090": 3, "B091-B130": 2, "B131-B373": 4},
        expected_base_sha=ledger.POSTMERGE_BASE_SHA,
    )
    ledger.validate_git_anchor(
        ledger.REPO_ROOT, source="postmerge-ledger.md",
        base_ref=ledger.POSTMERGE_BASE_SHA, base_sha=ledger.POSTMERGE_BASE_SHA,
    )


def test_postmerge_snapshot_rejects_modified_preimage_and_manifest(monkeypatch, tmp_path):
    altered_prior = tmp_path / "prior.json"
    altered_prior.write_bytes(ledger.SNAPSHOT_PATH.read_bytes() + b"\n")
    monkeypatch.setattr(ledger, "SNAPSHOT_PATH", altered_prior)
    with pytest.raises(LedgerError, match="snapshot manifest digest drifted"):
        ledger.load_postmerge_snapshot_manifest()
    monkeypatch.undo()
    altered_post = tmp_path / "post.json"
    altered_post.write_bytes(b"not the pinned post-merge snapshot\n")
    monkeypatch.setattr(ledger, "POSTMERGE_SNAPSHOT_PATH", altered_post)
    with pytest.raises(LedgerError, match="snapshot manifest digest drifted"):
        ledger.load_postmerge_snapshot_manifest()


def test_snapshot_rejects_crossed_pre_and_postmerge_states():
    if not ledger.POSTMERGE_SNAPSHOT_PATH.is_file():
        pytest.skip("versioned post-merge data is not present in the candidate tree")
    post = ledger.load_postmerge_snapshot_manifest()
    old = load_snapshot_manifest()
    old_backlog = _committed_preimage_file("BACKLOG.md").decode()
    old_state = parse_ledger_state(
        _committed_preimage_file("docs/campaigns/remediation/BACKLOG-WP-LEDGER.md").decode(),
        "old-ledger.md",
    )
    post_backlog = ledger.REPO_ROOT.joinpath("BACKLOG.md").read_text()
    post_state = parse_ledger_state(
        ledger.LEDGER_PATH.read_text(),
        "post-ledger.md",
    )
    with pytest.raises(LedgerError, match="outside the immutable snapshot"):
        validate_snapshot_manifest(old, post_backlog, post_state, source="crossed")
    with pytest.raises(LedgerError, match="outside the immutable snapshot"):
        validate_snapshot_manifest(post, old_backlog, old_state, source="crossed")


def test_current_candidate_main_still_passes():
    assert ledger.main() == 0


def test_current_candidate_tree_has_ancestry_anchor():
    ledger.validate_git_anchor(ledger.REPO_ROOT, source="current D03 tree")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _synthetic_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "squash-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "ledger tests")
    (repo / "state.txt").write_text("base\n")
    _git(repo, "add", "state.txt")
    _git(repo, "commit", "--quiet", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "branch", "-M", "main")
    (repo / "state.txt").write_text("squashed D03 tree\n")
    _git(repo, "commit", "--quiet", "-am", "squashed D03 tree")
    return repo, base


def test_git_anchor_accepts_squash_style_descendant_without_d03_sha_or_ref(tmp_path):
    repo, base = _synthetic_repo(tmp_path)
    ledger.validate_git_anchor(
        repo,
        source="fixture",
        base_ref="main",
        base_sha=base,
    )


def test_git_anchor_rejects_wrong_ref_and_unrelated_head(tmp_path):
    repo, base = _synthetic_repo(tmp_path)
    _git(repo, "checkout", "--quiet", "--orphan", "unrelated")
    (repo / "unrelated.txt").write_text("unrelated\n")
    _git(repo, "add", "unrelated.txt")
    _git(repo, "commit", "--quiet", "-m", "unrelated")
    with pytest.raises(LedgerError, match="base-ref"):
        ledger.validate_git_anchor(
            repo,
            source="fixture",
            base_ref="unrelated",
            base_sha=base,
            head_ref="main",
        )
    with pytest.raises(LedgerError, match="not an ancestor"):
        ledger.validate_git_anchor(
            repo,
            source="fixture",
            base_ref="main",
            base_sha=base,
            head_ref="HEAD",
        )


def test_main_rejects_tampered_base_sha_end_to_end(monkeypatch, tmp_path):
    source = ledger.LEDGER_PATH.read_text()
    state = parse_ledger_state(source, "live-ledger.md")
    tampered = source.replace(
        f"base-sha: {state['base-sha']}",
        "base-sha: 0000000000000000000000000000000000000000",
        1,
    )
    assert tampered != source
    path = tmp_path / "BACKLOG-WP-LEDGER.md"
    path.write_text(tampered)
    monkeypatch.setattr(ledger, "LEDGER_PATH", path)
    assert ledger.main() == 1


def test_snapshot_rejects_coordinated_open_item_closure_and_count_rewrite():
    backlog = ledger.REPO_ROOT.joinpath("BACKLOG.md").read_text()
    start = backlog.index("### B-008")
    end = backlog.index("### B-009", start)
    mutated_backlog = (
        backlog[:start]
        + backlog[start:end].replace("status: open", "status: done", 1)
        + backlog[end:]
    )
    ledger_text = ledger.LEDGER_PATH.read_text()
    live_state = parse_ledger_state(ledger_text, "live-ledger.md")
    open_count = int(live_state["open-count"])
    done_count = int(live_state["done-count"])
    mutated_ledger = ledger_text.replace(f"open-count: {open_count}", f"open-count: {open_count - 1}", 1)
    mutated_ledger = mutated_ledger.replace(f"done-count: {done_count}", f"done-count: {done_count + 1}", 1)
    mutated_ledger = mutated_ledger.replace("B001-B045=4", "B001-B045=3", 1)
    state = parse_ledger_state(mutated_ledger, "mutated-ledger.md")
    with pytest.raises(LedgerError, match="outside the immutable snapshot"):
        validate_snapshot_manifest(
            _live_snapshot_manifest(),
            mutated_backlog,
            state,
            source="mutated-ledger.md",
        )


def test_snapshot_rejects_ledger_count_rewrite_without_backlog_change():
    live_text = ledger.LEDGER_PATH.read_text()
    open_count = int(parse_ledger_state(live_text, "live-ledger.md")["open-count"])
    ledger_text = live_text.replace(f"open-count: {open_count}", f"open-count: {open_count - 1}", 1)
    assert ledger_text != live_text
    state = parse_ledger_state(ledger_text, "mutated-ledger.md")
    with pytest.raises(LedgerError, match="ledger open-count is outside"):
        validate_snapshot_manifest(
            _live_snapshot_manifest(),
            ledger.REPO_ROOT.joinpath("BACKLOG.md").read_text(),
            state,
            source="mutated-ledger.md",
        )


@pytest.mark.parametrize("missing", ["WP-140", "WP-146"])
def test_main_rejects_missing_ci_predecessor_end_to_end(monkeypatch, tmp_path, missing):
    source = ledger.LEDGER_PATH.read_text()
    remaining = "WP-146" if missing == "WP-140" else "WP-140"
    tampered = source.replace("WP-148 | WP-140,WP-146", f"WP-148 | {remaining}")
    path = tmp_path / "BACKLOG-WP-LEDGER.md"
    path.write_text(tampered)
    monkeypatch.setattr(ledger, "LEDGER_PATH", path)
    assert ledger.main() == 1


def test_predecessor_references_must_resolve_to_backlog_or_declared_wp():
    with pytest.raises(LedgerError, match="does not resolve"):
        validate_predecessors(
            "**Predecessor / integration.** after B-999 and WP-NOT-DECLARED.",
            "WP-B008",
            "fixture.md",
            {"B-008"},
            {"WP-B008"},
        )
    validate_predecessors(
        "**Predecessor / integration.** after B-008, WP-B008, and #1234.",
        "WP-B009",
        "fixture.md",
        {"B-008", "B-009"},
        {"WP-B008", "WP-B009"},
    )


def test_structured_allowlist_requires_explicit_path_order():
    valid = {"WP-A", "WP-B", "WP-C", "WP-X", "WP-Y"}
    with pytest.raises(LedgerError, match="exactly one initial owner"):
        validate_structured_allowlist(
            [("shared/file.py", "WP-A", "WP-X"), ("shared/file.py", "WP-B", "WP-Y")],
            valid,
        )
    validate_structured_allowlist(
        [("shared/file.py", "WP-A", "none"), ("shared/file.py", "WP-B", "WP-A")],
        valid,
    )
    with pytest.raises(LedgerError, match="multiple immediate successors"):
        validate_structured_allowlist(
            [
                ("shared/file.py", "WP-A", "none"),
                ("shared/file.py", "WP-B", "WP-A"),
                ("shared/file.py", "WP-C", "WP-A"),
            ],
            valid,
        )


def test_structured_allowlist_does_not_treat_read_first_as_editable():
    text = """
```wp-editable-allowlist
crates/corelink-container/src/routes/cas.rs | WP-A | none
```
**Read first.** `crates/corelink-container/src/routes/cas.rs`.
"""
    entries = parse_structured_allowlist(text, "fixture.md")
    assert entries == [("crates/corelink-container/src/routes/cas.rs", "WP-A", "none")]
    validate_structured_allowlist(entries, {"WP-A"})


def test_workflow_ownership_is_closed_and_wp150_is_read_only():
    valid = {"WP-A", "WP-150"}
    actual = {".github/workflows/a.yml", ".github/workflows/b.yml"}
    with pytest.raises(LedgerError, match="WP-150 cannot own"):
        validate_workflow_ownership(
            [(".github/workflows/a.yml", "WP-150", "owned"),
             (".github/workflows/b.yml", "LEAD-BLOCKED", "blocked")],
            valid,
            actual,
        )
    with pytest.raises(LedgerError, match="does not exist"):
        validate_workflow_ownership(
            [(".github/workflows/missing.yml", "LEAD-BLOCKED", "blocked")],
            valid,
            actual,
        )
    with pytest.raises(LedgerError, match="outside ownership map"):
        validate_workflow_ownership(
            [(".github/workflows/a.yml", "LEAD-BLOCKED", "blocked")],
            valid,
            actual,
        )
    with pytest.raises(LedgerError, match="duplicate workflow ownership path"):
        validate_workflow_ownership(
            [(".github/workflows/a.yml", "LEAD-BLOCKED", "blocked"),
             (".github/workflows/a.yml", "LEAD-BLOCKED", "blocked"),
             (".github/workflows/b.yml", "LEAD-BLOCKED", "blocked")],
            valid,
            actual,
        )


def test_current_workflow_population_is_closed_and_deterministic():
    root = Path(__file__).resolve().parents[1]
    relative = sorted(
        path for path in subprocess.check_output(
            ["git", "ls-files", "--", ".github/workflows"],
            cwd=root,
            text=True,
        ).splitlines()
        if path.endswith((".yml", ".yaml"))
    )
    payload = ("\n".join(relative) + "\n").encode()
    assert len(relative) == 260
    assert hashlib.sha256(payload).hexdigest() == (
        "5c1d78b2cfc4ebc0ccb2a4cb71239d5232bdcc7d8deddb5a5044c9430cb83ae3"
    )
    assert validate_workflow_population(root) == set(relative)


def test_workflow_population_uses_only_git_tracked_paths(tmp_path):
    root = tmp_path
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    tracked = [".github/workflows/a.yml", ".github/workflows/b.yaml"]
    for path in tracked:
        target = root / path
        target.write_text("name: tracked\n")
    manifest = root / ledger.WORKFLOW_OWNERSHIP_MANIFEST
    manifest.parent.mkdir(parents=True)
    payload = ("\n".join(tracked) + "\n").encode()
    digest = hashlib.sha256(payload).hexdigest()
    rows = "\n".join(f"{path} | LEAD-BLOCKED | blocked" for path in tracked)
    manifest.write_text(
        "# WP-150 workflow ownership manifest\n"
        f"workflow-count: {len(tracked)}\n"
        f"workflow-paths-sha256: {digest}\n\n"
        "```wp-workflow-ownership\n" + rows + "\n```\n"
    )
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(
        [
            "git", "add", ".github/workflows/a.yml",
            ".github/workflows/b.yaml",
            ledger.WORKFLOW_OWNERSHIP_MANIFEST.as_posix(),
        ],
        cwd=root,
        check=True,
    )
    (workflow_dir / "untracked.yml").write_text("name: untracked\n")
    assert validate_workflow_population(root) == set(tracked)


@pytest.mark.parametrize("stale_field", ["count", "digest"])
def test_workflow_population_rejects_stale_count_or_digest(tmp_path, stale_field):
    root = tmp_path
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    tracked = [".github/workflows/a.yml", ".github/workflows/b.yaml"]
    for path in tracked:
        (root / path).write_text("name: tracked\n")

    payload = ("\n".join(tracked) + "\n").encode()
    count = len(tracked)
    digest = hashlib.sha256(payload).hexdigest()
    if stale_field == "count":
        count += 1
    else:
        digest = "0" * 64

    manifest = root / ledger.WORKFLOW_OWNERSHIP_MANIFEST
    manifest.parent.mkdir(parents=True)
    rows = "\n".join(f"{path} | LEAD-BLOCKED | blocked" for path in tracked)
    manifest.write_text(
        "# WP-150 workflow ownership manifest\n"
        f"workflow-count: {count}\n"
        f"workflow-paths-sha256: {digest}\n\n"
        "```wp-workflow-ownership\n" + rows + "\n```\n"
    )
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(
        [
            "git", "add", ".github/workflows/a.yml",
            ".github/workflows/b.yaml",
            ledger.WORKFLOW_OWNERSHIP_MANIFEST.as_posix(),
        ],
        cwd=root,
        check=True,
    )

    with pytest.raises(LedgerError, match="WP-150 workflow population drift"):
        validate_workflow_population(root)


def test_workflow_ownership_parser_uses_strict_top_level_fence():
    text = """
```wp-workflow-ownership
.github/workflows/a.yml | LEAD-BLOCKED | blocked
```
"""
    assert parse_workflow_ownership(text, "fixture.md") == [
        (".github/workflows/a.yml", "LEAD-BLOCKED", "blocked")
    ]
    with pytest.raises(LedgerError, match="nested"):
        parse_workflow_ownership(
            "````markdown\n```wp-workflow-ownership\na | LEAD-BLOCKED | blocked\n```\n````",
            "fixture.md",
        )
