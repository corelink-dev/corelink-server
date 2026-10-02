from __future__ import annotations

import hashlib
import importlib.util
import itertools
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_b155_backlog_grep_population.py"
spec = importlib.util.spec_from_file_location("b155_verifier", SCRIPT)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)

REPAIR_SCRIPT = ROOT / "scripts/repair_b155_grep_population.py"
repair_spec = importlib.util.spec_from_file_location("b155_repair", REPAIR_SCRIPT)
assert repair_spec and repair_spec.loader
repair = importlib.util.module_from_spec(repair_spec)
sys.modules[repair_spec.name] = repair
repair_spec.loader.exec_module(repair)


class B155VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")

    def test_census_is_complete_and_population_is_exact(self) -> None:
        result = verifier.census(self.backlog)
        self.assertEqual(result.records, 373)
        self.assertEqual(result.command_records, 354)
        self.assertEqual(result.manual_records, 19)
        self.assertEqual(result.command_records + result.manual_records, result.records)
        self.assertEqual(result.grep_invocations, 194)
        self.assertEqual(len(result.assertions), 191)
        self.assertEqual(len(result.unsafe), 0)
        self.assertEqual(len(result.indeterminate), 0)

    def test_long_malformed_verify_line_fails_closed_with_bounded_work(self) -> None:
        with self.assertRaises(verifier.InstrumentError):
            verifier._grep_checks({"id": "B-155", "verify": "grep '" + "\\" * 20_000})

    def test_valid_verify_line_within_limit_remains_supported(self) -> None:
        checks, invocations, indeterminate = verifier._grep_checks(
            {"id": "B-155", "verify": 'grep -q "safe" README.md'}
        )
        self.assertEqual(invocations, 1)
        self.assertEqual(len(checks), 1)
        self.assertEqual(indeterminate, [])

    def test_source_kind_uses_grep_operands_not_pattern_text(self) -> None:
        bait = 'grep -q "^[^/*]*foo.rs" BACKLOG.md'
        self.assertEqual(verifier._source_kind(bait, bait, bait.find("grep"))[0], "markdown")
        real = 'grep -q "foo.rs" crates/corelink-container/src/lib.rs'
        self.assertEqual(verifier._source_kind(real, real, real.find("grep"))[0], "rust")
        quoted = 'grep -q "file.rs" docs/README.md'
        self.assertEqual(verifier._source_kind(quoted, quoted, quoted.find("grep"))[0], "markdown")
        for verify in ('cat file.rs | grep -q "foo.rs"', 'grep -q "foo.rs"'):
            checks, invocations, indeterminate = verifier._grep_checks(
                {"id": "B-155", "verify": verify}
            )
            self.assertEqual(invocations, 1)
            self.assertEqual(len(checks), 1)
            self.assertEqual(checks[0].source_kind, "unknown")
            self.assertEqual(len(indeterminate), 1)

    def test_grep_operand_roles_are_closed_and_syntax_is_conservative(self) -> None:
        # Redirection targets, process substitutions, and here-doc words are
        # shell I/O, never grep file operands. A stream-only assertion remains
        # indeterminate even when its data spells a known extension.
        for verify in (
            'grep -q "^[^/*]*foo" < file.rs',
            'grep -q "^[^/*]*foo" > file.rs',
            'grep -q "^[^/*]*foo" >>file.rs',
            'grep -q "^[^/*]*foo" 2> file.rs',
            'grep -q "^[^/*]*foo" 2>>file.rs',
            'grep -q "^[^/*]*foo" <<< foo.rs',
            'grep -q "^[^/*]*foo" << EOF',
            'grep -q "foo" <(cat file.rs)',
        ):
            with self.subTest(verify=verify):
                checks, invocations, indeterminate = verifier._grep_checks(
                    {"id": "B-155", "verify": verify}
                )
                self.assertEqual(invocations, 1)
                self.assertEqual(checks[0].source_kind, "unknown")
                self.assertEqual(len(indeterminate), 1)

        # Only positional operands classify the source. Options and patterns
        # may contain extensions without controlling the dialect.
        controls = (
            ('grep -q -- "foo.rs" docs/README.md', "markdown"),
            ('grep -q -e "foo.rs" docs/README.md', "markdown"),
            ('grep -q -f patterns.rs docs/README.md', "markdown"),
            ('grep -q -efoo.rs "docs/read me.md"', "markdown"),
            ('grep -q -fpatterns.rs "docs/read me.md"', "markdown"),
            ('grep -q "foo" src/*.rs', "rust"),
            ('grep -q "foo" fixtures.md/generated/file.rs', "rust"),
        )
        for verify, expected_kind in controls:
            with self.subTest(verify=verify):
                checks, invocations, indeterminate = verifier._grep_checks(
                    {"id": "B-155", "verify": verify}
                )
                self.assertEqual(invocations, 1)
                self.assertEqual(checks[0].source_kind, expected_kind)
                self.assertEqual(indeterminate, [])

        # A glob without a syntax suffix and multiple differing source
        # syntaxes cannot choose the first extension. Mixed known syntaxes
        # union their comment prefixes so Markdown comments remain visible.
        for verify in (
            'grep -q "foo" src/*',
            'grep -q "foo" src/*.{rs,md}',
            'grep -q "^[^/*]*foo" file.rs README.md',
        ):
            with self.subTest(verify=verify):
                checks, invocations, indeterminate = verifier._grep_checks(
                    {"id": "B-155", "verify": verify}
                )
                self.assertEqual(invocations, 1)
                self.assertEqual(len(checks), 1)
                if "README" in verify:
                    self.assertEqual(checks[0].source_kind, "mixed")
                    self.assertIn("#", checks[0].comment_prefixes)
                    self.assertTrue(verifier._matches_comment(checks[0]))
                    self.assertEqual(indeterminate, [])
                else:
                    self.assertEqual(checks[0].source_kind, "unknown")
                    self.assertEqual(len(indeterminate), 1)

    def test_b125_grep_operands_have_no_ambiguous_continuation_token(self) -> None:
        record = next(item for item in verifier._records(self.backlog) if item["id"] == "B-125")
        verify = record["verify"]
        self.assertIsInstance(verify, str)
        assert isinstance(verify, str)
        for line in verify.splitlines():
            if "grep" in line:
                self.assertFalse(line.rstrip().endswith("\\"), line)

    def test_real_unanchored_member_mutation_changes_semantic_verdict(self) -> None:
        baseline = verifier.census(self.backlog)
        marker = 'grep -q "^[^#]*clippy --workspace --all-targets"'
        self.assertEqual(self.backlog.count(marker), 1)
        mutated = self.backlog.replace(marker, 'grep -q "clippy --workspace --all-targets"', 1)
        changed = verifier.census(mutated)
        self.assertGreater(len(changed.unsafe), len(baseline.unsafe))

    def test_parser_rejects_empty_population_instead_of_returning_done(self) -> None:
        with self.assertRaises(verifier.InstrumentError):
            verifier.census("no fenced backlog records")

    def test_missing_pyyaml_fails_closed(self) -> None:
        result = subprocess.run(
            [sys.executable, "-S", str(SCRIPT), "--expect", "open"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PyYAML is required", result.stderr)

    def test_exact_multiword_reproductions_are_comment_sensitive(self) -> None:
        # B087/B088/B125 were all missed when the detector tested only one
        # token from the pattern.  Keep the reproductions independent of the
        # repaired BACKLOG text so a future guard cannot delete the fixture.
        for record_id, pattern in (
            ("B-087", "Object Lock"),
            ("B-088", "No external pentest has been commissioned"),
            ("B-125", "fn resolve_seed"),
        ):
            check = verifier.GrepCheck(record_id, 1, pattern, "-q ", "grep", "'")
            self.assertTrue(verifier._matches_comment(check), record_id)

    def test_b084_fence_and_b164_positive_grep_removals_are_rejected(self) -> None:
        # B084: deleting an entire real record must not shrink the denominator
        # and leave a falsely clean census.
        fence = next(
            match
            for match in verifier.FENCE.finditer(self.backlog)
            if "id: B-084\n" in match.group(1)
        )
        without_b084 = self.backlog[: fence.start()] + self.backlog[fence.end() :]
        with self.assertRaises(verifier.InstrumentError):
            verifier.census(without_b084)

        # B-373: the newest real record is equally load-bearing. Removing its
        # fence must not be accepted as a green, smaller population.
        fence = next(
            match
            for match in verifier.FENCE.finditer(self.backlog)
            if "id: B-373\n" in match.group(1)
        )
        without_b373 = self.backlog[: fence.start()] + self.backlog[fence.end() :]
        with self.assertRaises(verifier.InstrumentError):
            verifier.census(without_b373)

        # B164 still contains executable positive greps. Deleting one must
        # change the closed assertion population even though all records parse.
        record = next(
            item for item in verifier._records(self.backlog) if item["id"] == "B-164"
        )
        checks, _, _ = verifier._grep_checks(record)
        self.assertTrue(checks)
        fence = next(
            match
            for match in verifier.FENCE.finditer(self.backlog)
            if "id: B-164\n" in match.group(1)
        )
        raw_lines = fence.group(1).splitlines()
        raw_line = next(
            line for line in raw_lines
            if "grep" in line and "get_json_preserves_http_status_without_response_body" in line
        )
        raw_lines[raw_lines.index(raw_line)] = raw_line.replace("grep", "true", 1)
        mutated_block = "\n".join(raw_lines)
        mutated = self.backlog[: fence.start(1)] + mutated_block + self.backlog[fence.end(1) :]
        with self.assertRaises(verifier.InstrumentError):
            verifier.census(mutated)

    def test_unquoted_grep_in_if_is_parsed_and_reopens_gate(self) -> None:
        marker = 'grep -q "^[^#]*clippy --workspace --all-targets"'
        self.assertEqual(self.backlog.count(marker), 1)
        mutated = self.backlog.replace(marker, "if grep unsafe BACKLOG.md", 1)
        result = verifier.census(mutated)
        self.assertTrue(any(check.pattern == "unsafe" for check in result.unsafe))

    def test_nested_bash_c_grep_is_counted_and_guard_mutation_changes_verdict(self) -> None:
        record = next(item for item in verifier._records(self.backlog) if item["id"] == "B-055")
        checks, invocations, _ = verifier._grep_checks(record)
        self.assertEqual(invocations, 3)
        self.assertIn("^[^/*]*Sli::AvailCasGet", [check.pattern for check in checks])

        marker = 'grep -q "^[^/*]*Sli::AvailCasGet"'
        self.assertEqual(self.backlog.count(marker), 1)
        mutated = self.backlog.replace(marker, 'grep -q "Sli::AvailCasGet"', 1)
        changed = verifier.census(mutated)
        baseline = verifier.census(self.backlog)
        self.assertGreater(len(changed.unsafe), len(baseline.unsafe))

    def test_dynamic_nested_shell_payload_fails_closed(self) -> None:
        record = {
            "id": "B-155",
            "verify": 'bash -c "$SCRIPT"',
        }
        with self.assertRaises(verifier.InstrumentError):
            verifier._grep_checks(record)

    def test_dynamic_nested_payload_expansions_fail_closed_at_every_position(self) -> None:
        # The old guard only inspected the beginning of the payload, allowing
        # an expansion to manufacture the rest of a script after a harmless
        # prefix.  A double-quoted argument is expanded by the invoking shell
        # at every position; all shell spellings must therefore be rejected.
        for shell in ("bash", "sh", "zsh"):
            for payload in (
                '"$SCRIPT; grep -q foo file"',
                '"echo hi $SCRIPT; grep -q foo file"',
                '"echo hi; grep -q foo file; $SCRIPT"',
                '"$(gen); grep -q foo file"',
                '"echo hi $(gen); grep -q foo file"',
                '"echo hi; grep -q foo file; $(gen)"',
            ):
                with self.subTest(shell=shell, payload=payload):
                    with self.assertRaises(verifier.InstrumentError):
                        verifier._grep_checks(
                            {"id": "B-155", "verify": f"{shell} -c {payload}"}
                        )

    def test_single_quoted_payload_is_literal_to_invoking_shell(self) -> None:
        # These expansions are data passed to the child shell, matching the
        # production backlog's literal bash -c bodies.  Conversely, a single
        # quote inside an outer double-quoted word does not suppress expansion
        # in the invoking shell and must still fail closed.
        for shell in ("bash", "sh", "zsh"):
            with self.subTest(shell=shell):
                checks, invocations, indeterminate = verifier._grep_checks(
                    {
                        "id": "B-155",
                        "verify": f"{shell} -c 'echo hi $SCRIPT; grep -q foo file.rs'",
                    }
                )
                self.assertEqual(invocations, 1)
                self.assertEqual([check.pattern for check in checks], ["foo"])
                self.assertEqual(indeterminate, [])
                with self.assertRaises(verifier.InstrumentError):
                    verifier._grep_checks(
                        {
                            "id": "B-155",
                            "verify": f'{shell} -c "echo \'$SCRIPT\'; grep -q foo file"',
                        }
                    )

    def test_escaped_quotes_in_double_quoted_payload_are_decoded(self) -> None:
        checks, invocations, indeterminate = verifier._grep_checks(
            {"id": "B-155", "verify": 'bash -c "grep -q \\"foo\\" file.rs"'}
        )
        self.assertEqual(invocations, 1)
        self.assertEqual(indeterminate, [])
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].pattern, "foo")
        self.assertEqual(checks[0].quote, '"')

    def test_bre_ere_fixed_and_shell_variable_semantics_are_not_literal(self) -> None:
        self.assertIsNotNone(verifier._as_python_regex(r"foo\|bar").search("bar"))
        self.assertIsNone(verifier._as_python_regex(r"foo|bar").search("bar"))
        self.assertIsNotNone(verifier._as_python_regex("foo|bar", "-E ").search("bar"))
        self.assertIsNotNone(verifier._as_python_regex("foo|bar", "-F ").search("foo|bar"))
        dynamic = verifier.GrepCheck("B-155", 1, "$needle", "-q ", "grep", '"')
        self.assertTrue(verifier._matches_comment(dynamic))

    def test_mutation_self_test_covers_fixture_and_completeness_guard(self) -> None:
        verifier.mutation_self_test(self.backlog)

    def test_syntax_manifest_covers_comment_forms(self) -> None:
        for suffix, kind in (("rs", "rust"), ("ts", "typescript"), ("yml", "config"), ("md", "markdown"), ("sh", "shell")):
            with self.subTest(suffix=suffix):
                checks, invocations, indeterminate = verifier._grep_checks(
                    {"id": "B-155", "verify": f'grep -q "needle" file.{suffix}'}
                )
                self.assertEqual(invocations, 1)
                self.assertEqual(indeterminate, [])
                self.assertEqual(checks[0].source_kind, kind)
                self.assertTrue(verifier._matches_comment(checks[0]))

    def test_wrapped_grep_forms_are_counted_or_fail_closed(self) -> None:
        # A wrapper must not hide a grep from the command census.  File-backed
        # forms classify normally; a dynamic/no-file form is indeterminate and
        # therefore red rather than silently disappearing.
        wrapped = (
            "sudo grep -q \"needle\" file.rs",
            "sudo -u alice grep -q \"needle\" file.rs",
            "env grep -q \"needle\" file.rs",
            "env -i VAR=x grep -q \"needle\" file.rs",
            "git grep -q \"needle\" file.rs",
            "git -C repo grep -q \"needle\" file.rs",
            "xargs grep -q \"needle\" file.rs",
            "xargs -n 1 grep -q \"needle\" file.rs",
            "{ grep -q \"needle\" file.rs; }",
            "VAR=value grep -q \"needle\" file.rs",
            "2>/dev/null grep -q \"needle\" file.rs",
        )
        for verify in wrapped:
            with self.subTest(verify=verify):
                checks, invocations, indeterminate = verifier._grep_checks(
                    {"id": "B-155", "verify": verify}
                )
                self.assertEqual(invocations, 1)
                self.assertEqual(len(checks), 1)
                self.assertEqual(checks[0].source_kind, "rust")
                self.assertEqual(indeterminate, [])

        # Replacing any recognized wrapper with an unknown executable must not
        # make the grep disappear from the census.
        for prefix in ("sudo -u alice", "env -i VAR=x", "git -C repo", "xargs -n 1"):
            with self.subTest(prefix=prefix):
                known = f"{prefix} grep -q \"needle\" file.rs"
                unknown = known.replace(prefix, "mystery-wrapper", 1)
                _, known_count, known_unknown = verifier._grep_checks(
                    {"id": "B-155", "verify": known}
                )
                _, unknown_count, unknown_indeterminate = verifier._grep_checks(
                    {"id": "B-155", "verify": unknown}
                )
                self.assertEqual((known_count, known_unknown), (1, []))
                self.assertEqual(unknown_count, 1)
                self.assertEqual(len(unknown_indeterminate), 1)

        checks, invocations, indeterminate = verifier._grep_checks(
            {"id": "B-155", "verify": "sudo grep -q \"needle\""}
        )
        self.assertEqual(invocations, 1)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].source_kind, "unknown")
        self.assertEqual(len(indeterminate), 1)
        # Unknown syntax is fail-closed at census level, even when the helper
        # is exercised directly with a synthetic record.
        with self.assertRaises(verifier.InstrumentError):
            verifier.census(
                "```backlog\n"
                "id: B-155\nrepo: corelink-server\nowner: tl\nstatus: open\n"
                "verify: sudo grep -q needle\nverify-means: wrapped\n```\n"
            )

    def test_owned_batch_guards_reject_bounded_comment_bait(self) -> None:
        # Each repaired block must remain load-bearing: removing one complete
        # syntax guard reopens that record in the census. Mutate one assertion
        # per owner, never the global population or status fields.
        mutations = {
            "B-125": (
                'grep -q "^[^#]*AUDIT_DRAIN_BATCH_LIMIT" wrangler.toml',
                'grep -q "AUDIT_DRAIN_BATCH_LIMIT" wrangler.toml',
            ),
            "B-136": (
                'grep -qE "^[[:space:]]*[^#/*<>-][^#/*<>]*github.event_name"',
                'grep -qE "github.event_name"',
            ),
            "B-141": (
                'grep -q "^[^#]*persist-credentials: false"',
                'grep -q "persist-credentials: false"',
            ),
            "B-159": (
                'grep -q "^[^#<>*/-].*Cache errors" apps/docs/docs/integrations/sccache-cargo.md',
                'grep -q "Cache errors" apps/docs/docs/integrations/sccache-cargo.md',
            ),
            "B-164": (
                'grep -q "^[^#/*-]*CliError::HttpStatus { status: 401 }" tools/cli/src/doctor.rs',
                'grep -q "CliError::HttpStatus { status: 401 }" tools/cli/src/doctor.rs',
            ),
            "B-252": (
                "grep -q '^[^#]*scripts/tests/gitleaks-shape-regression.sh'",
                "grep -q 'scripts/tests/gitleaks-shape-regression.sh'",
            ),
        }
        baseline = verifier.census(self.backlog)
        for record_id, (guarded, bait) in mutations.items():
            with self.subTest(record_id=record_id):
                fence = next(
                    match
                    for match in verifier.FENCE.finditer(self.backlog)
                    if f"id: {record_id}\n" in match.group(1)
                )
                self.assertIn(guarded, fence.group(1))
                mutated_block = fence.group(1).replace(guarded, bait, 1)
                mutated = self.backlog[: fence.start(1)] + mutated_block + self.backlog[fence.end(1) :]
                changed = verifier.census(mutated)
                self.assertGreater(
                    len(changed.unsafe), len(baseline.unsafe),
                    f"{record_id} guard mutation did not reopen B-155 risk",
                )

    def test_repair_is_a_noop_after_population_is_closed(self) -> None:
        rewritten, changed = repair.repair(self.backlog)
        self.assertEqual(rewritten, self.backlog)
        self.assertEqual(changed, 0)

    def test_b055_extracted_shell_payload_is_syntactically_valid(self) -> None:
        record = next(item for item in verifier._records(self.backlog) if item["id"] == "B-055")
        verify = record["verify"]
        self.assertIsInstance(verify, str)
        match = verifier.NESTED_SHELL.search(verify)
        self.assertIsNotNone(match)
        assert match is not None
        position = match.end()
        while position < len(verify) and verify[position].isspace():
            position += 1
        payload, _ = verifier._decode_nested_payload(verify, position)
        parsed = subprocess.run(
            ["bash", "-n"], input=payload, text=True, capture_output=True, check=False
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)


class B155BoundaryGrammarTests(unittest.TestCase):
    """#1674: command boundaries match in linear time and keep the regex language.

    Every expected value below was captured by running the replaced regexes
    (unchanged from #2852 through origin/main 12cb082ca), so these tests pin
    the old language, not the new implementation's opinion of it; both
    equivalence tests also pass against the old regexes.
    """

    GRAMMARS = ("COMMAND_BOUNDARY", "WRAPPED_COMMAND_BOUNDARY", "REDIRECTION_BOUNDARY")

    def verdicts(self, text: str) -> tuple[bool, ...]:
        return tuple(getattr(verifier, name).search(text) is not None for name in self.GRAMMARS)

    def test_golden_prefixes_keep_the_replaced_regex_verdicts(self) -> None:
        # (text, (command, wrapped, redirection)).  The second half is the
        # adversarial set: values adjacent to quoted values, a quote opened
        # inside another quote, the ReDoS witness shapes, ``$`` before a final
        # newline, and Unicode \s, \d and \w around the boundary words.
        cases = (
            ("", (True, False, False)),
            ("  ", (True, False, False)),
            ("FOO=1 ", (True, False, False)),
            ("if ", (True, False, False)),
            ("if ! ", (True, False, False)),
            ("then ", (True, False, False)),
            ("x && ", (True, False, False)),
            ("x || ", (True, False, False)),
            ("a | ", (True, False, False)),
            ("$( ", (True, False, False)),
            ("( ", (True, False, False)),
            ("echo foo ", (False, False, False)),
            ("echo sudo ", (False, False, False)),
            ("sudo ", (False, True, False)),
            ("sudo -u root ", (False, False, False)),
            ("env A=1 ", (False, True, False)),
            ("git -C repo ", (False, False, False)),
            ("xargs -0 ", (False, True, False)),
            ("2>/dev/null ", (False, False, True)),
            ("< file.rs ", (False, False, True)),
            ("cat file | ", (True, False, False)),
            ("A='x y' ", (True, False, False)),
            ('A="x y" ', (True, False, False)),
            ("A=x B='y z' ", (True, False, False)),
            ("if x=1; then ", (True, False, False)),
            ("A=1 sudo ", (False, True, False)),
            ("! sudo env B=2 git ", (False, True, False)),
            ("x; >>> y", (False, False, True)),
            ("A=xB='y z'", (True, False, False)),
            ("A='x B=y'z", (True, False, False)),
            ("A='x B=\"y z' w\"", (True, False, False)),
            ("A='x y", (False, False, False)),
            ("A=xsudo ", (True, True, False)),
            ("x; A=1 2>&1 <<<'h i' ", (False, False, False)),
            ("A=" + "!A=" * 6 + " x", (False, False, False)),
            ("<<!" * 4 + " x", (False, False, False)),
            (">" + "!<" * 4 + ")", (False, False, False)),
            ("A=1\n", (True, False, False)),
            ("A=1\nB", (False, False, False)),
            ("\u00a0", (True, False, False)),
            ("\u0663>x ", (False, False, True)),
            ("\u00e9if ", (False, False, False)),
            ("elif ", (True, False, False)),
            ("do", (True, False, False)),
            ("done ", (False, False, False)),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(self.verdicts(text), expected)

    def test_engine_dollar_also_matches_before_a_final_newline(self) -> None:
        # The three real tails end in \s* or \s+, which absorb a final
        # newline, so that half of ``$`` is only observable on a tail that
        # cannot: compare the engine itself with ``re`` on such a tail.
        parser = verifier._parser
        engine = parser._BoundaryGrammar(parser._lit("x"))
        regex = re.compile(
            r"(?:^|[;&|(!]|\$\(|\b(?:if|elif|then|while|until|do|command|builtin|exec)\b)x$"
        )
        for text in ("x", "x\n", "x\n\n", "x\ny", "\nx", "ax\n", ";x\n", "; x\n", "$(x\n", "ifx\n"):
            with self.subTest(text=text):
                self.assertEqual(engine.search(text), True if regex.search(text) else None)

    def test_exhaustive_token_domain_keeps_the_replaced_regex_language(self) -> None:
        # Every concatenation of up to three tokens, one verdict bit per
        # grammar.  The digest and counts are the replaced regexes' output on
        # this exact enumeration (wider one-off differentials while authoring
        # #1674: 1,727,605 exhaustive and 600,000 seeded random strings, no
        # verdict differed).
        tokens = ("A=", "B", "=", "'", '"', " ", "x", "!", ";", ">", "<<", "2", "sudo", "env", "-u",
                  "(", "$(", "if", "\t", "\n", "\u00a0", "\u0663", "'a b'", "B=1", "|", "do")
        digest = hashlib.sha256()
        positives = [0, 0, 0]
        total = 0
        for length in range(4):
            for parts in itertools.product(tokens, repeat=length):
                bits = 0
                for index, matched in enumerate(self.verdicts("".join(parts))):
                    if matched:
                        bits |= 1 << index
                        positives[index] += 1
                digest.update(bytes([bits]))
                total += 1
        self.assertEqual(total, 18_279)
        self.assertEqual(positives, [6_954, 120, 1_790])
        self.assertEqual(
            digest.hexdigest(), "42fb0db6d7d65024153f66a18553b58cd5dda1f28eb512b78e80e601d4433b29"
        )

    def test_redos_witnesses_at_the_line_cap_finish_in_bounded_time(self) -> None:
        # Each witness made the replaced regexes backtrack exponentially
        # ("<<!" * 12 + " x", 38 characters, took 27 s and two more
        # repetitions multiply it by more than ten), so at the verify-line
        # cap they never finish; the linear matcher needs milliseconds.  Run
        # them, directly and through the nested shell scanner that consumes
        # the boundary, in a child process so a regression fails on the
        # timeout instead of hanging the suite.
        program = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('b155_parser_redos', sys.argv[1])\n"
            "parser = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = parser\n"
            "spec.loader.exec_module(parser)\n"
            "grammars = (parser.COMMAND_BOUNDARY, parser.WRAPPED_COMMAND_BOUNDARY, parser.REDIRECTION_BOUNDARY)\n"
            "for witness in ('A=' + '!A=' * 2700 + ' x', '<<!' * 2700 + ' x', '>' + '!<' * 4000 + ')'):\n"
            "    verify = witness + \" bash -c 'grep -q y f.rs'\"\n"
            "    assert len(verify.encode()) <= parser.MAX_VERIFY_LINE_BYTES\n"
            "    print(*(grammar.search(witness) is not None for grammar in grammars))\n"
            "    print(parser._grep_checks({'id': 'B-155', 'verify': verify})[1])\n"
        )
        parser = ROOT / "scripts/b155_backlog_grep_parser.py"
        result = subprocess.run(
            [sys.executable, "-c", program, str(parser)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["False False False", "0"] * 3)


if __name__ == "__main__":
    unittest.main()
