from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import verify_real_ignored_harnesses as verifier
from scripts.test_stripe_guard_mutations import TEST, check_result


METHODS = (
    "verify_test_mode_starter_catalog",
    "verify_direct_test_mode_account",
    "create_harness_starter_product",
    "create_harness_starter_price",
    "cleanup_harness_price",
    "cleanup_harness_product",
    "cleanup_harness_checkout",
    "cleanup_harness_customer",
)


class StripePreRequestGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="stripe-pre-request-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = {}
        for relative in verifier.STRIPE_CONTRACT_SOURCES:
            source = (verifier.ROOT / relative).read_text(encoding="utf-8")
            self.sources[relative] = source
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")

    def test_unmodified_contract_passes(self) -> None:
        verifier.verify_stripe_cleanup_contract(self.root)

    def test_each_removed_guard_is_rejected_without_digest_checks(self) -> None:
        relative = verifier.STRIPE_CONTRACT_SOURCES[0]
        source = self.sources[relative]
        for method in METHODS:
            with self.subTest(method=method):
                match = re.search(rf"(?ms)^    pub fn {method}\b.*?^    }}", source)
                self.assertIsNotNone(match)
                body = match.group(0)
                self.assertEqual(body.count("self.require_direct_test_key()?;"), 1)
                mutated = source[:match.start()] + body.replace(
                    "self.require_direct_test_key()?;", "", 1
                ) + source[match.end():]
                (self.root / relative).write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(AssertionError, rf"pre-request TEST-key guard: {method}"):
                    verifier.verify_stripe_cleanup_contract(self.root)
        (self.root / relative).write_text(source, encoding="utf-8")

    def test_each_missing_behavioral_call_is_rejected(self) -> None:
        relative = verifier.STRIPE_CONTRACT_SOURCES[1]
        source = self.sources[relative]
        start = source.index("    fn direct_test_refuses_live_and_non_test_keys_before_any_request()")
        end = source.index("    fn direct_account_result(", start)
        for method in METHODS:
            with self.subTest(method=method):
                body = source[start:end]
                call = f"client.{method}("
                self.assertEqual(body.count(call), 1)
                mutated = source[:start] + body.replace(call, "client.effective_base_url(", 1) + source[end:]
                (self.root / relative).write_text(mutated, encoding="utf-8")
                with self.assertRaisesRegex(AssertionError, rf"refusal coverage: {method}"):
                    verifier.verify_stripe_cleanup_contract(self.root)
        (self.root / relative).write_text(source, encoding="utf-8")


class HostedMutationResultTests(unittest.TestCase):
    def test_requires_exact_behavioral_failure(self) -> None:
        method = "create_harness_starter_price"
        killed = f"test {TEST} ... FAILED\nrequest before key refusal: {method}\n"
        check_result(subprocess.CompletedProcess([], 101, killed), method)
        for code, output in (
            (0, killed),
            (101, "error: could not compile corelink-stripe-real"),
            (101, f"test {TEST} ... FAILED\nexpected authentication refusal: {method}\n"),
            (101, killed.replace(method, "create_harness_starter_product")),
            (101, killed.replace(TEST, "some_other_test")),
        ):
            with self.subTest(code=code, output=output):
                with self.assertRaises(AssertionError):
                    check_result(subprocess.CompletedProcess([], code, output), method)

    def test_control_must_execute_the_exact_test(self) -> None:
        check_result(subprocess.CompletedProcess([], 0, f"test {TEST} ... ok\n"), None)
        for code, output in ((0, "running 0 tests"), (101, f"test {TEST} ... ok\n")):
            with self.subTest(code=code, output=output):
                with self.assertRaises(AssertionError):
                    check_result(subprocess.CompletedProcess([], code, output), None)


if __name__ == "__main__":
    unittest.main()
