#!/usr/bin/env python3
"""Bounded Stripe test-mode evidence probes for issues #1649 and #2565.

The #2565 identity-only mode makes one read-only Account GET. The #1649
customer-lifecycle mode creates one disposable Customer, replays the exact
create request with one stable idempotency key, verifies test mode and ordering,
then deletes the Customer. Both modes write only redacted receipts; response
bodies and credentials are never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

API_BASE = "https://api.stripe.com"
TIMEOUT_SECONDS = 20
CONFIRMATION = "run-i1649-stripe-test-mode"
IDENTITY_CONFIRMATION = "run-i2565-stripe-identity-only"
STARTER_PRICE_CONFIRMATION = "run-i2565-stripe-starter-price-readonly"
REQUIRED_WORKFLOW_MARKERS = (
    "github.repository == 'HuGR-dev/corelink-server'",
    "runs-on: ubuntu-latest",
    "STRIPE_SECRET_KEY",
    "rk_test_",
    "Accounts: Read",
    "Customers: Write",
    "livemode",
    "idempotency",
    "cleanup",
    "identity-only",
    "starter-price-readonly",
    "Products: Read",
    "STRIPE_TEST_ACCOUNT_ID",
    "Run read-only Stripe account identity probe",
    "persist-credentials: false",
)
FORBIDDEN_WORKFLOW_MARKERS = (
    "sk_test_",
    "sk_live_",
    "runs-on: corelink",
    "runs-on: self-hosted",
    "api.stripe.com/v1",
)


class ProbeError(RuntimeError):
    """A fail-closed probe error without provider response content."""


def redacted_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "<missing>"
    if len(value) <= 8:
        return value[:3] + "…"
    return value[:4] + "…" + value[-3:]


def request_json(
    key: str,
    method: str,
    path: str,
    *,
    form: dict[str, str] | None = None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, Any]]:
    body = urllib.parse.urlencode(form or {}).encode() if form is not None else None
    headers = {"Authorization": f"Bearer {key}"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(
        API_BASE + path, data=body, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read())
            if not isinstance(payload, dict):
                raise ProbeError(f"Stripe returned a non-object for {path}")
            return response.status, payload
    except urllib.error.HTTPError as error:
        # Never include the response body: provider errors can contain request
        # metadata and are not part of the redacted evidence contract.
        raise ProbeError(f"Stripe {method} {path} returned HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ProbeError(f"Stripe {method} {path} was unavailable") from error


def assert_test_mode(payload: dict[str, Any], label: str) -> None:
    if payload.get("livemode") is not False:
        raise ProbeError(f"{label} did not assert livemode=false")


def assert_account_identity(payload: dict[str, Any]) -> None:
    """Validate the Account shape; Stripe Account objects do not expose livemode."""
    account_id = payload.get("id")
    if (
        payload.get("object") != "account"
        or not isinstance(account_id, str)
        or not account_id.startswith("acct_")
    ):
        raise ProbeError(
            "Stripe account response did not contain the expected account identity"
        )


def require_restricted_test_key(key: str) -> None:
    """Reject unrestricted and live keys before any provider request."""
    if not key.startswith("rk_test_"):
        raise ProbeError("STRIPE_SECRET_KEY must start with rk_test_; other keys are rejected")


def run_probe(key: str, run_id: str, output: Path) -> int:
    require_restricted_test_key(key)
    if not run_id or not run_id.isascii() or not run_id.replace("-", "").isalnum():
        raise ProbeError("GITHUB_RUN_ID is missing or malformed")

    steps: list[str] = []
    customer_id: str | None = None
    cleanup_ok = False
    idempotency_key = f"corelink-i1649-{run_id}"
    receipt: dict[str, Any] = {
        "schema": "corelink.stripe-test-mode-evidence.v1",
        "issue": 1649,
        "mode": "test",
        "livemode": None,
        "idempotency_replayed": False,
        "ordering": [],
        "cleanup": {"attempted": False, "succeeded": False},
        "redacted": True,
    }

    try:
        account_status, account = request_json(key, "GET", "/v1/account")
        if account_status != 200:
            raise ProbeError("Stripe account read failed")
        assert_account_identity(account)
        steps.append("account_identity_checked")

        create_form = {
            "description": f"corelink i1649 evidence {run_id}",
            "metadata[corelink_evidence]": "i1649",
        }
        _, first = request_json(
            key, "POST", "/v1/customers", form=create_form, idempotency_key=idempotency_key
        )
        assert_test_mode(first, "created customer")
        receipt["livemode"] = False
        customer_id = first.get("id")
        if not isinstance(customer_id, str) or not customer_id.startswith("cus_"):
            raise ProbeError("Stripe customer response did not contain a customer id")
        steps.append("customer_created")

        _, replay = request_json(
            key, "POST", "/v1/customers", form=create_form, idempotency_key=idempotency_key
        )
        assert_test_mode(replay, "replayed customer")
        if replay.get("id") != customer_id:
            raise ProbeError("same idempotency key produced a different customer")
        receipt["idempotency_replayed"] = True
        steps.append("same_request_replayed")

        _, retrieved = request_json(key, "GET", f"/v1/customers/{customer_id}")
        assert_test_mode(retrieved, "retrieved customer")
        if retrieved.get("id") != customer_id:
            raise ProbeError("retrieved customer id differed from create response")
        steps.append("customer_retrieved_after_create")

        receipt["customer"] = redacted_id(customer_id)
        receipt["idempotency_key"] = redacted_id(idempotency_key)
    finally:
        receipt["cleanup"]["attempted"] = customer_id is not None
        if customer_id is not None:
            try:
                _, deleted = request_json(key, "DELETE", f"/v1/customers/{customer_id}")
                cleanup_ok = deleted.get("deleted") is True and deleted.get("id") == customer_id
                if cleanup_ok:
                    steps.append("customer_deleted")
            except ProbeError:
                cleanup_ok = False
        receipt["cleanup"]["succeeded"] = cleanup_ok
        receipt["ordering"] = steps
        receipt["captured_at"] = datetime.now(timezone.utc).isoformat()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if steps != [
        "account_identity_checked",
        "customer_created",
        "same_request_replayed",
        "customer_retrieved_after_create",
        "customer_deleted",
    ]:
        raise ProbeError("probe ordering receipt did not match the required sequence")
    if not cleanup_ok:
        raise ProbeError("cleanup did not confirm customer deletion")
    return 0


def run_identity_probe(key: str, run_id: str, expected_account_id: str, output: Path) -> int:
    """Read Stripe account identity once; never creates or changes provider data."""
    require_restricted_test_key(key)
    if not run_id or not run_id.isascii() or not run_id.replace("-", "").isalnum():
        raise ProbeError("GITHUB_RUN_ID is missing or malformed")
    if not expected_account_id.startswith("acct_"):
        raise ProbeError("STRIPE_TEST_ACCOUNT_ID is missing or malformed")

    status, account = request_json(key, "GET", "/v1/account")
    if status != 200:
        raise ProbeError("Stripe account read failed")
    assert_account_identity(account)
    matches = account["id"] == expected_account_id

    receipt = {
        "schema": "corelink.stripe-test-mode-identity.v1",
        "issue": 2565,
        "run_id": run_id,
        "mode": "test",
        # Stripe Account has no livemode field. The restricted rk_test_ prefix
        # is checked before the sole GET, so this is evidence about key mode.
        "livemode": False,
        "account_matches_expected": matches,
        "requests": ["GET /v1/account"],
        "provider_mutations": 0,
        "redacted": True,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not matches:
        raise ProbeError("Stripe account did not match the configured test account")
    return 0


def _bounded_list(key: str, path: str, *, max_pages: int = 5) -> list[dict[str, Any]]:
    """Read a complete Stripe collection with a hard page and item bound."""
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    next_path = path
    for _ in range(max_pages):
        _, page = request_json(key, "GET", next_path)
        data = page.get("data")
        has_more = page.get("has_more")
        if not isinstance(data, list) or not isinstance(has_more, bool):
            raise ProbeError("Stripe catalog page shape was incomplete")
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in seen_ids:
                raise ProbeError("Stripe catalog page contained an invalid or repeated item")
            seen_ids.add(item["id"])
            rows.append(item)
        if not has_more:
            return rows
        if not data:
            raise ProbeError("Stripe catalog pagination made no progress")
        cursor = urllib.parse.quote(data[-1]["id"], safe="")
        separator = "&" if "?" in path else "?"
        next_path = f"{path}{separator}starting_after={cursor}"
    raise ProbeError("Stripe catalog exceeds the bounded page limit")


def run_starter_price_probe(key: str, run_id: str, expected_account_id: str, output: Path) -> int:
    """Read account, products, then the exact active Starter monthly price."""
    require_restricted_test_key(key)
    if not run_id or not run_id.isascii() or not run_id.replace("-", "").isalnum():
        raise ProbeError("GITHUB_RUN_ID is missing or malformed")
    if not expected_account_id.startswith("acct_"):
        raise ProbeError("STRIPE_TEST_ACCOUNT_ID is missing or malformed")

    account_status, account = request_json(key, "GET", "/v1/account")
    if account_status != 200:
        raise ProbeError("Stripe account read failed")
    assert_account_identity(account)
    if account.get("id") != expected_account_id:
        raise ProbeError("Stripe account did not match the configured test account")

    products = _bounded_list(key, "/v1/products?active=true&limit=100")
    matches = [p for p in products if p.get("name") == "CoreLink Starter" and p.get("active") is True and p.get("livemode") is False]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str) or not matches[0]["id"].startswith("prod_"):
        raise ProbeError("Stripe test catalog did not contain one exact CoreLink Starter product")
    encoded_product = urllib.parse.quote(matches[0]["id"], safe="")
    prices = _bounded_list(key, f"/v1/prices?product={encoded_product}&active=true&limit=100")
    matching_prices = [
        price for price in prices
        if isinstance(price, dict)
        and price.get("active") is True
        and price.get("livemode") is False
        and price.get("currency") == "usd"
        and price.get("unit_amount") == 4900
        and isinstance(price.get("recurring"), dict)
        and price["recurring"].get("interval") == "month"
        and price["recurring"].get("interval_count") == 1
        and isinstance(price.get("id"), str)
        and price["id"].startswith("price_")
    ]
    if len(matching_prices) != 1:
        raise ProbeError("Stripe test catalog did not contain one active Starter USD 49 monthly price")
    price = matching_prices[0]
    receipt = {
        "schema": "corelink.stripe-starter-test-price.v1",
        "issue": 2565,
        "run_id": run_id,
        "mode": "test",
        "livemode": False,
        "account_matches_expected": True,
        "starter_price": {
            "id": price["id"], "unit_amount": 4900, "currency": "usd",
            "interval": "month", "interval_count": 1,
        },
        "requests": ["GET /v1/account", "GET /v1/products?active=true&limit=100", "GET /v1/prices?product=<exact Starter product>&active=true&limit=100"],
        "provider_mutations": 0,
        "redacted": True,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def contract_check(workflow: Path) -> int:
    text = workflow.read_text(encoding="utf-8")
    missing = [marker for marker in REQUIRED_WORKFLOW_MARKERS if marker not in text]
    forbidden = [marker for marker in FORBIDDEN_WORKFLOW_MARKERS if marker in text]
    if missing or forbidden:
        if missing:
            print("contract missing required markers: " + ", ".join(missing))
        if forbidden:
            print("contract contains forbidden markers: " + ", ".join(forbidden))
        return 1
    print("i1649 Stripe hosted test-mode contract: PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", action="store_true")
    parser.add_argument("--workflow", type=Path, default=Path(".github/workflows/issue-1649-stripe-test-mode.yml"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/issue-1649-stripe-test-mode-receipt.json"))
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--starter-price-readonly", action="store_true")
    args = parser.parse_args(argv)
    if args.contract:
        return contract_check(args.workflow)
    try:
        if args.identity_only and args.starter_price_readonly:
            raise ProbeError("at most one #2565 read-only mode may be selected")
        if args.identity_only:
            if os.environ.get("I2565_CONFIRM") != IDENTITY_CONFIRMATION:
                raise ProbeError("identity-only dispatch confirmation is missing or incorrect")
            return run_identity_probe(
                os.environ.get("STRIPE_SECRET_KEY", ""),
                os.environ.get("GITHUB_RUN_ID", ""),
                os.environ.get("STRIPE_TEST_ACCOUNT_ID", ""),
                args.output,
            )
        if args.starter_price_readonly:
            if os.environ.get("I2565_CONFIRM") != STARTER_PRICE_CONFIRMATION:
                raise ProbeError("Starter-price read-only dispatch confirmation is missing or incorrect")
            return run_starter_price_probe(
                os.environ.get("STRIPE_SECRET_KEY", ""),
                os.environ.get("GITHUB_RUN_ID", ""),
                os.environ.get("STRIPE_TEST_ACCOUNT_ID", ""),
                args.output,
            )
        if os.environ.get("I1649_CONFIRM") != CONFIRMATION:
            raise ProbeError("dispatch confirmation is missing or incorrect")
        return run_probe(
            os.environ.get("STRIPE_SECRET_KEY", ""),
            os.environ.get("GITHUB_RUN_ID", ""),
            args.output,
        )
    except ProbeError as error:
        print(f"i1649 Stripe test-mode evidence: FAIL — {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
