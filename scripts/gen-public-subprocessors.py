#!/usr/bin/env python3
"""gen-public-subprocessors.py — Auto-generate the public sub-processors page
from `specs/_compliance/VENDOR-RISK-REGISTER.md`.

The internal Vendor Risk Register is the **engineering source of truth** for
the public page; `legal/sub-processors.md` is the **authoritative contractual
disclosure** (referenced by the DPA §3) and must be kept consistent with the
register's active customer-data subset in the same PR. This generator enforces
that the customer-facing
`apps/docs/docs/trust/subprocessors.mdx` page can never drift away from the
internal vendor register, satisfying:

- LGPD Art. 39 / Art. 27 §4º (public sub-processor list + 30-day advance
  notice mechanism — see `scripts/subprocessor-change-notify.py`).
- GDPR Art. 28 §2 (controller right to object to processor changes).
- DPA §6.2 contractual commitment to maintain a public list.

# Scope filter (public-visibility)

A row in the internal register is emitted to the public page **only** when:

1. `Cat.` is `C` (Critical) **or** `I` (Important).
   Standard-tier vendors are internal-only by default unless they also share
   customer data (`pii` / `payment` / `audit-logs` containing user content).
2. `Data sharing` is non-empty (a literal `none` value excludes the row,
   e.g. HashiCorp Vault customer-side).

A small set of "internal-only customer-side" vendors (BYOK custodians AWS
KMS / GCP KMS / Azure Key Vault / HashiCorp Vault) are emitted into a
separate **"BYOK key custodians"** info table because they are
sub-processors *to the customer*, not to CoreLink — but customers expect to
see them disclosed regardless.

# Usage

    # Default: write apps/docs/docs/trust/subprocessors.mdx
    python3 scripts/gen-public-subprocessors.py

    # Dry-run: print the rendered MDX to stdout, no file written
    python3 scripts/gen-public-subprocessors.py --dry-run

    # CI drift gate: exit 1 if the existing MDX differs from regenerated
    python3 scripts/gen-public-subprocessors.py --check

# Cross-references

- Compliance matrix: `specs/03_architecture/compliance_matrix.md` §7
  (GDPR Art. 28 + LGPD Art. 27 §4º + Art. 39).
- Runbook: `specs/_runbooks/RB-SUBPROCESSOR-CHANGE.md` (operational flow).
- Workflow: `.github/workflows/subprocessors-sync.yml` (drift gate + auto-PR).
- Notify hook: `scripts/subprocessor-change-notify.py` (30-day grace clock).
"""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTER_PATH = REPO_ROOT / "specs" / "_compliance" / "VENDOR-RISK-REGISTER.md"
OUTPUT_PATH = REPO_ROOT / "apps" / "docs" / "docs" / "trust" / "subprocessors.mdx"

# Standard-tier vendors that share PII/payment/account data and must still
# appear on the public page (rare; documented in runbook §3).
STANDARD_TIER_PUBLIC_OVERRIDES = {"Twilio, Inc. (SendGrid + Twilio SMS)"}

# BYOK-custodian vendors emitted into the separate info table (customer-side;
# CoreLink never sees plaintext key material). Keyed by the `Vendor` column
# value in the register.
BYOK_CUSTODIANS = {
    "Amazon Web Services, Inc.",
    "Google LLC (Google Cloud)",
    "Microsoft Corporation (Azure)",
    "HashiCorp, Inc. (Vault customer-managed)",
}

# Internal-LLM vendors (no customer data; documented separately).
INTERNAL_LLM_VENDORS = {"Anthropic, PBC", "OpenAI, LLC"}

# Vendors completely excluded from public disclosure (out of scope, listed in
# register §4 as exclusions).
PUBLIC_EXCLUDED = {
    "Cybot A/S (Cookiebot)",  # consent vendor; documented under /privacy
}

# The §2 register table describes vendor risk, not storage topology. Keep the
# architecture-sensitive public disclosures explicit here so generation
# cannot resurrect blanket "tenant-pinned" claims: Cloudflare R2/DO state
# differs from shared D1 metadata; Resend stores data in the US even when
# an email-sending region varies.
PUBLIC_REGION_OVERRIDES = {
    "Cloudflare, Inc.": "R2/DO tenant-pinned; D1 control-plane metadata global under SCC/TIA safeguards",
    "Resend, Inc.": "United States (data storage; [sending region may vary](https://resend.com/security/gdpr))",
    "Plausible Insights OÜ (Plausible Analytics)": "European Union (visitor data)",
}

# Vendors that are registered (real client code + reviewed contract posture)
# but are NOT currently receiving customer data: the credential is not
# deployed anywhere, or no code path invokes the client. Kept off the
# "Active sub-processors" table and rendered instead under a separate
# "Contracted-but-not-active" section so they are documented, not silently
# dropped. Source of truth for the reasons: register §4b. Keep this map in
# sync with that section.
INERT_VENDORS = {
    "Drata, Inc.": (
        "`DRATA_API_KEY` is deployed on none of 10 production Workers and is "
        "not a GitHub Actions secret; no binary or workflow invokes the client."
    ),
    "Slack Technologies, LLC (Salesforce)": (
        "`SLACK_SECURITY_WEBHOOK` is unset everywhere; "
        "`.github/workflows/pentest-findings-sync.yml` skips the delivery "
        "step when it is absent — no code consumer is actually wired."
    ),
    "HubSpot, Inc.": (
        "`HUBSPOT_PRIVATE_APP_TOKEN` is unset; the HubSpot client is not a "
        "dependency of `corelink-container` and is never mounted as a route."
    ),
    "Grafana Labs": (
        "`CORELINK_GRAFANA_API_KEY` is deployed on no Worker, so the "
        "`grafana_cloud` OTel exporter variant falls back to `disabled`."
    ),
    "Twilio, Inc. (SendGrid + Twilio SMS)": (
        "`SENDGRID_API_KEY` is unset everywhere and Twilio has no code "
        "consumer at all; the live transactional-email path is Resend, "
        "not Twilio/SendGrid."
    ),
}

# Vendors the owner deferred from the approved launch set (register §4c).
# They stay registered internally but appear on NO public list — neither the
# active table nor the inert table. Keep this map in sync with register §4c.
DEFERRED_VENDORS = {
    "PagerDuty, Inc.": "Deferred by the owner on 2026-10-01 (#1648, #2593).",
}

# Each active sub-processor is engaged on its own standard online terms and
# DPA (B-316 owner re-charter, #2593). These are the vendor's public pages,
# each confirmed to resolve when it was added here; they must match
# `legal/sub-processors.md` (`terms_url` / `dpa_url`), which
# `scripts/verify_b316_pending_vendor_reviews.py` enforces. An active vendor
# without an entry here is a generation error, never an "on request" fallback.
PUBLIC_LEGAL_LINKS = {
    "Cloudflare, Inc.": (
        "https://www.cloudflare.com/terms/",
        "https://www.cloudflare.com/cloudflare-customer-dpa/",
    ),
    "Stripe, Inc.": (
        "https://stripe.com/legal/ssa",
        "https://stripe.com/legal/dpa",
    ),
    "Clerk, Inc.": (
        "https://clerk.com/legal/standard-terms",
        "https://clerk.com/legal/dpa",
    ),
    "GitHub, Inc. (Microsoft Enterprise)": (
        "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
        "https://github.com/customer-terms/github-data-protection-agreement",
    ),
    "Resend, Inc.": (
        "https://resend.com/legal/terms-of-service",
        "https://resend.com/legal/dpa",
    ),
    "Functional Software, Inc. (Sentry)": (
        "https://sentry.io/terms/",
        "https://sentry.io/legal/dpa/",
    ),
    "Plausible Insights OÜ (Plausible Analytics)": (
        "https://plausible.io/terms",
        "https://plausible.io/dpa",
    ),
    "Better Stack, Inc. (BetterStack / Statuspage)": (
        "https://betterstack.com/terms",
        "https://betterstack.com/dpa",
    ),
}


@dataclass(frozen=True)
class VendorRow:
    """One parsed row from the register's section §2 table."""

    number: int
    vendor: str
    service: str
    category: str  # 'C' | 'I' | 'S'
    data_sharing: str
    regulatory_scope: str
    contract: str
    attestation: str
    inherent: str
    cef: str
    residual: str
    cadence: str
    last_review: str
    next_review: str
    owner: str

    @property
    def is_byok_custodian(self) -> bool:
        return self.vendor in BYOK_CUSTODIANS

    @property
    def is_internal_llm(self) -> bool:
        return self.vendor in INTERNAL_LLM_VENDORS

    @property
    def is_public_excluded(self) -> bool:
        return self.vendor in PUBLIC_EXCLUDED

    @property
    def is_inert(self) -> bool:
        return self.vendor in INERT_VENDORS

    @property
    def inert_reason(self) -> str:
        return INERT_VENDORS.get(self.vendor, "")

    @property
    def is_deferred(self) -> bool:
        return self.vendor in DEFERRED_VENDORS

    @property
    def is_customer_data_processor(self) -> bool:
        """True if the vendor actually receives CoreLink-customer data and
        must appear on the public list per GDPR Art. 28 / LGPD Art. 39."""
        if self.is_inert or self.is_deferred:
            return False
        if self.is_byok_custodian or self.is_internal_llm or self.is_public_excluded:
            return False
        if self.data_sharing.strip().lower() == "none":
            return False
        if self.category in ("C", "I"):
            return True
        # Standard tier: only if explicitly overridden (vendor handles user PII).
        return self.vendor in STANDARD_TIER_PUBLIC_OVERRIDES


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

_TABLE_ROW = re.compile(r"^\|\s*(\d+)\s*\|")


def parse_register(register_text: str) -> tuple[list[VendorRow], str]:
    """Parse the register markdown and return (rows, last_review_date).

    The last_review date is taken from the `updated:` frontmatter field;
    register §1 also exposes a 'Baseline date'. We prefer frontmatter
    because it is what generators downstream pin against.
    """
    lines = register_text.splitlines()

    # Frontmatter `updated:`
    updated = "unknown"
    for ln in lines[:30]:
        m = re.match(r'^updated:\s*"?(\d{4}-\d{2}-\d{2})"?\s*$', ln)
        if m:
            updated = m.group(1)
            break

    rows: list[VendorRow] = []
    in_section_2 = False
    for ln in lines:
        if ln.startswith("## 2. Register"):
            in_section_2 = True
            continue
        if in_section_2 and ln.startswith("## "):
            # Left §2.
            break
        if not in_section_2:
            continue
        if not _TABLE_ROW.match(ln):
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        # Expected 15 columns per §2 header.
        if len(cells) < 15:
            continue
        try:
            number = int(cells[0])
        except ValueError:
            continue
        rows.append(
            VendorRow(
                number=number,
                vendor=cells[1],
                service=cells[2],
                category=cells[3],
                data_sharing=cells[4],
                regulatory_scope=cells[5],
                contract=cells[6],
                attestation=cells[7],
                inherent=cells[8],
                cef=cells[9],
                residual=cells[10],
                cadence=cells[11],
                last_review=cells[12],
                next_review=cells[13],
                owner=cells[14],
            )
        )
    return rows, updated


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

# A vendor page that could not be confirmed is published as this literal,
# never as a guessed URL. The B-316 verifier reports any such vendor as open.
LINK_PENDING = "link pending"


class MissingLegalLinks(ValueError):
    """An active sub-processor has no public terms/DPA entry."""


def legal_links(vendor: str) -> tuple[str, str]:
    """Return the vendor's (terms, DPA) table cells. Fails closed: an active
    vendor without an entry for both documents cannot be published."""
    links = PUBLIC_LEGAL_LINKS.get(vendor)
    if links is None or len(links) != 2:
        raise MissingLegalLinks(
            f"active sub-processor {vendor!r} has no public terms and DPA links "
            "in PUBLIC_LEGAL_LINKS"
        )
    cells = []
    for label, url in zip(("Terms", "DPA"), links):
        if url == LINK_PENDING:
            cells.append(LINK_PENDING)
        elif url.startswith("https://"):
            cells.append(f"[{label}]({url})")
        else:
            raise MissingLegalLinks(
                f"active sub-processor {vendor!r} has a {label} link that is "
                f"neither https:// nor {LINK_PENDING!r}: {url!r}"
            )
    return cells[0], cells[1]


def shorten_region(scope: str, data_sharing: str, vendor: str | None = None) -> str:
    """Derive a public-facing region string. The register doesn't carry a
    dedicated region column for §2, so we encode 'Multi-region (per tenant
    primary_region pin)' as the default, with a Brazil-residency hint when
    LGPD scope is implied by the data-sharing class. Architecture-sensitive
    disclosures use an explicit vendor override above."""
    if vendor in PUBLIC_REGION_OVERRIDES:
        return PUBLIC_REGION_OVERRIDES[vendor]
    if "encrypted-blobs" in data_sharing or "pii" in data_sharing:
        return "Multi-region (per tenant `primary_region` pin)"
    return "US / EU (selectable)"


def shorten_service(service: str) -> str:
    """Trim the register's long service descriptions to a public summary."""
    # Cut at the first em-dash or " — " separator if it includes editorial.
    parts = re.split(r"\s+[—–-]\s+", service, maxsplit=1)
    public = parts[0].strip()
    # Final length cap.
    if len(public) > 90:
        public = public[:87].rstrip() + "..."
    return public


def shorten_data_sharing(ds: str) -> str:
    """Public-facing data-class label."""
    tokens = [t.strip() for t in ds.split("+")]
    pretty = ", ".join(tokens)
    return pretty


def render_active_table(rows: Iterable[VendorRow]) -> str:
    out = [
        "| # | Vendor | Service to CoreLink | Customer-data class | Regions | Terms | DPA |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    n = 0
    for r in rows:
        n += 1
        terms, dpa = legal_links(r.vendor)
        out.append(
            f"| {n} | **{r.vendor}** | {shorten_service(r.service)} | "
            f"{shorten_data_sharing(r.data_sharing)} | "
            f"{shorten_region(r.regulatory_scope, r.data_sharing, r.vendor)} | "
            f"{terms} | {dpa} |"
        )
    return "\n".join(out)


def render_byok_table(rows: Iterable[VendorRow]) -> str:
    out = [
        "| Vendor | Service | Role |",
        "| --- | --- | --- |",
    ]
    for r in rows:
        short = shorten_service(r.service)
        out.append(f"| **{r.vendor}** | {short} | Customer-controlled CMK (BYOK option) |")
    return "\n".join(out)


def render_internal_llm_table(rows: Iterable[VendorRow]) -> str:
    out = [
        "| Vendor | Service | Used for |",
        "| --- | --- | --- |",
    ]
    for r in rows:
        out.append(f"| {r.vendor} | {shorten_service(r.service)} | Internal CoreLink eng / ops tooling |")
    return "\n".join(out)


def render_inert_table(rows: Iterable[VendorRow]) -> str:
    out = [
        "| Vendor | Service (as integrated) | Why it is not active today |",
        "| --- | --- | --- |",
    ]
    for r in rows:
        out.append(
            f"| **{r.vendor}** | {shorten_service(r.service)} | {r.inert_reason} |"
        )
    return "\n".join(out)


MDX_TEMPLATE = '''---
title: "Sub-processors"
slug: "/trust/subprocessors"
description: "Public list of CoreLink sub-processors — vendor, service, region, links to each vendor's terms and DPA, and the 30-day advance-notice mechanism for changes."
draft: false
generator: "scripts/gen-public-subprocessors.py"
source: "specs/_compliance/VENDOR-RISK-REGISTER.md"
cross_functional_review: TBD
pending_signoff:
  - "Security Lead"
  - "Legal"
  - "DPO"
sources:
  - "specs/_compliance/VENDOR-RISK-REGISTER.md"
  - "legal/sub-processors.md"
last_updated: "{last_updated}"
---

{{/* AUTO-GENERATED FILE — DO NOT EDIT BY HAND.
     Source of truth: specs/_compliance/VENDOR-RISK-REGISTER.md
     Generator:       scripts/gen-public-subprocessors.py
     CI drift gate:   .github/workflows/subprocessors-sync.yml
     30-day notify:   scripts/subprocessor-change-notify.py
*/}}

# Sub-processors

CoreLink uses a small set of carefully selected sub-processors to operate
the service. This page is the **public list** maintained per GDPR Art. 28
§2 and LGPD Art. 39 + Art. 27 §4º. It is a subset of our internal
Vendor Risk Register
({total_vendors} vendors total) — only those who *actually process customer
personal data on CoreLink's behalf today* appear in the **Active
sub-processors** table ({active_count} of them). A handful of registered
vendors have a built integration but no live credential or code path yet —
see "Contracted-but-not-active" below; they are not sub-processors until
that changes.

> **Last refreshed:** {last_updated}. This page is **auto-generated** from
> the internal vendor register on every change; see
> `.github/workflows/subprocessors-sync.yml` for the drift gate.

## Notice of changes (30-day grace)

Per our DPA (`legal/dpa/v1.0.0` §6) and LGPD Art. 27 §4º + GDPR Art. 28 §2,
we will give **at least 30 calendar days' written notice** before adding or
replacing a sub-processor that processes customer personal data.

Subscribe to change notices:

- **Email digest** — register a `subprocessor-changes@` distribution
  address inside your tenant settings. We send a digest the moment a
  change is queued, and a reminder 7 days before the change takes effect.
- **Status page** — [hugrl.betteruptime.com](https://hugrl.betteruptime.com)
  carries service state. It is **not** a sub-processor notification channel:
  subscriptions are switched off on that page, so email, SMS, RSS and webhook
  delivery do not exist there. Earlier versions of this page said they did.
- **RSS feed for sub-processor changes** — not available. A feed on the
  never-provisioned dotted `corelink.` brand subdomain was listed here as
  "post-GA"; that hostname does not resolve and no such feed was ever
  published.

If you object to a proposed sub-processor change you have the rights set
out in DPA §6.4 (objection window, escalation, termination-for-cause if
unresolved).

## Active sub-processors

Each sub-processor below is engaged on that vendor's own standard terms and
data processing agreement (DPA), linked in the table. CoreLink accepted them
online when it created each account; the acceptance dates were not recorded,
so this page shows none.

{active_table}

## Contracted-but-not-active / integration built, not enabled

The vendors below are registered internally (reviewed contract posture,
real client code lives in the codebase) but are **not** currently
sub-processors: no production credential is deployed for them, or no code
path actually invokes the client, so no customer data flows to them today.
They are listed here — rather than omitted — so the disclosure stays
truthful if one of them is switched on later. Each is re-verified whenever
the register is updated (`specs/_compliance/VENDOR-RISK-REGISTER.md` §4b).

{inert_table}

### BYOK key custodians (customer-side; not sub-processors)

The four KMS providers below are listed for completeness. CoreLink does
**not** process customer key material — keys remain inside the customer's
KMS account at all times. These providers are sub-processors *to you*, not
to us. CoreLink only holds wrapped DEKs.

{byok_table}

See [BYOK customer-managed keys](/security/byok) for the full provider
matrix and key-flow diagram.

### Internal LLM tooling (no customer data)

The providers below are used by CoreLink **internally** for engineering
and operations tooling. **No customer data is sent to either provider.**
Internal prompts are routed through enterprise zero-retention APIs.

{internal_llm_table}

If your DPO requires these to be listed as sub-processors despite the
zero-retention guarantee and no-customer-data scope, please raise it via
`privacy@humangr.com` and we will update the table on a per-tenant basis.

## Out-of-scope (referenced for completeness)

The following appear in our internal registers but are **not**
sub-processors:

- **Sigstore (Linux Foundation)** — the former Worker OCI signing workflow was
  removed on **2026-09-08** after review established that it never executed, so
  no Fulcio certificate or Rekor entry was issued for that lane. The separate
  release-SLSA and CAS signing paths remain independently gated.
  Current release-SLSA, CAS, and TSA paths send only CoreLink-owned
  artifact/signing metadata to Sigstore; no customer-data path is wired.
  The separate transparency-log seam is not a live transport; any future
  pseudonymous-tenant use requires a new Legal/DPO review. Sigstore is not a
  customer-data sub-processor in the current register; the separate GDPR transfer
  table remains subject to Legal/DPO review.
- **Self-hosted Dependency-Track** — operated by CoreLink; no third party.
- **Per-customer HashiCorp Vault instances** — customer-side infrastructure
  outside CoreLink's processor relationship.

## Auditing this list

The internal sub-processor file (with the full DPA matrix and termination
clauses) is at
held internally and available on request from support@humangr.com.
The full vendor risk register ({total_vendors} vendors with inherent risk scoring,
control-effectiveness factors, and quarterly review cadence) is at
held internally and available on request from support@humangr.com.

## Change management

The operational runbook is held internally.
The 30-day customer-broadcast pipeline is implemented by
`scripts/subprocessor-change-notify.py` and the
`corelink-privacy-sub-processor-emit` crate (CloudEvents
`corelink.privacy.subprocessor.notify_required`).

## Related

- [Trust Center overview](./)
- [Compliance](./compliance)
- [Data handling](./data-handling)
- [Incident response](./incident-response)
'''


def render_mdx(rows: list[VendorRow], last_updated: str) -> str:
    active = [r for r in rows if r.is_customer_data_processor]
    byok = [r for r in rows if r.is_byok_custodian]
    llm = [r for r in rows if r.is_internal_llm]
    inert = [r for r in rows if r.is_inert]
    return MDX_TEMPLATE.format(
        last_updated=last_updated,
        total_vendors=len(rows),
        active_count=len(active),
        active_table=render_active_table(active),
        inert_table=render_inert_table(inert),
        byok_table=render_byok_table(byok),
        internal_llm_table=render_internal_llm_table(llm),
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--register", type=pathlib.Path, default=REGISTER_PATH,
                        help="Path to VENDOR-RISK-REGISTER.md (default: specs/_compliance/VENDOR-RISK-REGISTER.md).")
    parser.add_argument("--out", type=pathlib.Path, default=OUTPUT_PATH,
                        help="Path to write the generated MDX (default: apps/docs/docs/trust/subprocessors.mdx).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the rendered MDX to stdout; do not write.")
    parser.add_argument("--check", action="store_true",
                        help="Exit 1 if the regenerated MDX differs from the file on disk (CI drift gate).")
    args = parser.parse_args(argv)

    if not args.register.exists():
        print(f"error: register not found at {args.register}", file=sys.stderr)
        return 2

    text = args.register.read_text(encoding="utf-8")
    rows, updated = parse_register(text)
    if not rows:
        print("error: parsed 0 vendor rows from register §2", file=sys.stderr)
        return 2

    try:
        mdx = render_mdx(rows, updated)
    except MissingLegalLinks as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        # Print compact summary at the bottom for human eyes.
        sys.stdout.write(mdx)
        print(
            f"\n--- dry-run: {len(rows)} register rows; "
            f"{sum(1 for r in rows if r.is_customer_data_processor)} active; "
            f"{sum(1 for r in rows if r.is_inert)} inert; "
            f"{sum(1 for r in rows if r.is_byok_custodian)} BYOK; "
            f"{sum(1 for r in rows if r.is_internal_llm)} internal-LLM ---",
            file=sys.stderr,
        )
        return 0

    if args.check:
        if not args.out.exists():
            print(f"error: --check but {args.out} does not exist", file=sys.stderr)
            return 1
        existing = args.out.read_text(encoding="utf-8")
        if existing != mdx:
            print("error: subprocessors.mdx is stale relative to VENDOR-RISK-REGISTER.md", file=sys.stderr)
            print("       run: python3 scripts/gen-public-subprocessors.py", file=sys.stderr)
            return 1
        print("ok: subprocessors.mdx is in sync with VENDOR-RISK-REGISTER.md")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(mdx, encoding="utf-8")
    print(f"wrote: {args.out} ({len(mdx)} bytes; last_updated={updated})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
