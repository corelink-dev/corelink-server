#!/usr/bin/env python3
"""Check that BACKLOG.md still agrees with reality.

WHY THIS EXISTS
---------------
On 2026-08-23 a day of planning was built on notes that had quietly gone stale.
Three items recorded as open had in fact shipped days earlier; one cited a count
of hosted CI lanes that no longer matched either the file count or the job count.
Nothing was dishonest — the notes were simply written once and never re-checked,
and no mechanism existed that could notice.

So a list is not enough. The list has to be able to disagree with the world and
say so out loud. Every item in BACKLOG.md therefore carries its own verification
declaration. This gate validates the declaration and its trusted-base transition,
but deliberately does not execute it: a PR is an untrusted data source.

An item that genuinely cannot be checked by a command declares `verify: manual`
and must carry a fresh `last-verified` date. Those decay: past `max-age-days`
they go STALE and fail the gate. That is the whole point — an unverifiable claim
is allowed, but it is not allowed to sit unchallenged forever, which is exactly
what happened to the notes this replaces.

USAGE
-----
    python3 scripts/backlog_verify.py            # check every item
    python3 scripts/backlog_verify.py --id B-003 # check one
    python3 scripts/backlog_verify.py --format json
    python3 scripts/backlog_verify.py --candidate-file PR/BACKLOG.md \
        --trusted-file BASE/BACKLOG.md --candidate-root PR --trusted-root BASE

Exit code is 0 only when every item is CONFIRMED. Anything else is a red gate.
Candidate mode validates the PR register, dense-ID population, allowed field
transitions, and trusted control closure but never executes candidate
`verify:` strings or candidate verifier code.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKLOG_PATH = REPO_ROOT / "BACKLOG.md"

# A fenced ```backlog block is the machine-readable half of an item; the prose
# around it is the human half. One file, one source — no generated mirror to
# drift out of sync (this repo has been bitten by hand-editing a generated file).
BLOCK_RE = re.compile(r"^```backlog\n(.*?)^```", re.MULTILINE | re.DOTALL)

# The prose half of an item is titled `### B-0NN — …`, and every reference from
# outside this file — a CHANGELOG entry, a PR body, a runbook — cites that
# heading. The block's `id:` is what the gate reads. Nothing made the two agree,
# and on 2026-08-24 they silently disagreed: the forked-partitions item was
# headed B-026 while its block declared `id: B-024`, and the Turborepo item held
# the mirror image. Both ids were unique, so the duplicate check below was
# content; the register simply pointed the wrong way for anyone following an id.
HEADING_RE = re.compile(r"^### (B-\d+)\b", re.MULTILINE)

REQUIRED_FIELDS = ("id", "repo", "owner", "status", "verify", "verify-means", "last-verified")
VALID_STATUS = ("open", "done", "parked")
VALID_OWNER = ("tl", "owner")
DEFAULT_MAX_AGE_DAYS = 14
# Candidate trees are data. Semantic execution is available only through the
# explicit trusted-main workflow mode; candidate mode never executes a verifier.
MAX_BACKLOG_BYTES = 2_000_000
VERIFY_TIMEOUT_S = 120
# Only these BASE-frozen declarations may receive the job's short-lived alert
# token. Keep the command as well as the ID in the allowlist: a changed shell
# string must not turn a Dependabot ID into an arbitrary credentialed command.
AUTH_VERIFY_COMMANDS = {
    "B-028": "python3 scripts/verify_b028_dependabot.py",
    "B-373": "python3 scripts/verify_b373_dependabot.py --alerts-file docs/security/b373-dependabot-census-2026-09-09.json",
}
# The sequential B-register ends at B-373. B-1630 is the single historical
# external-issue identity: PR #1945 recorded GitHub issue #1630 under that key,
# and immutable V0004 binds it in history_changed_ids and history_transitions
# (commit 08b1618d3d6ce922043e8cd064d5e58a50990f63). It is not a missing run of
# 1,256 canonical B-items. Keep this exact identity required and separate from
# the allocator sequence; every other unrecognized gap remains fatal.
HISTORICAL_EXTERNAL_ISSUE_IDS = {"B-1630": 1630}
# This prefix is the delivered canonical allocator population. Never lower it;
# later allocated B-IDs extend the dense sequence and retirement keeps the row.
CANONICAL_B_ID_PREFIX_MAX = 373
IMMUTABLE_ITEM_FIELDS = frozenset({
    "id", "repo", "verify", "action-packet", "source-document",
    "source-locator", "finding-title", "problem", "evidence", "acceptance",
    "next-action",
})
B154_LEGACY_VERIFY_SHA256 = "39b0307a1a4451c90fb22fe9a37cfbd858485d38e6361e6c3d15bce1d1f4beac"
B154_SPRINT3_VERIFY_SHA256 = "a6045afb801b3b6a61ff09d97b6e77ba5fa4f7e1c4f9ed0fde8554957484264e"
ALLOWED_TRANSITION_FIELDS = frozenset({"status", "owner", "last-verified", "verify-means"})

# C0 is a one-time, separately admitted repair to the B-057 verifier.  The
# pull_request_target lane reads this policy from the immutable BASE checkout;
# it inspects candidate bytes but never imports, parses, or executes them.
B057_C0_PREIMAGES = {
    "scripts/verify_b057_sli.py": "5db63c2981c9f8278e1df9141f1eb5514712d964210c42cd9e4f451cfb78a82b",
    "tests/test_b057_sli_contract.py": "e50ffb0b8a78d9050656d79527fbb575be646530538a44b4315f4e334aead90c",
}
B057_C0_TARGETS = {
    "scripts/verify_b057_sli.py": "cc19cdd2501c8eddbb99feffcdf7eb6466a5f9fe31bf3fb71d7d7b887918de2e",
    "tests/test_b057_sli_contract.py": "77c2ebfb5842e007ca096e2bcbbccb9fb4e1a8c51a13aa58ecfd2c0622fc7421",
    ".github/workflows/issue-2414-b057-sli.yml": "feed9cf65ce17f8a11427db710ff0dbae26ad185ca38c1effeffdb94bfc09084",
}

# One-time #2585 load-admission client transition. The trusted BASE verifier
# admits this bundle only as a complete byte-pinned tree transition. Candidate
# files remain data: this code reads their bytes and never imports or runs them.
# ``None`` is an intentionally frozen absent preimage for files introduced by
# this delivery.
B029_LOAD_GATE_PREIMAGES: dict[str, str | None] = {
    ".github/workflows/endurance-2h-nightly.yml": "f4739df34adc52669f3ae95f69afc9dc2d8d6d435804c90249e8aa0313f0d3d0",
    ".github/workflows/load-test-nightly.yml": "353f8357b95b4f0b2d6223b402c291eced64c6a47131495747cbbb949b84fb90",
    "scripts/staging_load_lifecycle_auth.py": None,
    "scripts/verify_b029_load_gate.py": "8621cab412ac9acc4ae49449e14bfd768f0de8e2cec8613d08d47487040653be",
    "scripts/verify_i1687_endurance_lane.py": "95a8c6c71bdefb6327d5fdfc3c839b6218c8539e27c05f5aa911b45453c66c0a",
    "tests/load/k6/byok-revoke-stampede.js": "715a284bc9c7a297271e4145a04c3b3e27510a7d6cc848c901cff9255d154695",
    "tests/load/k6/cas-write-read.js": "d479b7ab832ba1fedba6e676644871a730c13d84eea5e15b9e6412f630bfb2e7",
    "tests/load/k6/dsr-api.js": "2bea908cb7eef957c15b18ed7b2d990aa3ebe67b3b9865bb9d27e5d7b8af5d11",
    "tests/load/k6/lib/staging_load_admission.js": None,
    "tests/load/k6/scenarios/endurance-24h.js": "0bee2d15fb0ce2c519de0020a5e4d00f2405f00d22ab9eb5599a900d74b58de8",
    "tests/load/k6/signup-orchestration.js": "e99cbb84a20bd21403a3f95cf40c9c531ccc6d33d2c4701aa4f71c3316ec3fad",
    "tests/load/k6/stripe-webhook-burst.js": "06a14722634ed0c9e5686b04df24fd127f0061e37f51f1b85e03b403aa3d8033",
    "tests/test_b029_load_gate.py": "4402a59616b002f69b995ff9c4c2c50272581e93dfc55832b3be6f5d82c2bca5",
    "tests/test_staging_load_lifecycle_auth.py": None,
}
B029_LOAD_GATE_TARGETS = {
    ".github/workflows/endurance-2h-nightly.yml": "3ceeb7551fb510d04bf02ee217d235b40116468d4eeff329e2d8aaac908a67df",
    ".github/workflows/load-test-nightly.yml": "bba2ef8825eb641be4e0db5faeb4cfa71739d863f9f5104801dcd51a0dbecd0e",
    "scripts/staging_load_lifecycle_auth.py": "0b5c58f99f856afcc48207a3d13f0b1ee30f27fdf5d05491a494ea5215a4040c",
    "scripts/verify_b029_load_gate.py": "e6771e4379d5a9673739fd9ffc4bc0fdfd65a9ede431ca4a4039d1e051cc7393",
    "scripts/verify_i1687_endurance_lane.py": "b81c8db0aa3bfe5f298d3f5c9fe211c91f88817b316ae598b4a1aa51a3ccb44f",
    "tests/load/k6/byok-revoke-stampede.js": "19bc5eb99bafc1a7d2605b66c9cf03fdf41d42eb52046d5c7b2c47bc8da9b94b",
    "tests/load/k6/cas-write-read.js": "a6f9c19471c077dbf217de164fabe778801453a53a6ebb3582319800ec6ba92e",
    "tests/load/k6/dsr-api.js": "35c3106460e5ee17414c8afc2baf00a1ac59e32e07512363cb1dc5acbee32dfc",
    "tests/load/k6/lib/staging_load_admission.js": "1065b994de05236332112023cdd89727777239cf15555e7122e58f0c516fc64a",
    "tests/load/k6/scenarios/endurance-24h.js": "b5acaf4bfb6e366e91f0b332af3bbe453bea7c31599d01319ad2bd157b583d33",
    "tests/load/k6/signup-orchestration.js": "0b006dba9c2465420389c3ff71e70bfc4815ca23ca241088d6e3176ae093449a",
    "tests/load/k6/stripe-webhook-burst.js": "e103615d94e559db751c0dad6d8c56692d0a9d79edb6e105d6abaedaf033b88d",
    "tests/test_b029_load_gate.py": "db521b18c5bea32858dbe29965010f543a4ca8394f68357e7a55e6cc0f6134bf",
    "tests/test_staging_load_lifecycle_auth.py": "7f64f668a5eafb38b34dd46fd8b8b1b977363dc9126dc8d21b923ccd746fc399",
}
B029_LOAD_GATE_TARGET_MODES = {
    path: 0o644 for path in B029_LOAD_GATE_TARGETS
}
B029_LOAD_GATE_TARGET_MODES["scripts/verify_b029_load_gate.py"] = 0o755

# One-time #1700 Custom Domain transition. This admits only the exact three
# trusted control edits plus their exact unprovisioned topology input. The
# BASE copy of this file checks bytes only; it never imports candidate code.
STAGING_CUSTOM_DOMAIN_PREIMAGES = {
    "scripts/verify_b072_receiver.py": "8acce3d50dbe4ad9a3df24d33e56828203a51510eab3fcfa3bff2b46c0b27a69",
    "scripts/verify_staging_topology_contract.py": "ba7abe9d5887269a69fcf2a8cfcec6d60d579ecd53f72a3ec6e9cc74250c677b",
    "tests/test_verify_staging_topology_contract.py": "97d1f75eb3608dbf71cc0506922ddd7b88b92f7f8f0812f01d392ee535be8103",
    "infra/staging/topology.json": "5156d6578d662020777a7e98cb1b91a181c6b4536afbd2c4a9498be06f57357e",
}
STAGING_CUSTOM_DOMAIN_TARGETS = {
    "scripts/verify_b072_receiver.py": "3bfa5d552f9d588c424c25a2cb7654dd840f77279cd89ff249f594c052674ecc",
    "scripts/verify_staging_topology_contract.py": "18a70767b543a5ea8cadda94a216c068de41a8a294182ef255067126a9fa0e27",
    "tests/test_verify_staging_topology_contract.py": "bba450e2410791916e7ec80600c7968be86152a21526d02cf1dddf57f2ae909f",
    "infra/staging/topology.json": "586665e34c11bf91a34fb83247fdbafec9fdfb8e7a336ba4da6f5bda8266dd99",
}
# #1652 full-delivery pins from source head 8d193a15. The receiver verifier
# changes only with the complete 17-path delivery.
I1652_DELIVERY_PINS: dict[str, tuple[tuple[int, str] | None, tuple[int, str] | None]] = {
    ".github/workflows/issue-1652-b072-evidence.yml": ((0o644, "7902fc5211d88c461554981f635dbbd7948ea358420facb722cd1f06c215aa43"), (0o644, "95f1644aea80a18f5ca4aaffbf1e66c2beecf4326cad465ee55188e4dc6618f1")),
    ".github/workflows/synthetic-pager-worker-deploy.yml": ((0o644, "3ab28f10f0bdda409be1790b63b18f8c45c2290ac1f5534c872981766af2dace"), (0o644, "3c011375a5477d05fa4211ee9aace75ab253e8c869380e45b1d724e849962c75")),
    "apps/synthetic-pager-worker/src/contract.ts": ((0o644, "fb4a25030f5ab409cd6af58e33bc7aac64f812a80b06365118d66f4af3668ee2"), (0o644, "db25b1a27776180a63f4e52f232bd36d1d20dffc0861732cfef534c98c9439bb")),
    "apps/synthetic-pager-worker/src/index.ts": ((0o644, "d1951170489f1dc4d7d794cf993371a912c819ba4b068b1b07f494c9c763f173"), (0o644, "e4bab682267f9409d1546b38c660be6a601a077268c1b4cb0c80f768d98cca97")),
    "apps/synthetic-pager-worker/tests/receiver.test.ts": ((0o644, "4158b83f17cd34f37357a002c54e73d5a199c86b49f95d110a82d6eeab29df56"), (0o644, "28964c621797a4d87155c0c365badc6eacedc14abac8f30bf001727848f5d5f3")),
    "changelog.d/1652-b072-one-shot.md": (None, (0o644, "22f60747b272725bcf9d71a32a7e8899970fda47538bffcd8a8b890ca4d4d2db")),
    "docs/internal/b072-scheduled-drills-owner-packet.md": ((0o644, "27b8ada7c3c84706c82173b9092c1464952ade6419688700fcc9dd1de75ce2fd"), (0o644, "54e33cb943bb961324c3babf2c35eed21acb93b839dbf1616dd54260b7faaa45")),
    "migrations/d1/0153_b072_one_shot_fence.sql": (None, (0o644, "8ac96c331cb5b44a9f0376ae5c257fc23a783e1fb51ec2415842101da57a67a9")),
    "scripts/issue_1652_b072_operator.py": (None, (0o644, "0fb4752246e6036e7af9fc8e62d2b9bae7764aacfc219be7148699ae0b35062c")),
    "scripts/test_b072_receiver_mutations.py": ((0o644, "86c3f91858694327126c5db48af9f151fb5b4603d461634c12dc5ccebaf26297"), (0o644, "761de6a4375d9dbeb74e706b3f2d32c5beb74432178b06f4fe2281d14e8e659a")),
    "scripts/test_issue_1652_b072_operator.py": (None, (0o644, "74678eb4b42fef3567cac2963d9462da28904964abbcf22372535ce6c6ad0828")),
    "scripts/test_issue_1652_b072_workflow.py": (None, (0o644, "40501fd987ad3994e32ab58e7fe7269ad8248a537e41d1080f820d8623bd63dc")),
    "scripts/verify_b072_receiver.py": ((0o644, "3bfa5d552f9d588c424c25a2cb7654dd840f77279cd89ff249f594c052674ecc"), (0o644, "650a2b0ed7d999e7698182f29fa3d2e6f98a252d8e46eac215b80f34b8549d55")),
    "worker/src/b072_one_shot.ts": (None, (0o644, "0083f893f91aee58f59bb3f290c95e17cba19bc22a3d06c42f0d07f166c56e4c")),
    "worker/src/index_schedule.ts": ((0o644, "cce9a2f88923fed6f7c6eddb82a6f9145767b9c77617721de2e634961dea3e3d"), (0o644, "390a6458dbcc7bc825105dc5373b017e3044dd41085c4d775cafe6b02913cfdb")),
    "worker/tests/b072_one_shot.test.ts": (None, (0o644, "ecd19f939fca175b5b29bbb187e73e0ac05a4b582f74f491b9f14fcb4517598c")),
    "worker/tests/scheduled_drills.test.ts": ((0o644, "7ff36a7bb7bf65fe58c3013b80b397f5432d8dd8d90c87dd2443db171be1b5a5"), (0o644, "d325b36d1bdca9f96e691a917a912033818db9b9e29ae7e56a6a1ef35ceebb90")),
}

STAGING_CUSTOM_DOMAIN_DELIVERY_PATHS = frozenset({
    ".github/workflows/issue-1700-staging-custom-domain.yml",
    "docs/campaigns/remediation/wp150-workflow-ownership.md",
    "infra/staging/README.md",
    "scripts/plan_staging_provider.py",
    "scripts/render_staging_wrangler.py",
    "scripts/staging_bootstrap_provider.py",
    "scripts/staging_custom_domain.py",
    "scripts/verify_staging_provider_preflight.py",
    "scripts/verify_staging_target.py",
    "tests/test_render_staging_wrangler.py",
    "tests/test_staging_bootstrap_provider.py",
    "tests/test_staging_custom_domain.py",
    "tests/test_verify_staging_target.py",
})

# One-time #1700 Container/D1 binding-proxy delivery. Every candidate path is
# byte- and mode-pinned against this exact transition. The BASE checker reads
# these entries as data and never imports or executes candidate code.
STAGING_D1_BINDING_PROXY_PREIMAGES: dict[str, tuple[int, str] | None] = {
    '.github/workflows/issue-1700-container-staging-deploy.yml': (420, '9970b7ae60d825c8d5f5deaa1e82a84a58f96352312f9f8faa699621ccc38e76'),
    '.github/workflows/staging-quarantine-apply.yml': (420, '11937887c2dc88942e0c35e7b3824c9835c0f484e6ae1f0fdd8de4066a83c9da'),
    'crates/corelink-container/src/main.rs': (420, 'f1150ff53657179a26373bea5d009a732d1a9bccea8c820936858c460ae4b46c'),
    'crates/corelink-container/src/routes.rs': (420, 'd1909aefc3f99b981eebb10d018b8fdb21ce739f05c834257f7412c85d88a7ef'),
    'crates/corelink-container/src/routes/staging_d1_binding_probe.rs': None,
    'crates/corelink-container/src/storage.rs': (420, '89bd546ac229e17454dc27457e306662f8dbc3babab440c889ab2c485e9bf361'),
    'crates/corelink-container/src/storage/d1_http.rs': (420, '57df01654b44a12c57663d4543b1290125c87346e014e3b8210624a2d9cb6dd2'),
    'docs/internal/secrets-checklist.md': (420, '24d0e59ee398a92a1bfd037daf4482d619129118e6236c1bea974b76b4ef3b22'),
    'infra/staging/README.md': (420, '4689c4a43dda1d69ecbb60cdc8a65b4e2f2e5e017f5783f06f567d70ff8ab0ea'),
    'infra/staging/topology.json': (420, '586665e34c11bf91a34fb83247fdbafec9fdfb8e7a336ba4da6f5bda8266dd99'),
    'pnpm-lock.yaml': (420, 'b2b79225204fbce1b33e64f03987f0b894b1f7a187daef51078411d6285e0278'),
    'scripts/issue_1700_runtime_probe.mjs': None,
    'scripts/staging_bootstrap_provider.py': (420, '4684063fe7acbbc781ea177e029ea6d6ac7b7d4b906a814cf0c41b67eda8abf4'),
    'scripts/tests/issue_1700_runtime_probe.test.mjs': None,
    'scripts/verify_staging_provider_preflight.py': (420, '30c5e7fca9151d5a5147cc37b0ea49ced0100bd0dce5392eec4faa9e53afbfe0'),
    'scripts/verify_staging_topology_contract.py': (420, '18a70767b543a5ea8cadda94a216c068de41a8a294182ef255067126a9fa0e27'),
    'tests/test_issue_1700_route_inventory.py': (420, '216a00df6c5b67d78c90d5a9d1c78043a56985c230d7ede72e0270186eb6ef56'),
    'tests/test_staging_bootstrap_provider.py': (420, '189efec0ef4b61b5a5efbea105ad56c210196c4b051fc9c1119645ec3758f5f7'),
    'tests/test_staging_custom_domain.py': (420, 'ebca7d9b0e46763cac025dfc79bda65291d1e77f2132176527f28c9f8238e3a2'),
    'tests/test_staging_quarantine_apply_contract.py': (420, 'ceb689591b8a5e380ce34f91bc598262c8f9051aaa84b7e0d05c088f194dffe6'),
    'worker/package.json': (420, '7b20dc56684526ad90f3b5998aa995f41b750e304397714ab34b6ece2e162348'),
    'worker/src/durable_object.ts': (420, '5be00eb88931adf4b2789c15ff3e715407dcd3e67e176de370c0922b175356a7'),
    'worker/src/durable_object_start.ts': (420, '26d78fadfb89ca7327f698696ec15c53c455823f3f2c1ae3c282af16b4cab244'),
    'worker/src/index.ts': (420, '627c97d894c9d02521e279b1721a9b0a4346ab1050a586706321b94931fbee8c'),
    'worker/src/index_schedule.ts': (420, '1dab69b8d54f53129631f2135a23ade52fa2772c384e785f4e356c035e4888da'),
    'worker/src/lib/devenv_cleanup_route.ts': (420, 'f039ca514d423ef4acdd722e5561482efcb99c4fab99d49ab0e8374e36c6cf71'),
    'worker/src/lib/runner_credential_routes.ts': (420, '0830e3843c4b252efc3c0842e87441fe050ff7e9372ebd99879482eb898a1715'),
    'worker/src/pat_issue_rate_limit.ts': (420, '139d80e9037eba47e5712e6d80110e70fc7360e61f0c5ce2b7529e80146485a4'),
    'worker/src/staging_d1_binding_proxy.ts': None,
    'worker/src/staging_d1_binding_proxy_entrypoint.ts': None,
    'worker/src/staging_runtime_d1_probe.ts': None,
    'worker/tests/cloudflare_workers_node_stub.ts': None,
    'worker/tests/durable_object.test.ts': (420, 'ae533b3614615a5ca908922af6082f8e504986947f4db22d52b6dbe65018a669'),
    'worker/tests/staging_d1_binding_proxy.test.ts': None,
    'worker/tests/staging_d1_binding_start_gate.test.ts': None,
    'worker/tests/staging_runtime_d1_probe.test.ts': None,
    'worker/vitest.config.mts': (420, '0ee4c1a03685a300e6ead7720901ab0ae9103da8ffb359a34c5b10e7d3e46a44'),
}

STAGING_D1_BINDING_PROXY_TARGETS: dict[str, tuple[int, str] | None] = {
    '.github/workflows/issue-1700-container-staging-deploy.yml': (420, 'c31908be992a6727e124e9b87160708af44fa2f1a042be2bd142b930abf15199'),
    '.github/workflows/staging-quarantine-apply.yml': (420, '24d901a61e2b45af71fc5ec0632455956690725f8f05f9959c0baf213deb1594'),
    'crates/corelink-container/src/main.rs': (420, '44c28a9a8387212b156ce05aa65918b0c34454453d7fcd85e79fd29f9a5518db'),
    'crates/corelink-container/src/routes.rs': (420, '04a84d7be655fd25ee6d05d1b5c598c169be1aae381a255533ffeda0aad1ec2f'),
    'crates/corelink-container/src/routes/staging_d1_binding_probe.rs': (420, '237d0679a4d7b63c7ad1f9634d74fbd029f62e38e8ad3aa8982e014204d032ff'),
    'crates/corelink-container/src/storage.rs': (420, 'ee16e0155fae72ddfe01fedb4b7d29bff087467b2a23c42c830a42f3aeb9b78e'),
    'crates/corelink-container/src/storage/d1_http.rs': (420, '258e068b53867a06a1b97ca9991b9ce616322af17ccfb0004d12b5d5962e33d5'),
    'docs/internal/secrets-checklist.md': (420, '6157f5653e1a4ebea7be4a11e69e04abd36f59eb5fed6fa23997bb48f18f45b8'),
    'infra/staging/README.md': (420, '5f3daac1edba6320bcfc6663d57bece16a9c63b7977156c0fc3a3b562276a435'),
    'infra/staging/topology.json': (420, 'a55b4e72f63569b74539e9b42a8c0b34bd964f9213a5696b535fb2eb4ca24b14'),
    'pnpm-lock.yaml': (420, '7d8509a802bad9c700070722a8e834c98aef18c925768fb9c763a90a5a10c6cc'),
    'scripts/issue_1700_runtime_probe.mjs': (420, '7045e5d0f1bd8065055396494ea14c8162457f37637bb5e0078223bce0a02186'),
    'scripts/staging_bootstrap_provider.py': (420, '8a77837893f2bd094f1fd834042361e69375e1453ec1d4dde9c20c605d00ccdb'),
    'scripts/tests/issue_1700_runtime_probe.test.mjs': (420, '48e3b316bd716f112e682636a8e9dd3f3f759aedf8809e6d7535c40b966187ab'),
    'scripts/verify_staging_provider_preflight.py': (420, 'ddc9d57aa31cbee273dabc923b23a3ef33fb11b40bbd3b746ad7dcaca0633b62'),
    'scripts/verify_staging_topology_contract.py': (420, '48b69bc6c4852ef8218058d53105fb82c4a60d22af25739b111dc4a0def79bf9'),
    'tests/test_issue_1700_route_inventory.py': (420, 'd9dc1e4012f590ef6b3e76eb1e342ac43d513a14ef16f3ee8db8cffb9ef2b734'),
    'tests/test_staging_bootstrap_provider.py': (420, 'ec4633c038fd4ae1553464e00ba2ce6dfe79e10562f79243e0fb629d1d93e219'),
    'tests/test_staging_custom_domain.py': (420, 'cfc063496302c06c8bc879c380c7f24e13088fdf8f2a5412def3e6e60b115afc'),
    'tests/test_staging_quarantine_apply_contract.py': (420, 'b90d143271b96038ce2f51a23bc62b3be3fee546a231f003b9bcfbfb79a497bf'),
    'worker/package.json': (420, '96b6b20887688c4280772874766e878e285edb715acdf286f6fe5641e911fe34'),
    'worker/src/durable_object.ts': (420, 'c4046c2008acedecc7d1404bfad2fecbda58131e66927b58c5d56d82ca9febb9'),
    'worker/src/durable_object_start.ts': (420, '7f8c28ac7b93628f4c4767efd1bb68bb75d2df9ea85442e92d9a6097c500ce4c'),
    'worker/src/index.ts': (420, '18b960a74833284f953bd28818cd7260798d9570c17bce459502f7b7ca50f3cd'),
    'worker/src/index_schedule.ts': (420, 'fa2385df3e6ec121de862845fac0a66e48edb506912a95f2c7d3a02dae671678'),
    'worker/src/lib/devenv_cleanup_route.ts': (420, 'e279cb99a585388fbf4483313a80c042df3c14bf1ca5ef52c31dc451e329907c'),
    'worker/src/lib/runner_credential_routes.ts': (420, '6cd7af8c032dd8315c619f6830c3ef63df1a459152f197ca6a7faedf847b5731'),
    'worker/src/pat_issue_rate_limit.ts': (420, 'ff4ca0814c40f128fed4650b2041660670bcc985037b975cb6f29b177d3c1afb'),
    'worker/src/staging_d1_binding_proxy.ts': (420, '1e5d940b240a4bef9daba0e360758793ab7b11a165f5b1bc8ccb7eae658a348d'),
    'worker/src/staging_d1_binding_proxy_entrypoint.ts': (420, 'af759d84e63a2016737c899cfba045f52c1fcf20061678a3612ddeec6c18bdab'),
    'worker/src/staging_runtime_d1_probe.ts': (420, '3758098dd2419314fd006fdb8478f5b5043b1b80dd6679a31e2043323355f132'),
    'worker/tests/cloudflare_workers_node_stub.ts': (420, '0237103e747517298fea07261598d250e25edff6f412cd1df33695c1585cfcf7'),
    'worker/tests/durable_object.test.ts': (420, '53f07e0929c957a4e804e2f9063e01359e382fea74b7c0322c2a41f47bbd16a2'),
    'worker/tests/staging_d1_binding_proxy.test.ts': (420, '5710f974898de4c88a1ddca3f9815589d7c805faa4481f44d9005054d10796cc'),
    'worker/tests/staging_d1_binding_start_gate.test.ts': (420, '2377e10e46528888f60f711820a931f8358d214ac53b8c822bfac9c2d9f2da66'),
    'worker/tests/staging_runtime_d1_probe.test.ts': (420, '05bfc2224d8db3ab72946332bcb41b4667e5e628da30a24a237ed57f7163f639'),
    'worker/vitest.config.mts': (420, 'e2c2f0e46d4a45d5e789f920f95b73ffd44e6a14a9450e11817426995feda506'),
}
STAGING_D1_BINDING_PROXY_MANIFEST_SHA256 = "05e9e3c71a7073146ced7fbcf52afaf8acae88ee6ffc621710921a0eb1f6ec0e"

# Exact follow-on ownership transitions sealed with the #1700 base.
STAGING_I1648_PREIMAGES = {
    ".github/workflows/container-build-push-prod.yml": (0o644, "db7124deb092eb309e3d3421ab304e2b53267dbcbdd5547dd2f86b87273a5b2f"),
    "scripts/verify_b063_hosted_build_workflow.py": None,
    "scripts/test_verify_b063_hosted_build_workflow.py": None,
    "wrangler.toml": (0o644, "d9aeb0fab1790d37fc6511c0760a812921e8405bafc039a046947dd565576ddc"),
    "evidence/owner-actions/B-063/production-image-build-receipt.json": None,
}
STAGING_I1648_TARGETS = {
    ".github/workflows/container-build-push-prod.yml": (0o644, "8ee0d29eff20ef5d473e4a712279a727fcdc6c881ba2bb46433f7659802f598f"),
    "scripts/verify_b063_hosted_build_workflow.py": (0o644, "09617a685bb467ed749dadd0e6d5155e08e901733393223f825b34e2b2c22157"),
    "scripts/test_verify_b063_hosted_build_workflow.py": (0o644, "3dae07bc590c83f50d03c5194d8db3a71cb15a3c2eabbd68c1ef059ebcedb748"),
    "wrangler.toml": (0o644, "568d0e6994ce1156542e350520a9750924a0f3f416e67af07c7275682e24c7a6"),
    "evidence/owner-actions/B-063/production-image-build-receipt.json": (0o644, "6fdc47bb51354a0e7675b9f19c21864a23e89562751944386525e966e957dd27"),
}
STAGING_B216_PREIMAGES = {
    ".github/workflows/b216-receiver-deploy-nonprod.yml": (0o644, "1d0e94cd0ba53fccc4b8aaf225a81b180192136f4bee99b8b9d6f69a7b78eeb0"),
    "apps/dsr-alert-receiver/scripts/deploy-route.mjs": (0o644, "c83ac8b06826940a49faca93ef192bf5acdd44adaed3088a29b4f7df97117557"),
    "apps/dsr-alert-receiver/tests/deploy-route.test.mjs": (0o644, "7f0511864d5deced20c2352ed23da7d436761f1d0a422750fb06e94feaac65d8"),
    "docs/internal/secrets-checklist.md": (0o644, "6157f5653e1a4ebea7be4a11e69e04abd36f59eb5fed6fa23997bb48f18f45b8"),
}
STAGING_B216_TARGETS = {
    ".github/workflows/b216-receiver-deploy-nonprod.yml": (0o644, "1a3c849443f1ded6e0a8791797d906640121b753f8e5a0043b1dec78ac1c941d"),
    "apps/dsr-alert-receiver/scripts/deploy-route.mjs": (0o644, "3245267227c49d3ffaa84136f5f3230d559c63d96df25eb34bf75fe773bc5f5b"),
    "apps/dsr-alert-receiver/tests/deploy-route.test.mjs": (0o644, "a2ec944dbb5e9bf54ff1a7cceeb7e26b55427eda6e24b9d4c83730607e32c755"),
    "docs/internal/secrets-checklist.md": (0o644, "acc1debc7f96d7b38b03743f6c905e882655dc0a370ab4b7c97d7b37b5e00196"),
}


def _preauthorized_exact_staging_transition(candidate_root: Path, trusted_root: Path, preimages: dict[str, tuple[int, str] | None], targets: dict[str, tuple[int, str]], required_base: tuple[dict[str, tuple[int, str]], ...] = ()) -> bool:
    try:
        candidate, trusted = _candidate_tree_entries(candidate_root), _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False
    paths = set(preimages)
    if not paths or set(targets) != paths:
        return False
    cumulative_base_pins: dict[str, tuple[int, str]] = {}
    for pins in required_base:
        cumulative_base_pins.update(pins)
    for path, pin in cumulative_base_pins.items():
        entry = trusted.get(path)
        if entry is None or entry[0] != "file" or entry[1:] != pin:
            return False
    changes = {path for path in set(candidate) | set(trusted) if candidate.get(path) != trusted.get(path)}
    if changes != paths:
        return False
    for path in paths:
        target = targets[path]; entry = candidate.get(path); preimage = preimages[path]; old = trusted.get(path)
        if entry is None or entry[0] != "file" or entry[1:] != target:
            return False
        if preimage is None:
            if old is not None: return False
        elif old is None or old[0] != "file" or old[1:] != preimage:
            return False
    return True


STAGING_I2568_PREIMAGES = {
    '.actionlint.yaml': (420, '8e119ec23c53aa981bbfea4d909637d76f79956bee8d7aee30f4d6cfbbc48099'),
    '.github/workflows/issue-2568-sla-credit-real.yml': None,
    'scripts/issue_2568_sla_credit_real.py': None,
    'scripts/issue_2568_sla_credit_worker.ts': None,
    'scripts/verify_issue_2568_sla_credit_real.py': None,
    'tests/test_issue_2568_sla_credit_real.py': None,
    'docs/campaigns/remediation/wp150-workflow-ownership.md': (420, 'd8ea8a8c5b19ca5b5fdae2ea8fd46664d9e860d47a7ddaaf318855e89fb6c210'),
    'docs/internal/secrets-checklist.md': (420, 'acc1debc7f96d7b38b03743f6c905e882655dc0a370ab4b7c97d7b37b5e00196'),
}

STAGING_I2568_TARGETS = {
    '.actionlint.yaml': (420, '2e1ad216236818322adb7baed2e25dcc836cd7a030493fd799f4d4fc06702576'),
    '.github/workflows/issue-2568-sla-credit-real.yml': (420, '67031ad29cdcbef2efa7d6385c298f3aa240440545db81e53d490b9df58ee195'),
    'scripts/issue_2568_sla_credit_real.py': (420, '3a41577dec203d3fa4f18924de6af92224ca5ae35f5b2231551e25a00b8ca0d2'),
    'scripts/issue_2568_sla_credit_worker.ts': (420, '4cf891a4ba1030e03db9401df4a312c75204a08bf7be774a8f634a1bc89e2d62'),
    'scripts/verify_issue_2568_sla_credit_real.py': (420, 'bca4fc394e00694eb2bf95e2418a5f90005cace3c426133e862eae868d20bab4'),
    'tests/test_issue_2568_sla_credit_real.py': (420, '392514070165cf8442f41c82237000831ae313c20d6a0d92d70c0b5dc0214df5'),
    'docs/campaigns/remediation/wp150-workflow-ownership.md': (420, 'cb9bb10177faf2fd578e1cc23163015f8c2913e360e8f2880dcd2afc71904e15'),
    'docs/internal/secrets-checklist.md': (420, '4d3cbad537f0ec07f00cdc34336f41000822c60febbf178dd9fe16a48ea52af7'),
}


# One reviewed B-035 closeout. The exact old/new bytes and file modes are
# frozen against protected main after #2585's serial integration.
B035_CLOSEOUT_PREIMAGES: dict[str, tuple[int, str]] = {'BACKLOG.md': (420, 'cb22a787eb4ccdcbe4fe45516326e2a4623d0a52f5f34eb515ba3ff65c8c94da'),
 'docs/campaigns/remediation/BACKLOG-WP-LEDGER.md': (420,
                                                     'fa1d028ac338e9fd9b7119caf228541bc756f27776d7970e1d6f2522140127c3'),
 'docs/campaigns/remediation/work-packages/B001-B045.md': (420,
                                                           '081c9885db8d79c18f2f31edb7864bb1ca1a18d53f408720f3f9e4f00524f9c6'),
 'docs/handoff/2026-09-05-owner-action-packets-b008-b154.json': (420,
                                                                 'f12c3c95ed8e3fc02bbcf5c050d238ebbc6a663546ce1a95fbd11a2fb8da020e'),
 'scripts/verify_b155_owned.py': (420,
                                  '3389811be2d3f42eb0e8b6998502544b64bd6a538aeb8bf80bb1c2fcdfe04b62'),
 'scripts/verify_owner_action_packets.py': (420,
                                            '30954c34e64946339cde8b2b9f648cac2442a9dd4fce3cb25b41654fe8d235ba')}
B035_CLOSEOUT_TARGETS: dict[str, tuple[int, str]] = {'BACKLOG.md': (420, '503a9c3b42827843206330d3693ecd9a9b1f7ce9866bec70b18d692752d4f13d'),
 'docs/campaigns/remediation/work-packages/B001-B045.md': (420,
                                                           'd5e3b5edfb7a47e9ff360c07c2fe602d1c9b91decf59c7b8523ed9091c1d3b47'),
 'docs/handoff/2026-09-05-owner-action-packets-b008-b154.json': (420,
                                                                 'd08a1dc56721feb1a55102449581d54f52d7345278545fa901f3852a21d48d27'),
 'scripts/verify_b155_owned.py': (420,
                                  '2ad10f2ea62197502badd0c711e757ae352cf35f82b792ddb99a9b9f232ac1a4'),
 'scripts/verify_owner_action_packets.py': (420,
                                            '10cc058394ecdeb0ac27d98fdb5d0779e7a0d1bb1c1d1a15eae0d872d3f227a2'),
 'evidence/owner-actions/B-035/tls-legal-remediation.json': (420,
                                                             '1fe3d441fd99f39b8059fbd836089f4a8dc1e86e8e272ebadab83cd0eb848cbb')}
B035_CLOSEOUT_DYNAMIC_PATHS = frozenset({'docs/campaigns/remediation/BACKLOG-WP-LEDGER.md', 'docs/campaigns/remediation/backlog-ledger-snapshot-v0011.json'})
B035_CLOSEOUT_LEDGER_TEMPLATE_SHA256 = '1ff010467cf3125af24c7f8e434be04cbbcc4e5e5046d7c25e6000482afe3d4a'
B035_CLOSEOUT_SNAPSHOT_TEMPLATE_SHA256 = '92587079ef9d6b5fe29229e2fb614a95f6dac261849696663861aa6911409c71'
B035_CLOSEOUT_NEW_PATHS = frozenset({
    "docs/campaigns/remediation/backlog-ledger-snapshot-v0011.json",
    "evidence/owner-actions/B-035/tls-legal-remediation.json",
})

# A command's polarity cannot be inferred from arbitrary shell.  We can still
# reject the known dangerous declaration: a `done` item whose human explanation
# explicitly says the check remains `open`.  Unmarked legacy entries remain
# compatible; authors may describe their inverted guard in their existing prose.
OPEN_VERIFY_MARKER_RE = re.compile(
    r"^(?:open\b|(?:polaridade|polarity)\s+(?:abert[ao]|open)\b|"
    r"(?:polaridade|polarity)\s+de\s+item\s+abert[oa]\b)",
    re.IGNORECASE,
)

CONFIRMED, DRIFTED, STALE, BROKEN = "CONFIRMED", "DRIFTED", "STALE", "BROKEN"


@dataclass
class Item:
    raw: dict
    line: int
    id: str = ""
    verdict: str = ""
    detail: str = ""
    evidence: str = ""
    problems: list[str] = field(default_factory=list)


class _NoDuplicateKeysLoader(yaml.SafeLoader):
    """`yaml.SafeLoader` that refuses a mapping with a repeated key.

    PyYAML's default is last-wins, silently. On 2026-08-24 a B-039 `verify:` +
    `verify-means:` pair was pasted into the B-040 block; both blocks parsed,
    both were unique by `id`, and the gate cheerfully ran B-039's TLA-jar check
    while reporting on B-040. The two happened to agree at the time, so nothing
    went red — the register would have started lying the moment they diverged.
    A duplicate key here is never intentional; make it BROKEN.
    """


def _no_duplicate_keys(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r} in a backlog block", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_NoDuplicateKeysLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def parse(text: str) -> list[Item]:
    items: list[Item] = []
    for m in BLOCK_RE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        try:
            data = yaml.load(m.group(1), Loader=_NoDuplicateKeysLoader) or {}
        except yaml.YAMLError as e:
            items.append(Item(raw={}, line=line, id=f"<unparseable@{line}>", verdict=BROKEN,
                              detail=f"the backlog block is not valid YAML: {e}"))
            continue
        if not isinstance(data, dict):
            items.append(Item(raw={}, line=line, id=f"<malformed@{line}>", verdict=BROKEN,
                              detail="a backlog block must be a mapping of fields"))
            continue
        items.append(Item(raw=data, line=line, id=str(data.get("id", f"<no id@{line}>"))))
    return items


def validate_schema(item: Item) -> None:
    """Reject a malformed item outright rather than half-checking it.

    A silently skipped item is precisely the failure this gate exists to prevent,
    so a missing field is a hard failure, never a warning.
    """
    d = item.raw
    for f in REQUIRED_FIELDS:
        if f not in d or d[f] in (None, ""):
            item.problems.append(f"missing required field `{f}`")
    # YAML turns bare `true`, `yes`, `on`, `no`, `off` into booleans, so a verify
    # written without quotes silently stops being a command. Caught by this file's
    # own self-test on 2026-08-23; a real item could make the same mistake and would
    # otherwise report DRIFTED with a baffling "command not found".
    if "verify" in d and not isinstance(d["verify"], str):
        item.problems.append(
            f"verify must be a quoted string, got {type(d['verify']).__name__} "
            f"({d['verify']!r}) — YAML reads bare true/yes/on as booleans"
        )
    if d.get("status") not in VALID_STATUS and "status" in d:
        item.problems.append(f"status must be one of {VALID_STATUS}, got {d.get('status')!r}")
    if d.get("owner") not in VALID_OWNER and "owner" in d:
        item.problems.append(f"owner must be one of {VALID_OWNER}, got {d.get('owner')!r}")
    # `status` and `owner` were validated INDEPENDENTLY and never crossed (B-147).
    # `owner: owner` means "still needs the human" — a credential, a payment, a
    # deletion, a legal call. A finished item does not still need the human, so
    # `done` + `owner: owner` is a contradiction on its face, and the practical
    # cost is the owner's queue accumulating work nobody has to do any more (28 → 12
    # when it was last cleaned by hand, in #1510).
    # SCOPE, fixed here so the gate does not become folklore: `done` ONLY. `parked`
    # is deliberately EXCLUDED — an item parked precisely because it is waiting on
    # the owner is legitimate, and the strict reading (`!= open`) would forbid it.
    if d.get("status") == "done" and d.get("owner") == "owner":
        item.problems.append(
            "status: done with owner: owner — `owner: owner` means the item still needs "
            "the human, and a finished item does not. Set `owner: tl`, or reopen it."
        )
    if d.get("status") == "done" and has_explicit_open_verify_marker(d.get("verify-means")):
        item.problems.append(
            "status: done has an explicit open-polarity declaration in the first non-empty "
            "line of `verify-means`; invert the verify or reopen the item"
        )
    if "last-verified" in d:
        try:
            parse_date(d["last-verified"])
        except Exception:
            item.problems.append(f"last-verified must be YYYY-MM-DD, got {d.get('last-verified')!r}")


def parse_date(value) -> dt.date:
    if isinstance(value, dt.date):
        return value
    return dt.datetime.strptime(str(value), "%Y-%m-%d").date()


def has_explicit_open_verify_marker(value) -> bool:
    """Return whether ``verify-means`` explicitly declares an open polarity.

    Only an explicit first-line marker is actionable.  This rejects the known
    false-done shape without inventing a semantic parser for arbitrary prose.
    """
    if not isinstance(value, str):
        return False
    first = next((line.strip() for line in value.splitlines() if line.strip()), "")
    first = re.sub(r"[*`_]", "", first).strip()
    return bool(OPEN_VERIFY_MARKER_RE.match(first))


def age_days(item: Item, today: dt.date) -> int:
    return (today - parse_date(item.raw["last-verified"])).days


def run_verify(command: str, *, mode: str, item_id: str = "") -> tuple[int, str]:
    """Run only trusted-main semantics; candidate and fixture text stay inert."""
    if mode == "fixture":
        if command == "true":
            return 0, "true"
        if command == "false":
            return 1, "false"
        return 125, "fixture verify command is not an allowlisted literal (not executed)"
    if mode != "trusted":
        return 125, "candidate verify command is data-only (not executed)"

    # This mode is reached only by the explicit trusted-semantic workflow step,
    # whose checkout is the immutable main github.sha. Keep the declaration's
    # established shell semantics, but do not inherit runner credential tokens.
    clean_env = {
        key: value for key, value in os.environ.items()
        if key not in {"GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "BASH_ENV", "ENV"}
    }
    if item_id in AUTH_VERIFY_COMMANDS and command == AUTH_VERIFY_COMMANDS[item_id]:
        token = os.environ.get("GH_TOKEN")
        if token:
            clean_env["GH_TOKEN"] = token
    try:
        with tempfile.TemporaryDirectory(prefix="backlog-gh-") as gh_config_dir:
            clean_env["GH_CONFIG_DIR"] = gh_config_dir
            process = subprocess.run(
                ["/bin/bash", "-o", "pipefail", "-c", command],
                cwd=REPO_ROOT,
                timeout=VERIFY_TIMEOUT_S,
                capture_output=True,
                text=True,
                env=clean_env,
            )
    except subprocess.TimeoutExpired:
        return 124, f"verify command exceeded {VERIFY_TIMEOUT_S}s"
    tail = (process.stdout + process.stderr).strip().splitlines()
    return process.returncode, tail[-1][:200] if tail else ""


def check(
    item: Item,
    today: dt.date,
    max_age: int,
    *,
    trusted_by_id: dict[str, Item] | None = None,
    authorized_verify_deltas: dict[str, tuple[str, str]] | None = None,
    enforce_manual_age: bool = False,
    execution_mode: str = "candidate",
) -> None:
    if item.verdict:  # already BROKEN at parse time
        return
    validate_schema(item)
    if item.problems:
        item.verdict = BROKEN
        item.detail = "; ".join(item.problems)
        return

    command = str(item.raw["verify"]).strip()
    if command == "manual":
        age = age_days(item, today)
        if enforce_manual_age and age > max_age:
            item.verdict = STALE
            item.detail = (f"last verified {age} days ago (limit {max_age}); "
                           "re-verify it by hand and update last-verified, or give it a real check")
        else:
            item.verdict = CONFIRMED
            item.detail = (
                f"manual, verified {age} day(s) ago"
                if enforce_manual_age
                else "manual declaration present; semantic freshness is deferred to exact-SHA CI"
            )
        return

    trusted = (trusted_by_id or {}).get(item.id)
    if trusted is not None and item.raw.get("verify") != trusted.raw.get("verify"):
        expected_delta = (trusted.raw.get("verify"), item.raw.get("verify"))
        if expected_delta != (authorized_verify_deltas or {}).get(item.id):
            item.verdict = BROKEN
            item.detail = "verify declaration differs from BASE; semantic execution is deferred to exact-SHA CI"
            return
    if execution_mode == "candidate":
        item.verdict = CONFIRMED
        item.detail = "verify declaration is syntactically present; semantic execution is deferred to exact-SHA CI"
        return
    code, evidence = run_verify(command, mode=execution_mode, item_id=item.id)
    item.evidence = evidence
    if code == 0:
        item.verdict = CONFIRMED
        item.detail = "verify agrees with the declared status"
    elif code == 124:
        item.verdict = BROKEN
        item.detail = evidence
    else:
        item.verdict = DRIFTED
        item.detail = (f"verify exited {code} — the item claims status "
                       f"`{item.raw['status']}` but the check for that no longer holds")


_CONTROL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])((?:scripts|tests)/[A-Za-z0-9_./-]+)")


def _normal_control_path(value: str) -> str | None:
    """Normalize a statically discovered path without permitting escape."""
    if value.startswith("/"):
        return None
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../"):
        return None
    return normalized.removeprefix("./")


def _static_path_expr(
    expression: ast.AST, source_relative: str, bindings: dict[str, ast.AST], seen: set[str] | None = None
) -> str | None:
    """Resolve bounded Path(__file__) expressions used by dynamic loaders."""
    seen = seen or set()
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return _normal_control_path(expression.value)
    if isinstance(expression, ast.Name) and expression.id not in seen and expression.id in bindings:
        return _static_path_expr(expression=bindings[expression.id], source_relative=source_relative,
                                  bindings=bindings, seen=seen | {expression.id})
    if isinstance(expression, ast.Call):
        if isinstance(expression.func, ast.Name) and expression.func.id == "Path":
            if expression.args and isinstance(expression.args[0], ast.Name) and expression.args[0].id == "__file__":
                return source_relative
            if expression.args and isinstance(expression.args[0], ast.Constant):
                return _normal_control_path(str(expression.args[0].value))
        if isinstance(expression.func, ast.Attribute):
            base = _static_path_expr(expression.func.value, source_relative, bindings, seen)
            if expression.func.attr == "with_name" and base and expression.args:
                name = _static_path_expr(expression.args[0], source_relative, bindings, seen)
                return _normal_control_path(posixpath.join(posixpath.dirname(base), name)) if name else None
            if expression.func.attr == "resolve":
                return base
    if isinstance(expression, ast.Attribute) and expression.attr == "parent":
        base = _static_path_expr(expression.value, source_relative, bindings, seen)
        return _normal_control_path(posixpath.dirname(base)) if base else None
    if isinstance(expression, ast.Subscript) and isinstance(expression.value, ast.Attribute) and expression.value.attr == "parents":
        base = _static_path_expr(expression.value.value, source_relative, bindings, seen)
        index = expression.slice.value if isinstance(expression.slice, ast.Constant) else None
        if base is not None and isinstance(index, int) and index >= 0:
            for _ in range(index + 1):
                base = posixpath.dirname(base)
            return _normal_control_path(base)
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
        base = _static_path_expr(expression.left, source_relative, bindings, seen)
        suffix = _static_path_expr(expression.right, source_relative, bindings, seen)
        if suffix is None:
            return None
        # A function parameter such as ``root`` is intentionally unresolved,
        # but a literal scripts/tests suffix is still a safe control path.
        return _normal_control_path(posixpath.join(base or "", suffix))
    return None


def _python_control_paths(source: Path, trusted_root: Path, relative: str) -> set[str]:
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise RuntimeError(f"cannot statically inspect trusted control {relative}: {exc}") from exc
    bindings: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        assignment = node if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.AST):
            for target in assignment.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = assignment.value
        elif isinstance(assignment, ast.AnnAssign) and isinstance(assignment.target, ast.Name) and assignment.value:
            bindings[assignment.target.id] = assignment.value

    discovered: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "scripts" or alias.name.startswith("scripts."):
                    discovered.add(alias.name.replace(".", "/") + ".py")
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module == "scripts" or node.module.startswith("scripts."):
                module_path = node.module.replace(".", "/")
                direct = module_path + ".py"
                if (trusted_root / direct).is_file():
                    discovered.add(direct)
                for alias in node.names:
                    imported = module_path + "/" + alias.name + ".py"
                    if (trusted_root / imported).is_file():
                        discovered.add(imported)
        elif isinstance(node, ast.Call):
            is_spec_loader = (
                isinstance(node.func, ast.Attribute) and node.func.attr == "spec_from_file_location"
            ) or (isinstance(node.func, ast.Name) and node.func.id == "spec_from_file_location")
            if not is_spec_loader or len(node.args) < 2:
                continue
            loaded = _static_path_expr(node.args[1], relative, bindings)
            if loaded is None:
                raise RuntimeError(
                    f"unresolved importlib loader path in trusted control {relative}:{node.lineno}"
                )
            if loaded.endswith(".py"):
                discovered.add(loaded)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                module = node.args[0].value
                if module == "scripts" or module.startswith("scripts."):
                    discovered.add(module.replace(".", "/") + ".py")
    return {path for path in discovered if (trusted_root / path).is_file()}


def _candidate_control_paths(trusted_root: Path, trusted_items: list[Item]) -> set[str]:
    """Resolve the trusted verifier's direct and transitive data controls.

    This is intentionally a static closure. It never imports or runs a
    candidate module, and it does not blanket-freeze unrelated source files.
    """
    paths = {
        "scripts/backlog_verify.py",
        "scripts/verify_backlog_wp_ledger.py",
        "scripts/backlog_ledger_successor.py",
        "scripts/backlog_ledger_contracts.py",
    }
    queue: list[str] = []
    for item in trusted_items:
        command = item.raw.get("verify")
        if isinstance(command, str):
            queue.extend(
                match.group(1).rstrip("'\"`),;:}")
                for match in _CONTROL_PATH_RE.finditer(command)
            )
    seen: set[str] = set()
    while queue:
        relative = queue.pop()
        if relative in seen or not relative.endswith((".py", ".sh")):
            continue
        seen.add(relative)
        paths.add(relative)
        if not relative.endswith(".py"):
            continue
        source = trusted_root / relative
        if not source.is_file() or source.is_symlink():
            continue
        queue.extend(_python_control_paths(source, trusted_root, relative))
    return paths


def _regular_control(root: Path, relative: str) -> bytes:
    path = root / relative
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"control path escapes checkout: {relative}") from exc
    try:
        current = root
        for component in Path(relative).parts[:-1]:
            current = current / component
            if current.is_symlink():
                raise RuntimeError(f"control parent is a symlink: {relative}")
        path.lstat()
    except OSError as exc:
        raise RuntimeError(f"control file unavailable: {relative}: {exc}") from exc
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"control file is not a regular non-symlink file: {relative}")
    return path.read_bytes()


def _candidate_tree_entries(root: Path) -> dict[str, tuple[str, int, str]]:
    """Return file modes and hashes or symlink targets without following links."""
    entries: dict[str, tuple[str, int, str]] = {}

    def fail_walk(error: OSError) -> None:
        raise RuntimeError(f"candidate tree traversal failed: {error}") from error

    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise RuntimeError("candidate tree root is not a regular directory")
    except OSError as exc:
        raise RuntimeError(f"candidate tree root unavailable: {exc}") from exc

    for current, directories, filenames in os.walk(
        root, topdown=True, onerror=fail_walk, followlinks=False
    ):
        current_path = Path(current)
        walk_directories: list[str] = []
        for name in directories:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise RuntimeError(f"candidate tree entry unavailable: {relative}: {exc}") from exc
            if name == ".git" and stat.S_ISDIR(mode):
                continue
            if stat.S_ISLNK(mode):
                entries[relative] = ("symlink", stat.S_IMODE(mode), os.readlink(path))
            elif stat.S_ISDIR(mode):
                walk_directories.append(name)
            else:
                raise RuntimeError(f"candidate tree contains non-directory path: {relative}")
        directories[:] = walk_directories

        for name in filenames:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise RuntimeError(f"candidate tree entry unavailable: {relative}: {exc}") from exc
            if stat.S_ISLNK(mode):
                entries[relative] = ("symlink", stat.S_IMODE(mode), os.readlink(path))
            elif stat.S_ISREG(mode):
                entries[relative] = (
                    "file",
                    stat.S_IMODE(mode),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            else:
                raise RuntimeError(f"candidate tree contains non-regular file: {relative}")
    return entries


def _preauthorized_i1652_receiver(candidate_root: Path, trusted_root: Path) -> bool:
    """Admit the B072 receiver guard only with its complete reviewed delivery.

    Candidate source is never imported or executed. The complete tree delta,
    file types, modes, bytes, and absent preimages must match the pins.
    """
    try:
        candidate_entries = _candidate_tree_entries(candidate_root)
        trusted_entries = _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False
    changed = {
        relative for relative in candidate_entries.keys() | trusted_entries.keys()
        if candidate_entries.get(relative) != trusted_entries.get(relative)
    }
    if changed != set(I1652_DELIVERY_PINS):
        return False
    for relative, (old_pin, new_pin) in I1652_DELIVERY_PINS.items():
        old_entry = None if old_pin is None else ("file", *old_pin)
        new_entry = None if new_pin is None else ("file", *new_pin)
        if trusted_entries.get(relative) != old_entry or candidate_entries.get(relative) != new_entry:
            return False
    return True


def _preauthorized_b057_c0(candidate_root: Path, trusted_root: Path) -> bool:
    """Recognize the sole byte-pinned B-057 trusted-control migration."""
    try:
        candidate_entries = _candidate_tree_entries(candidate_root)
        trusted_entries = _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False

    workflow = ".github/workflows/issue-2414-b057-sli.yml"
    if workflow in trusted_entries:
        return False
    if set(candidate_entries) != set(trusted_entries) | {workflow}:
        return False
    if any(
        candidate_entries.get(relative, ("", 0, ""))[0] != "file"
        for relative in B057_C0_TARGETS
    ):
        return False
    if any(
        trusted_entries.get(relative, ("", 0, ""))[0] != "file"
        for relative in B057_C0_PREIMAGES
    ):
        return False
    changed = {
        relative
        for relative, entry in candidate_entries.items()
        if entry != trusted_entries.get(relative)
    }
    if changed != set(B057_C0_TARGETS):
        return False
    return (
        all(
            trusted_entries[relative][2] == expected
            for relative, expected in B057_C0_PREIMAGES.items()
        )
        and all(
            candidate_entries[relative][2] == expected
            for relative, expected in B057_C0_TARGETS.items()
        )
    )


def _preauthorized_b029_load_gate(candidate_root: Path, trusted_root: Path) -> bool:
    """Recognize only the complete byte-pinned #2585 load gate transition."""
    try:
        candidate_entries = _candidate_tree_entries(candidate_root)
        trusted_entries = _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False

    paths = set(B029_LOAD_GATE_TARGETS)
    if set(B029_LOAD_GATE_PREIMAGES) != paths:
        return False
    changed = {
        path for path in set(candidate_entries) | set(trusted_entries)
        if candidate_entries.get(path) != trusted_entries.get(path)
    }
    if changed != paths:
        return False
    for path in paths:
        candidate = candidate_entries.get(path)
        if candidate is None or candidate[0] != "file":
            return False
        if candidate[1] != B029_LOAD_GATE_TARGET_MODES.get(path):
            return False
        if candidate[2] != B029_LOAD_GATE_TARGETS[path]:
            return False
        trusted = trusted_entries.get(path)
        preimage = B029_LOAD_GATE_PREIMAGES[path]
        if preimage is None:
            if trusted is not None:
                return False
        elif trusted is None or trusted[0] != "file" or trusted[2] != preimage:
            return False
    return True


def _preauthorized_staging_custom_domain(candidate_root: Path, trusted_root: Path) -> bool:
    """Recognize only the frozen #1700 verifier/topology byte transition."""
    try:
        candidate_entries = _candidate_tree_entries(candidate_root)
        trusted_entries = _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False
    paths = set(STAGING_CUSTOM_DOMAIN_PREIMAGES)
    if set(STAGING_CUSTOM_DOMAIN_TARGETS) != paths:
        return False
    if any(candidate_entries.get(path, ("", 0, ""))[0] != "file" for path in paths):
        return False
    if any(trusted_entries.get(path, ("", 0, ""))[0] != "file" for path in paths):
        return False
    if any(candidate_entries[path][1] != trusted_entries[path][1] for path in paths):
        return False
    # The delivery changes thirteen explicitly named application/docs paths in
    # addition to the four frozen controls. This allows the reviewed delivery
    # while rejecting arbitrary extra files; the BASE closure checks any other
    # trusted-control changes independently.
    allowed_changes = paths | STAGING_CUSTOM_DOMAIN_DELIVERY_PATHS
    changed = {
        path for path in set(candidate_entries) | set(trusted_entries)
        if candidate_entries.get(path) != trusted_entries.get(path)
    }
    if changed != allowed_changes:
        return False
    if not all(
        trusted_entries[path][2] == digest
        for path, digest in STAGING_CUSTOM_DOMAIN_PREIMAGES.items()
    ) or not all(
        candidate_entries[path][2] == digest
        for path, digest in STAGING_CUSTOM_DOMAIN_TARGETS.items()
    ):
        return False
    try:
        topology = json.loads((candidate_root / "infra/staging/topology.json").read_bytes())
        cloudflare = topology["cloudflare"]
        domains = cloudflare["routes"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return (
        topology.get("deployment_state") == "unprovisioned"
        and isinstance(domains, list)
        and domains == [{
            "pattern": "staging.corelink.humangr.com",
            "worker": "corelink-staging",
            "zone_name": "humangr.com",
            "custom_domain": True,
        }]
    )


def _preauthorized_staging_d1_binding_proxy(candidate_root: Path, trusted_root: Path) -> bool:
    """Recognize only the frozen 37-path #1700 runtime-probe successor tree."""
    try:
        candidate_entries = _candidate_tree_entries(candidate_root)
        trusted_entries = _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False
    paths = set(STAGING_D1_BINDING_PROXY_PREIMAGES)
    if len(paths) != 37 or set(STAGING_D1_BINDING_PROXY_TARGETS) != paths:
        return False
    changed = {
        path for path in set(candidate_entries) | set(trusted_entries)
        if candidate_entries.get(path) != trusted_entries.get(path)
    }
    if changed != paths:
        return False
    manifest_rows = []
    for path in paths:
        target = STAGING_D1_BINDING_PROXY_TARGETS[path]
        candidate = candidate_entries.get(path)
        if (
            target is None
            or candidate is None
            or candidate[0] != "file"
            or candidate[1:] != target
        ):
            return False
        preimage = STAGING_D1_BINDING_PROXY_PREIMAGES[path]
        trusted = trusted_entries.get(path)
        if preimage is None:
            if trusted is not None:
                return False
        elif (
            trusted is None
            or trusted[0] != "file"
            or trusted[1:] != preimage
        ):
            return False
        manifest_rows.append(f"{(0o100000 | target[0]):06o} {target[1]} {path}\n")
    return hashlib.sha256("".join(sorted(manifest_rows, key=lambda row: row.split(" ", 2)[2])).encode()).hexdigest() == STAGING_D1_BINDING_PROXY_MANIFEST_SHA256


def _preauthorized_b035_closeout(candidate_root: Path, trusted_root: Path) -> bool:
    """Admit only the frozen B-035 data/control successor, without executing it."""
    try:
        candidate = _candidate_tree_entries(candidate_root)
        trusted = _candidate_tree_entries(trusted_root)
    except (OSError, RuntimeError):
        return False
    old_paths = set(B035_CLOSEOUT_PREIMAGES)
    new_paths = set(B035_CLOSEOUT_TARGETS) | B035_CLOSEOUT_DYNAMIC_PATHS
    if not old_paths or new_paths != old_paths | B035_CLOSEOUT_NEW_PATHS:
        return False
    if not B035_CLOSEOUT_NEW_PATHS.isdisjoint(trusted):
        return False
    if set(candidate) != set(trusted) | B035_CLOSEOUT_NEW_PATHS:
        return False
    changed = {
        path for path in set(candidate) | set(trusted)
        if candidate.get(path) != trusted.get(path)
    }
    if changed != new_paths:
        return False
    if not (all(
        trusted.get(path) == ("file", *expected)
        for path, expected in B035_CLOSEOUT_PREIMAGES.items()
    ) and all(
        candidate.get(path) == ("file", *expected)
        for path, expected in B035_CLOSEOUT_TARGETS.items()
    )):
        return False
    if any(candidate.get(path, ("", 0, ""))[:2] != ("file", 0o644)
           for path in B035_CLOSEOUT_DYNAMIC_PATHS):
        return False
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=trusted_root,
        check=False, capture_output=True, text=True,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        return False
    ledger_path = "docs/campaigns/remediation/BACKLOG-WP-LEDGER.md"
    snapshot_path = "docs/campaigns/remediation/backlog-ledger-snapshot-v0011.json"
    try:
        ledger = _regular_control(candidate_root, ledger_path)
        normalized = ledger
        for field in ("base-ref", "base-sha"):
            line = f"{field}: {base}".encode()
            if normalized.count(line) != 1:
                return False
            normalized = normalized.replace(line, f"{field}: <BASE>".encode(), 1)
        if hashlib.sha256(normalized).hexdigest() != B035_CLOSEOUT_LEDGER_TEMPLATE_SHA256:
            return False
        raw = _regular_control(candidate_root, snapshot_path)
        receipt = json.loads(raw)
        if receipt.get("base_commit") != base or receipt.get("ledger_sha256") != hashlib.sha256(ledger).hexdigest():
            return False
        if raw != (json.dumps(receipt, indent=2) + "\n").encode():
            return False
        receipt["base_commit"] = "<BASE>"
        receipt["ledger_sha256"] = "<LEDGER_SHA>"
        template = (json.dumps(receipt, indent=2) + "\n").encode()
        return hashlib.sha256(template).hexdigest() == B035_CLOSEOUT_SNAPSHOT_TEMPLATE_SHA256
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return False


def check_candidate_controls(candidate_root: Path, trusted_root: Path, trusted_items: list[Item]) -> None:
    """Fail closed when PR data changes a trusted control in the closure."""
    topology_path = "infra/staging/topology.json"
    candidate_topology = candidate_root / topology_path
    trusted_topology = trusted_root / topology_path
    try:
        candidate_topology.lstat()
        candidate_has_topology = True
    except FileNotFoundError:
        candidate_has_topology = False
    try:
        trusted_topology.lstat()
        trusted_has_topology = True
    except FileNotFoundError:
        trusted_has_topology = False
    if candidate_has_topology != trusted_has_topology:
        topology_changed = True
    elif not candidate_has_topology:
        topology_changed = False
    else:
        try:
            topology_changed = _regular_control(candidate_root, topology_path) != _regular_control(
                trusted_root, topology_path
            )
        except RuntimeError:
            topology_changed = True
    staging_custom_domain_transition = topology_changed and _preauthorized_staging_custom_domain(
        candidate_root, trusted_root
    )
    staging_d1_binding_proxy_transition = topology_changed and _preauthorized_staging_d1_binding_proxy(
        candidate_root, trusted_root
    )
    i1648_transition = _preauthorized_exact_staging_transition(
        candidate_root, trusted_root, STAGING_I1648_PREIMAGES, STAGING_I1648_TARGETS,
        (STAGING_D1_BINDING_PROXY_TARGETS,),
    )
    b216_transition = _preauthorized_exact_staging_transition(
        candidate_root, trusted_root, STAGING_B216_PREIMAGES, STAGING_B216_TARGETS,
        (STAGING_D1_BINDING_PROXY_TARGETS, STAGING_I1648_TARGETS),
    )
    i2568_transition = _preauthorized_exact_staging_transition(
        candidate_root, trusted_root, STAGING_I2568_PREIMAGES, STAGING_I2568_TARGETS,
        (STAGING_D1_BINDING_PROXY_TARGETS, STAGING_I1648_TARGETS, STAGING_B216_TARGETS),
    )
    b035_transition: bool | None = None
    for relative in sorted(_candidate_control_paths(trusted_root, trusted_items)):
        trusted = _regular_control(trusted_root, relative)
        candidate = _regular_control(candidate_root, relative)
        if candidate != trusted:
            if (
                relative in STAGING_CUSTOM_DOMAIN_PREIMAGES
                and staging_custom_domain_transition
            ) or (
                relative in STAGING_D1_BINDING_PROXY_TARGETS
                and staging_d1_binding_proxy_transition
            ) or (relative in STAGING_I1648_TARGETS and i1648_transition) or (
                relative in STAGING_B216_TARGETS and b216_transition
            ) or (relative in STAGING_I2568_TARGETS and i2568_transition):
                continue
            if relative == "scripts/verify_b057_sli.py" and _preauthorized_b057_c0(
                candidate_root, trusted_root
            ):
                continue
            if relative == "scripts/verify_b029_load_gate.py" and _preauthorized_b029_load_gate(
                candidate_root, trusted_root
            ):
                continue
            if relative in {"scripts/verify_b072_receiver.py", "scripts/test_b072_receiver_mutations.py"} and _preauthorized_i1652_receiver(
                candidate_root, trusted_root
            ):
                continue
            if relative in {"scripts/verify_b155_owned.py", "scripts/verify_owner_action_packets.py"}:
                if b035_transition is None:
                    b035_transition = _preauthorized_b035_closeout(candidate_root, trusted_root)
                if b035_transition:
                    continue
            raise RuntimeError(
                f"candidate mutated trusted backlog control {relative}; "
                "candidate verifier code is data-only and was not executed"
            )


def check_candidate_staging_topology(candidate_root: Path, trusted_root: Path) -> None:
    """Reject topology-only or malformed changes after ledger diagnostics."""
    topology_path = "infra/staging/topology.json"
    candidate_topology = candidate_root / topology_path
    trusted_topology = trusted_root / topology_path
    try:
        candidate_topology.lstat()
        candidate_has_topology = True
    except FileNotFoundError:
        candidate_has_topology = False
    try:
        trusted_topology.lstat()
        trusted_has_topology = True
    except FileNotFoundError:
        trusted_has_topology = False
    if candidate_has_topology != trusted_has_topology:
        topology_changed = True
    elif not candidate_has_topology:
        topology_changed = False
    else:
        try:
            topology_changed = _regular_control(candidate_root, topology_path) != _regular_control(
                trusted_root, topology_path
            )
        except RuntimeError:
            topology_changed = True
    if topology_changed and not (
        _preauthorized_staging_custom_domain(candidate_root, trusted_root)
        or _preauthorized_staging_d1_binding_proxy(candidate_root, trusted_root)
    ):
        raise RuntimeError("candidate mutated unapproved staging topology; candidate data was not executed")


def validate_candidate_transitions(
    candidate_items: list[Item], trusted_items: list[Item], today: dt.date,
    *, allow_sprint3_rewrite: bool = False, allow_b154_reconciliation: bool = False,
    allow_v0006_reconciliation: bool = False,
    allow_v0007_reconciliation: bool = False,
    allow_v0009_reconciliation: bool = False,
    allow_v0010_reconciliation: bool = False,
    allow_b035_reconciliation: bool = False,
    successor_mode: bool = False
) -> list[str]:
    """Validate the small, auditable set of BACKLOG changes a PR may make."""
    trusted_by_id = {item.id: item for item in trusted_items if item.raw}
    candidate_by_id = {item.id: item for item in candidate_items if item.raw}
    errors: list[str] = []
    allowed_status = {
        "open": {"open", "parked", "done"},
        "parked": {"parked", "open", "done"},
        "done": {"done"},
    }
    for item in candidate_items:
        if not item.raw or item.id not in trusted_by_id:
            if item.raw.get("status") != "open":
                errors.append(f"new item {item.id} must start status: open")
            if successor_mode and item.raw.get("verify") != "manual":
                errors.append(f"new item {item.id} must use non-executable verify: manual")
            continue
        old = trusted_by_id[item.id]
        old_raw, new_raw = old.raw, item.raw
        v0006_fields = {
            "B-028": {"verify-means"},
            "B-101": {"verify-means"},
            "B-210": {"next-action", "acceptance", "verify"},
            "B-216": {"verify-means"},
            "B-229": {"next-action", "acceptance", "verify"},
        }
        v0007_fields = {"B-083": {"verify-means"}}
        v0009_fields = {"B-057": {"verify-means"}}
        v0010_fields = {"B-114": {"verify", "verify-means"}}
        for item_field in IMMUTABLE_ITEM_FIELDS:
            if old_raw.get(item_field) != new_raw.get(item_field):
                if item.id == "B-035" and item_field == "verify" and allow_b035_reconciliation:
                    continue
                if (
                    allow_v0006_reconciliation
                    and item.id in v0006_fields
                    and item_field in v0006_fields[item.id]
                ) or (
                    allow_v0007_reconciliation
                    and item.id in v0007_fields
                    and item_field in v0007_fields[item.id]
                ) or (
                    allow_v0009_reconciliation
                    and item.id in v0009_fields
                    and item_field in v0009_fields[item.id]
                ) or (
                    allow_v0010_reconciliation
                    and item.id in v0010_fields
                    and item_field in v0010_fields[item.id]
                ):
                    continue
                # The B-089 successor may add only this already-BASE-owned
                # owner-packet gate. A receipt cannot authorize arbitrary
                # candidate verifier code or shell fragments.
                if item_field == "verify" and allow_sprint3_rewrite and item.id == "B-089" and (
                    old_raw.get("verify") == "python3 scripts/verify_b089_sla_credits.py\n"
                    and new_raw.get("verify") == (
                        "python3 scripts/verify_b089_sla_credits.py && "
                        "python3 -S scripts/verify_owner_action_packets.py --id B-089"
                    )
                ):
                    continue
                # The reviewed B-154 repair is a fail-closed conjunction;
                # never turn the pinned exception into an arbitrary shell slot.
                if item_field == "verify" and (
                    allow_sprint3_rewrite or allow_b154_reconciliation
                ) and item.id == "B-154" and (
                    isinstance(old_raw.get("verify"), str)
                    and hashlib.sha256(old_raw["verify"].encode()).hexdigest()
                    == (
                        B154_SPRINT3_VERIFY_SHA256
                        if allow_sprint3_rewrite
                        else B154_LEGACY_VERIFY_SHA256
                    )
                    and new_raw.get("verify") == (
                        "python3 -S scripts/verify_owner_action_packets.py --id B-154 &&\n"
                        "python3 -S scripts/verify_b154_instrument_claims.py --self-test\n"
                    )
                ):
                    continue
                errors.append(f"{item.id}: immutable field {item_field!r} changed")
        for item_field in set(old_raw) | set(new_raw):
            if item_field not in IMMUTABLE_ITEM_FIELDS | ALLOWED_TRANSITION_FIELDS:
                if old_raw.get(item_field) != new_raw.get(item_field):
                    if (
                        allow_v0006_reconciliation
                        and item.id in v0006_fields
                        and item_field in v0006_fields[item.id]
                    ) or (
                        allow_v0007_reconciliation
                        and item.id in v0007_fields
                        and item_field in v0007_fields[item.id]
                    ) or (
                        allow_v0009_reconciliation
                        and item.id in v0009_fields
                        and item_field in v0009_fields[item.id]
                    ):
                        continue
                    errors.append(f"{item.id}: unsupported field {item_field!r} changed")
        old_status, new_status = old_raw.get("status"), new_raw.get("status")
        if new_status not in allowed_status.get(old_status, set()):
            errors.append(f"{item.id}: status transition {old_status!r} -> {new_status!r} is not allowed")
        if old_raw.get("owner") != new_raw.get("owner") and old_status == new_status:
            errors.append(f"{item.id}: owner may change only with a status transition")
        if old_raw.get("verify-means") != new_raw.get("verify-means") and old_status == new_status:
            if not ((allow_v0006_reconciliation and item.id in v0006_fields
                     and "verify-means" in v0006_fields[item.id])
                    or (allow_v0007_reconciliation and item.id in v0007_fields
                        and "verify-means" in v0007_fields[item.id])
                    or (allow_v0009_reconciliation and item.id in v0009_fields
                        and "verify-means" in v0009_fields[item.id])
                    or (allow_v0010_reconciliation and item.id in v0010_fields
                        and "verify-means" in v0010_fields[item.id])
                    or (allow_sprint3_rewrite and item.id in {
                "B-012", "B-065", "B-087", "B-089", "B-097", "B-154", "B-170",
            }) or (allow_b154_reconciliation and item.id == "B-154")):
                errors.append(f"{item.id}: verify-means may change only with a status transition")
        try:
            old_date, new_date = parse_date(old_raw["last-verified"]), parse_date(new_raw["last-verified"])
            if new_date < old_date or new_date > today:
                errors.append(f"{item.id}: last-verified must move forward and not be future-dated")
        except Exception:
            pass  # validate_schema reports the precise date error
    missing = sorted(set(trusted_by_id) - set(candidate_by_id))
    if missing:
        errors.append("candidate deleted BASE item(s): " + ", ".join(missing))
    return errors


def validate_dense_id_population(items: list[Item]) -> list[str]:
    """Require a dense primary B sequence plus the immutable B-1630 alias."""
    item_ids = {item.id for item in items}
    errors: list[str] = []
    for item_id, external_issue in HISTORICAL_EXTERNAL_ISSUE_IDS.items():
        if item_id not in item_ids:
            errors.append(
                f"missing history-backed external issue identity {item_id} "
                f"(GitHub issue #{external_issue})"
            )

    primary_numbers = sorted(
        int(match.group(1))
        for item in items
        if item.id not in HISTORICAL_EXTERNAL_ISSUE_IDS
        and (match := re.fullmatch(r"B-(\d+)", item.id))
    )
    present = set(primary_numbers)
    sequence_max = max(CANONICAL_B_ID_PREFIX_MAX, max(primary_numbers, default=0))
    missing = sorted(set(range(1, sequence_max + 1)) - present)
    if missing:
        ranges: list[tuple[int, int]] = []
        start = previous = missing[0]
        for number in missing[1:]:
            if number == previous + 1:
                previous = number
                continue
            ranges.append((start, previous))
            start = previous = number
        ranges.append((start, previous))
        rendered = ", ".join(
            f"B-{first:03d}" if first == last else f"B-{first:03d}..B-{last:03d}"
            for first, last in ranges
        )
        errors.append(
            f"missing {rendered} in the canonical B-ID sequence — ids must be dense; "
            "restore a real item or mark it retired in place"
        )
    return errors


def validate_candidate_workflow(candidate_root: Path, trusted_root: Path | None = None) -> None:
    """Inspect workflow policy as data; never execute the candidate workflow."""
    text = _regular_control(candidate_root, ".github/workflows/backlog-verify.yml").decode("utf-8")
    try:
        document = yaml.load(text, Loader=_NoDuplicateKeysLoader) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"candidate workflow policy is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise RuntimeError("candidate workflow policy must be a YAML mapping")
    required = (
        "pull_request_target:",
        "github.event.pull_request.head.sha || github.sha",
        "github.event.pull_request.base.sha || github.sha",
        "types: [opened, synchronize, reopened]",
        "persist-credentials: false",
        'paths: ["**"]',
        "permissions:\n  contents: read",
        "--candidate-file",
        "--trusted-file",
        "--trusted-semantic",
    )
    missing = [fragment for fragment in required if fragment not in text]
    if missing:
        raise RuntimeError("candidate workflow policy missing: " + ", ".join(missing))
    forbidden = (
        "pull_request:\n", "refs/pull/", "pull_request.head.ref", "pull_request.base.ref",
        "shell" + "=" + "True", "bash" + " " + "-c",
    )
    found = [fragment for fragment in forbidden if fragment in text]
    if found:
        raise RuntimeError("candidate workflow contains mutable/credentialed execution policy: " + ", ".join(found))

    # The workflow is not executed for this PR, but it becomes the BASE control
    # plane after merge. All YAML keys that can alter runner execution are
    # closed-world, including inherited env/defaults and per-step overrides.
    # Otherwise a job-level BASH_ENV can source candidate bytes before the
    # pinned BASE gate runs despite every named step appearing unchanged.
    trigger_keys = {key for key in (True, "on") if key in document}
    if len(trigger_keys) != 1 or set(document) != {
        "name", *trigger_keys, "permissions", "concurrency", "jobs"
    } or document.get("name") != "backlog-verify":
        raise RuntimeError("candidate workflow policy has unexpected top-level keys")
    trigger = document[next(iter(trigger_keys))]
    if not isinstance(trigger, dict) or set(trigger) != {
        "pull_request_target", "push", "schedule", "workflow_dispatch"
    }:
        raise RuntimeError("candidate workflow policy has unexpected triggers")
    pr_trigger = trigger.get("pull_request_target") if isinstance(trigger, dict) else None
    push_trigger = trigger.get("push") if isinstance(trigger, dict) else None
    if not isinstance(pr_trigger, dict) or pr_trigger != {
        "types": ["opened", "synchronize", "reopened"], "paths": ["**"]
    }:
        raise RuntimeError("candidate workflow policy has unexpected pull_request_target types")
    if not isinstance(push_trigger, dict) or push_trigger != {"branches": ["main"], "paths": ["**"]}:
        raise RuntimeError("candidate workflow policy has unexpected main push trigger")
    if trigger["schedule"] != [{"cron": "17 6 * * *"}] or trigger["workflow_dispatch"] != {}:
        raise RuntimeError("candidate workflow policy has unexpected schedule or dispatch trigger")
    if document.get("permissions") != {"contents": "read"}:
        raise RuntimeError("candidate workflow policy must grant contents: read only")
    legacy_group = "ci-backlog-verify-${{ github.event_name }}-${{ github.ref }}"
    pr_number_group = (
        "ci-backlog-verify-${{ github.event_name }}-"
        "${{ github.event.pull_request.number || github.ref }}"
    )
    trusted_workflow_root = trusted_root or Path(__file__).resolve().parents[1]
    trusted_text = _regular_control(
        trusted_workflow_root, ".github/workflows/backlog-verify.yml"
    ).decode("utf-8")
    try:
        trusted_document = yaml.load(trusted_text, Loader=_NoDuplicateKeysLoader) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"trusted workflow policy is not valid YAML: {exc}") from exc
    trusted_concurrency = (
        trusted_document.get("concurrency") if isinstance(trusted_document, dict) else None
    )
    trusted_group = (
        trusted_concurrency.get("group") if isinstance(trusted_concurrency, dict) else None
    )
    if (
        not isinstance(trusted_concurrency, dict)
        or set(trusted_concurrency) != {"group", "cancel-in-progress"}
        or trusted_concurrency.get("cancel-in-progress") is not True
    ):
        raise RuntimeError("trusted workflow policy has unexpected concurrency settings")
    if trusted_group == legacy_group:
        approved_groups = {legacy_group, pr_number_group}
    elif trusted_group == pr_number_group:
        approved_groups = {pr_number_group}
    else:
        raise RuntimeError("trusted workflow policy has unexpected concurrency settings")
    concurrency = document.get("concurrency")
    if (
        not isinstance(concurrency, dict)
        or set(concurrency) != {"group", "cancel-in-progress"}
        or concurrency.get("group") not in approved_groups
        or concurrency.get("cancel-in-progress") is not True
    ):
        raise RuntimeError("candidate workflow policy has unexpected concurrency settings")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"verify", "trusted_semantic"}:
        raise RuntimeError("candidate workflow policy must contain only the data and trusted jobs")
    checkout_ref = "9f698171ed81b15d1823a05fc7211befd50c8ae0"
    def checkout(name: str, ref: str, path: str, depth: int = 1) -> dict:
        return {
            "name": name,
            "uses": f"actions/checkout@{checkout_ref}",
            "with": {"ref": ref, "path": path, "fetch-depth": depth, "persist-credentials": False},
        }
    expected_gate = (
        'python3 scripts/backlog_verify.py --candidate-file "$CANDIDATE_ROOT/BACKLOG.md" '
        '--trusted-file "$TRUSTED_ROOT/BACKLOG.md" --candidate-root "$CANDIDATE_ROOT" '
        '--trusted-root "$TRUSTED_ROOT"'
    )
    expected_b314_gate = (
        "python3 -S scripts/verify_b314_gdpr_sigstore.py --self-test\n"
        "python3 -m pytest -q tests/test_verify_b314_gdpr_sigstore.py\n"
    )
    expected_b314_dependencies = (
        "set -euo pipefail\n"
        "python3 -m venv .venv\n"
        ".venv/bin/python3 -m pip install --disable-pip-version-check --no-input -r requirements-ci.txt\n"
        ".venv/bin/python3 -m pytest --version\n"
        'echo "$GITHUB_WORKSPACE/_base/.venv/bin" >> "$GITHUB_PATH"\n'
    )
    expected_b046_gate = (
        "python3 scripts/verify_b046_object_lock_probe.py\n"
        "python3 -m unittest -q tests/test_verify_b046_object_lock_probe.py\n"
        "test -f crates/corelink-container/src/routes/dsr/adapter_r2_cas_legalhold.rs\n"
        "test -f migrations/d1/0102_cas_retention.sql\n"
    )
    expected_data = {
        "runs-on": "ubuntu-24.04", "timeout-minutes": 10,
        "env": {"PYTHONDONTWRITEBYTECODE": "1"},
        "steps": [
            checkout("Checkout candidate data (immutable event SHA)",
                     "${{ github.event.pull_request.head.sha || github.sha }}", "_candidate"),
            checkout("Checkout BASE control tree (immutable event SHA)",
                     "${{ github.event.pull_request.base.sha || github.sha }}", "_base", 0),
            {"name": "Validate candidate as data with BASE checker", "working-directory": "_base",
             "env": {"CANDIDATE_ROOT": "${{ github.workspace }}/_candidate",
                     "TRUSTED_ROOT": "${{ github.workspace }}/_base"}, "run": expected_gate},
            {"name": "Prove BASE checker mutation teeth", "working-directory": "_base",
             "run": "python3 -m unittest -q tests/test_backlog_verify_trust_boundary.py"},
            {"name": "Install CI Python dependencies for B-314 tests", "working-directory": "_base",
             "run": expected_b314_dependencies},
            {"name": "Prove BASE B-314 owner-gate mutation teeth", "working-directory": "_base",
             "run": expected_b314_gate},
        ],
    }
    expected_trusted = {
        "if": "github.event_name == 'push' || github.event_name == 'schedule'",
        "runs-on": "ubuntu-24.04", "timeout-minutes": 10,
        "permissions": {"contents": "read", "vulnerability-alerts": "read"},
        "steps": [
            {"name": "Checkout trusted main (immutable event SHA)",
             "uses": f"actions/checkout@{checkout_ref}",
             "with": {"ref": "${{ github.sha }}", "path": "_base",
                      "fetch-depth": 0, "persist-credentials": False}},
            {"name": "Execute trusted main semantic checks", "working-directory": "_base",
             "run": "python3 scripts/backlog_verify.py --trusted-semantic --exclude-auth-checks"},
            {"name": "Execute authenticated Dependabot semantic checks", "working-directory": "_base",
             "env": {"GH_TOKEN": "${{ github.token }}"},
             "run": "python3 scripts/backlog_verify.py --trusted-semantic --auth-only"},
            {"name": "Execute B-046 Object-Lock contract and mutation checks", "working-directory": "_base",
             "run": expected_b046_gate},
        ],
    }
    verify_job = jobs["verify"]
    trusted_job = jobs["trusted_semantic"]
    if not isinstance(verify_job, dict) or verify_job.get("runs-on") != "ubuntu-24.04":
        raise RuntimeError("candidate workflow policy has unexpected verify runner")
    if not isinstance(trusted_job, dict) or trusted_job.get("runs-on") != "ubuntu-24.04":
        raise RuntimeError("candidate workflow policy has unexpected trusted semantic runner")
    if verify_job != expected_data or trusted_job != expected_trusted:
        raise RuntimeError("candidate workflow policy has unexpected data/trusted job shape")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", help="check a single item")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS,
                    help="how long a `verify: manual` item may go unchecked")
    ap.add_argument("--today", help="override today's date (YYYY-MM-DD), for testing")
    ap.add_argument("--file", help="check a different backlog file (used by the self-test)")
    ap.add_argument("--candidate-file", help="PR BACKLOG.md; parsed as data only")
    ap.add_argument("--trusted-file", help="trusted-base BACKLOG.md paired with --candidate-file")
    ap.add_argument("--candidate-root", help="PR checkout root paired with --candidate-file")
    ap.add_argument("--trusted-root", help="trusted checkout root paired with --candidate-file")
    ap.add_argument(
        "--trusted-semantic", action="store_true",
        help="execute declarations from this immutable trusted checkout (push/schedule only)",
    )
    semantic_selection = ap.add_mutually_exclusive_group()
    semantic_selection.add_argument("--exclude-auth-checks", action="store_true")
    semantic_selection.add_argument("--auth-only", action="store_true")
    args = ap.parse_args()

    candidate_mode = bool(args.candidate_file)
    if bool(args.candidate_file) != bool(args.trusted_file):
        print("FATAL: --candidate-file and --trusted-file must be supplied together", file=sys.stderr)
        return 2
    if candidate_mode and (not args.candidate_root or not args.trusted_root):
        print("FATAL: candidate mode requires --candidate-root and --trusted-root", file=sys.stderr)
        return 2
    if args.trusted_semantic and (candidate_mode or args.file):
        print("FATAL: --trusted-semantic cannot be combined with candidate or fixture mode", file=sys.stderr)
        return 2
    if args.trusted_semantic and os.environ.get("GITHUB_EVENT_NAME") not in {"push", "schedule"}:
        print("FATAL: --trusted-semantic is restricted to push/schedule workflow events", file=sys.stderr)
        return 2
    if (args.exclude_auth_checks or args.auth_only) and not args.trusted_semantic:
        print("FATAL: auth-check selection requires --trusted-semantic", file=sys.stderr)
        return 2
    if (args.exclude_auth_checks or args.auth_only) and args.id:
        print("FATAL: split semantic workflow modes must evaluate their full partition", file=sys.stderr)
        return 2

    execution_mode = "fixture" if args.file else "trusted" if args.trusted_semantic else "candidate"

    candidate_root = Path(args.candidate_root).resolve() if candidate_mode else None
    path = Path(args.candidate_file).resolve() if candidate_mode else Path(args.file).resolve() if args.file else BACKLOG_PATH
    if candidate_mode and (path != candidate_root / "BACKLOG.md" or not path.is_file() or path.is_symlink()):
        print("FATAL: candidate BACKLOG.md must be a regular file in the candidate root", file=sys.stderr)
        return 2
    if not path.exists():
        print(f"FATAL: {path} does not exist", file=sys.stderr)
        return 2

    today = dt.datetime.strptime(args.today, "%Y-%m-%d").date() if args.today else dt.date.today()
    try:
        if path.stat().st_size > MAX_BACKLOG_BYTES:
            print(f"FATAL: {path.name} exceeds {MAX_BACKLOG_BYTES} bytes", file=sys.stderr)
            return 2
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"FATAL: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    items = parse(text)
    trusted_by_id: dict[str, Item] | None = None
    authorized_verify_deltas: dict[str, tuple[str, str]] = {}
    if candidate_mode:
        trusted_path = Path(args.trusted_file).resolve()
        if not trusted_path.is_file() or trusted_path.is_symlink():
            print(f"FATAL: trusted backlog is not a regular file: {trusted_path}", file=sys.stderr)
            return 2
        if trusted_path.stat().st_size > MAX_BACKLOG_BYTES:
            print(f"FATAL: trusted BACKLOG.md exceeds {MAX_BACKLOG_BYTES} bytes", file=sys.stderr)
            return 2
        trusted_items = parse(trusted_path.read_text(encoding="utf-8"))
        trusted_by_id = {item.id: item for item in trusted_items if item.raw}
        if len(trusted_by_id) != len(trusted_items) or any(item.verdict == BROKEN for item in trusted_items):
            print("FATAL: trusted-base BACKLOG.md is not parseable; refusing candidate validation", file=sys.stderr)
            return 2
        try:
            check_candidate_controls(
                candidate_root,
                Path(args.trusted_root).resolve(),
                trusted_items,
            )
            if __package__:
                from scripts import verify_backlog_wp_ledger as ledger
            else:
                import verify_backlog_wp_ledger as ledger

            trusted_root = Path(args.trusted_root).resolve()
            try:
                if ledger.successor_required(trusted_root, candidate_root):
                    receipt = ledger.validate_candidate_successor(
                        trusted_root, candidate_root, today=today,
                    )
                    authorized_ids = set(receipt["changed_ids"])
                    candidate_by_id = {item.id: item for item in items if item.raw}
                    for item_id in authorized_ids:
                        trusted_item = trusted_by_id.get(item_id)
                        candidate_item = candidate_by_id.get(item_id)
                        if trusted_item is None or candidate_item is None:
                            continue
                        old_verify = trusted_item.raw.get("verify")
                        new_verify = candidate_item.raw.get("verify")
                        if isinstance(old_verify, str) and isinstance(new_verify, str) and old_verify != new_verify:
                            authorized_verify_deltas[item_id] = (old_verify, new_verify)
                else:
                    transition_errors = validate_candidate_transitions(items, trusted_items, today)
                    if transition_errors:
                        raise RuntimeError("candidate transition rejected:\n" + "\n".join(transition_errors))
            except ledger.LedgerError as exc:
                raise RuntimeError(f"candidate ledger successor rejected: {exc}") from exc
            check_candidate_staging_topology(candidate_root, trusted_root)
            validate_candidate_workflow(candidate_root, trusted_root)
        except (OSError, RuntimeError) as exc:
            print(f"FATAL: {exc}", file=sys.stderr)
            return 2

    if not items:
        # An empty backlog is not a pass. It is far more likely that the format
        # broke, or the file was truncated, than that there is genuinely no work.
        print(f"FATAL: {path.name} contains no parseable ```backlog blocks", file=sys.stderr)
        return 2

    # Each block must sit under a heading that names the SAME id. Checked before
    # the per-item verifies so a mislabelled item cannot be "confirmed" under a
    # heading that describes different work.
    headings = [(m.start(), m.group(1)) for m in HEADING_RE.finditer(text)]
    mismatches: list[str] = []
    # An id that is not `B-<digits>` used to be SKIPPED here, and that silence was
    # the gate failing OPEN (B-143): `id: B-UNALLOCATED`, `B-131a`, `b-131` and
    # `B-TBD` all merged CONFIRMED. The heading check skipped them, and the density
    # check below only collects ids matching `B-(\d+)` — so a malformed id opens no
    # gap, collides with nothing, and is counted by nothing. The two checks that DO
    # fail loudly (missing id = gap, duplicate id) both presuppose a well-formed id.
    # The rule must be the GENERAL form, never a match on the literal placeholder:
    # a gate that greps for `B-UNALLOCATED` is decorative.
    malformed_ids: list[str] = []
    non_positive_ids: list[str] = []
    for m in BLOCK_RE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        block_id = ""
        try:
            data = yaml.load(m.group(1), Loader=_NoDuplicateKeysLoader) or {}
            if isinstance(data, dict):
                block_id = str(data.get("id", ""))
        except yaml.YAMLError:
            continue  # already reported as BROKEN by parse()
        # B-167 — THE CANONICAL FORM, and the choice the item required be made.
        #
        # `^B-\d+$` was necessary and NOT sufficient. `B-0142` satisfies it and
        # coexists with the real `B-142`: density does `int("0142") == 142` so the
        # sequence stays dense, the duplicate check compares STRINGS so nothing
        # collides, and a `### B-0142` heading satisfies the heading/block check.
        # Two items every human reads as one number, both CONFIRMED, and every
        # `[B-142]` citation from outside resolving to whichever one it hits.
        #
        # Of the three rules B-167 enumerated, this is the THIRD: the spelling must
        # equal `f"B-{int(n):03d}"`.
        #   - NOT `^B-\d{3}$`: that closes the hole exactly for today's ids and
        #     forbids the day there is a `B-1000`.
        #   - NOT normalising only the duplicate key: that accepts the spelling and
        #     rejects only the collision, so `B-0500` would still merge as a lone
        #     item and read as a different number than it is.
        # This one canonicalises WITHOUT freezing the width — `B-1000` round-trips
        # (`f"B-{1000:03d}" == "B-1000"`), and all 167 ids today already satisfy it.
        canonical = ""
        if (mm := re.fullmatch(r"B-(\d+)", block_id)):
            number = int(mm.group(1))
            if number <= 0:
                non_positive_ids.append(
                    f"  line {line}: block `id: {block_id}` is non-positive — write it as `B-001` or greater"
                )
                continue
            canonical = f"B-{number:03d}"
        if not canonical:
            malformed_ids.append(
                f"  line {line}: block `id: {block_id or '<missing>'}` is not `B-<digits>`"
            )
            continue
        if block_id != canonical:
            malformed_ids.append(
                f"  line {line}: block `id: {block_id}` is not canonical — write it as "
                f"`{canonical}`. A zero-padded variant aliases the real item silently: "
                f"density satisfies int(), and the duplicate check compares strings"
            )
            continue
        prior = [h for pos, h in headings if pos < m.start()]
        if not prior:
            mismatches.append(f"  line {line}: block `id: {block_id}` has no `### B-…` heading above it")
        elif prior[-1] != block_id:
            mismatches.append(f"  line {line}: heading says {prior[-1]}, block says id: {block_id}")
    # The loop above walks BLOCKS and finds their heading. It is therefore blind
    # to the reverse failure: a heading whose block LOST ITS FENCE — a conflict
    # resolution that ate the ```backlog line, or the `id:` inside it. That item
    # simply stops existing for every check in this file, and the gate reports
    # all-green over the survivors. Observed 2026-08-31: 129 headings, 128 parsed
    # blocks, `confirmed=128, drifted=0, broken=0`. The item would have merged
    # green and vanished from the register.
    #
    # An item that is missing is indistinguishable from an item that is malformed
    # unless something compares the two populations. This does that.
    #
    # SCOPE, stated because the prose is what survives: the density rule above
    # already catches an item lost from the MIDDLE of the file (it leaves a gap).
    # The blind window is the item with the MAXIMUM id — the only one whose loss
    # leaves the sequence dense. That is the freshly added item, which is exactly
    # the one most likely to be born from a conflict resolution.
    # POSITION, not parseability. A block whose YAML is unparseable IS a block —
    # `parse()` already reports it as BROKEN (exit 1), and treating it as absent
    # here would upgrade every malformed-YAML case to a FATAL exit 2 and swallow
    # the more precise diagnosis. Caught by this repo's own gate-for-gates suite:
    # `FAIL  unparseable YAML is BROKEN (exit 2, want 1)`.
    #
    # So the question is only: does a fence open between this heading and the
    # next one? A heading with no fence at all is the item that vanishes.
    #
    # This check — and ONLY this check — reads headings from a fence-MASKED copy.
    # `### B-NN` inside a fenced block is an EXAMPLE, not an item: documenting the
    # item format inside BACKLOG.md itself would otherwise be flagged as an item
    # whose block is missing, naming an id that does not exist.
    #
    # The mask must NOT feed the divergence loop above. Fence pairing is
    # SEQUENTIAL from the top of the file, so the very defect this check hunts —
    # a lost fence opener — leaves an odd count and shifts EVERY later pairing by
    # one. Each subsequent `### B-NN` then falls inside a region believed to be
    # fenced and drops out of `headings`, and the divergence loop attributes every
    # later block to the last surviving heading. Measured on the real BACKLOG.md
    # (129 items) with B-062's opener removed: masked headings produced 64 spurious
    # `heading says B-062, block says id: B-0NN` lines and returned before the
    # density rule could run; unmasked headings give `FATAL: BACKLOG.md is missing
    # B-062 — ids must be dense.`, one exact line, as `main` did. Losing the LAST
    # item's fence — the case this check exists for — misaligns no block from its
    # heading, so the divergence loop stays silent and the orphan check is reached
    # intact either way. Masked here, unmasked there.
    #
    # SCOPE of the mask, not fixed here because it is unreachable today: `^```
    # only sees a fence in COLUMN 0. Measured 2026-08-31, BACKLOG.md carries 0
    # indented (`^\s+``` `) fences and 0 `~~~` fences — every fence in it opens in
    # column 0, so the mask pairs all of them. A `### B-NN` written in column 0
    # *inside* an indented fence, or a `~~~` fence, would still register as a
    # phantom heading here. Neither construct exists in the file; if one is ever
    # added, this mask needs a real fence tokenizer rather than a regex.
    masked = re.sub(
        r"^```.*?^```",
        lambda m: re.sub(r"[^\n]", " ", m.group(0)),
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    masked_headings = [(m.start(), m.group(1)) for m in HEADING_RE.finditer(masked)]
    block_starts = [m.start() for m in BLOCK_RE.finditer(text)]
    bounds = [pos for pos, _ in masked_headings] + [len(text)]
    orphan_headings = [
        h
        for i, (pos, h) in enumerate(masked_headings)
        if not any(pos < b < bounds[i + 1] for b in block_starts)
    ]
    # Named separately from `mismatches` on purpose. Both exit 2, but the FATAL
    # below says "a heading and its block disagree", which is FALSE for a
    # malformed id — the heading may agree perfectly. A gate whose own message
    # misdescribes what it caught is the prose that lies first.
    if malformed_ids:
        print(
            "FATAL: backlog block(s) with an id that is not `B-<digits>`.\n"
            + "\n".join(malformed_ids)
            + "\nA placeholder or malformed id is invisible to BOTH loud checks: it opens\n"
            "no gap in the density rule and collides with nothing, so it merges in\n"
            "silence. Allocate the real id before merging.\n"
            "A non-canonical id is rejected before density or duplicate checks, so it cannot\n"
            "silently alias another item. Allocate the canonical positive id before merging.",
            file=sys.stderr,
        )
        return 2

    if non_positive_ids:
        print(
            "FATAL: backlog block(s) with a non-positive id.\n"
            + "\n".join(non_positive_ids)
            + "\nIds are positive integers; B-000 and other zero forms are not allocatable.",
            file=sys.stderr,
        )
        return 2

    if mismatches:
        print(
            "FATAL: a heading and its block disagree about which item they are.\n"
            + "\n".join(mismatches)
            + "\nEvery reference from outside this file cites the HEADING; the gate reads\n"
            "the block. When they diverge the register points the wrong way and nothing\n"
            "notices, because both ids can still be unique.",
            file=sys.stderr,
        )
        return 2

    # A deleted item is invisible to per-item checks — every survivor still passes
    # while the record silently loses work. The sequential B-register stays dense;
    # B-1630 is excluded from that sequence only because immutable V0004 records it
    # as the historical external issue identity for GitHub issue #1630. This exact
    # ID remains required, and every other gap is still rejected.
    if orphan_headings:
        print(
            "FATAL: heading(s) sem bloco ```backlog parseavel: "
            + ", ".join(sorted(set(orphan_headings)))
            + "\nO item existe como titulo e NAO existe para nenhuma verificacao deste\n"
            "arquivo — some do portao sem que o portao reclame, porque ele conta o que\n"
            "consegue parsear e nada compara esse numero com quantos titulos ha.\n"
            f"(titulos: {len(masked_headings)}, blocos abertos: {len(block_starts)})",
            file=sys.stderr,
        )
        return 2

    id_population_errors = validate_dense_id_population(items)
    if id_population_errors:
        print("FATAL: invalid BACKLOG.md ID population: " + "; ".join(id_population_errors), file=sys.stderr)
        return 2

    seen: dict[str, int] = {}
    for it in items:
        if it.id in seen:
            it.verdict = BROKEN
            it.detail = f"duplicate id — also declared at line {seen[it.id]}"
        else:
            seen[it.id] = it.line

    selected = [i for i in items if not args.id or i.id == args.id]
    if args.id and not selected:
        print(f"FATAL: no backlog item with id {args.id}", file=sys.stderr)
        return 2
    if args.auth_only:
        if set(i.id for i in selected if i.id in AUTH_VERIFY_COMMANDS) != set(AUTH_VERIFY_COMMANDS):
            print("FATAL: authenticated verifier declaration is missing or selection is incomplete", file=sys.stderr)
            return 2
        if not os.environ.get("GH_TOKEN"):
            print("FATAL: authenticated verifier step has no GH_TOKEN", file=sys.stderr)
            return 2
        selected = [i for i in selected if i.id in AUTH_VERIFY_COMMANDS]
        if any(str(i.raw.get("verify", "")).strip() != AUTH_VERIFY_COMMANDS[i.id] for i in selected):
            print("FATAL: authenticated verifier command differs from the pinned allowlist", file=sys.stderr)
            return 2
    elif args.exclude_auth_checks:
        selected = [i for i in selected if i.id not in AUTH_VERIFY_COMMANDS]

    for it in selected:
        check(
            it,
            today,
            args.max_age_days,
            trusted_by_id=trusted_by_id,
            authorized_verify_deltas=authorized_verify_deltas,
            enforce_manual_age=execution_mode in {"fixture", "trusted"},
            execution_mode=execution_mode,
        )

    if args.format == "json":
        print(json.dumps([{
            "id": i.id, "line": i.line, "status": i.raw.get("status"),
            "owner": i.raw.get("owner"), "repo": i.raw.get("repo"),
            "verdict": i.verdict, "detail": i.detail, "evidence": i.evidence,
        } for i in selected], indent=2))
    else:
        width = max((len(i.id) for i in selected), default=8)
        for i in selected:
            print(f"  {i.verdict:9} {i.id:{width}}  {i.raw.get('status','?'):6} {i.detail}")
            if i.verdict in (DRIFTED, BROKEN) and i.evidence:
                print(f"  {'':9} {'':{width}}  └ {i.evidence}")
        counts = {v: sum(1 for i in selected if i.verdict == v) for v in (CONFIRMED, DRIFTED, STALE, BROKEN)}
        print(f"\n  {len(selected)} item(s): " + ", ".join(f"{v.lower()}={n}" for v, n in counts.items()))

    bad = [i for i in selected if i.verdict != CONFIRMED]
    if bad:
        print(f"\nBACKLOG.md disagrees with the repo on {len(bad)} item(s). "
              "Fix the item or fix the world — do not delete the check.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
