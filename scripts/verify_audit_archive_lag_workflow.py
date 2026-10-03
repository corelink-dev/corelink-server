#!/usr/bin/env python3
"""Check the B-063 detector's protected manual no-page boundary."""

from __future__ import annotations

import re
from pathlib import Path


WORKFLOW = Path(".github/workflows/audit-archive-lag.yml")
PAGERDUTY_GATE = "if: steps.measure.outputs.page == '1' && steps.measure.outputs.notify == 'true'"
ARCHIVE_JOB_GATE = (
    "github.repository_id == vars.CORELINK_SERVER_REPO_ID && "
    "github.ref == 'refs/heads/main' && github.ref_protected == true && "
    "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')"
)
PAGERDUTY_URL = "https://events.pagerduty.com/v2/enqueue"
HOSTED_RUNNER = "runs-on: ubuntu-24.04"
PYTHON_SETUP = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
PYTHON_VERSION = "python-version: '3.12'"
REQUESTS_PIN = "requests==2.32.5"


def _normalized(source: str) -> str:
    return re.sub(r"\s+", " ", source)


def verify(source: str) -> None:
    normalized = _normalized(source)
    archive_match = re.search(
        r"(?ms)^  archive-lag:\n(?P<body>.*?)(?=^  [a-z0-9_-]+:\n|\Z)",
        source,
    )
    if archive_match is None:
        raise AssertionError("missing archive-lag job")
    archive_job = archive_match.group("body")

    required = (
        'default: "read-only"',
        'options: ["read-only", "page"]',
        "NOTIFICATION_MODE: ${{ github.event.inputs.notification_mode || 'read-only' }}",
        'os.environ.get("GITHUB_EVENT_NAME") == "schedule"',
        'os.environ.get("NOTIFICATION_MODE") == "page"',
        "notify={'true' if notify else 'false'}",
        "verdict: **{'PAGE' if page else 'OK'}**",
        PAGERDUTY_GATE,
        ARCHIVE_JOB_GATE,
        PAGERDUTY_URL,
        HOSTED_RUNNER,
        PYTHON_SETUP,
        PYTHON_VERSION,
        REQUESTS_PIN,
    )
    for marker in required:
        if marker not in normalized:
            raise AssertionError(f"missing B-063 monitor invariant: {marker}")

    runner_values = re.findall(
        r"(?m)^    runs-on:[ \t]*(?P<value>[^\r\n#]*)(?:[ \t]*#.*)?$",
        archive_job,
    )
    if len(runner_values) != 1 or runner_values[0].strip() != "ubuntu-24.04":
        raise AssertionError("the archive detector must use the ubuntu-24.04 GitHub-hosted runner")
    if re.search(r"(?im)^\s*continue-on-error\s*:", archive_job):
        raise AssertionError("the archive detector must not suppress job or D1-read failures")
    if _normalized(ARCHIVE_JOB_GATE) not in _normalized(archive_job):
        raise AssertionError("live detector must be limited to protected canonical main")
    if "page = (clause1 and clause2) or (partitions_failed > 0)" not in normalized:
        raise AssertionError("the complete absence and per-partition failure predicate changed")

    final_failure = re.search(
        r"(?ms)^      - name: Fail the job when the archive is absent[^\n]*\n(?P<body>.*?)(?=^      - name:|\Z)",
        source,
    )
    if final_failure is None or "if: steps.measure.outputs.page == '1'" not in final_failure.group("body"):
        raise AssertionError("a red full-detector verdict must still fail read-only runs")
    if "exit 1" not in final_failure.group("body"):
        raise AssertionError("a red full-detector verdict must exit non-zero")

    pagerduty_start = source.find("      - name: PagerDuty SEV-0 page")
    pagerduty_end = source.find("\n      - name:", pagerduty_start + 1)
    pagerduty_step = source[pagerduty_start:pagerduty_end if pagerduty_end >= 0 else None]
    if pagerduty_start < 0 or PAGERDUTY_GATE not in _normalized(pagerduty_step):
        raise AssertionError("PagerDuty requires a failing detector and explicit notification")
    if source.count(PAGERDUTY_URL) != 1:
        raise AssertionError("PagerDuty enqueue must exist exactly once inside its guarded step")
    if re.search(r'(?im)^\s*"(?:UPDATE|INSERT|DELETE|REPLACE|ALTER|DROP|CREATE)\b', source):
        raise AssertionError("D1 SQL literals must remain SELECT-only")
    for action in re.findall(r"uses:\s*([^\s#]+)", source):
        if not re.search(r"@[0-9a-f]{40}$", action):
            raise AssertionError(f"unpinned action reference: {action}")


def verify_adversarial_mutations(source: str) -> None:
    mutations = (
        (source.replace(PAGERDUTY_GATE, "if: steps.measure.outputs.page == '1'", 1), "page without notify gate"),
        (source.replace('default: "read-only"', 'default: "page"', 1), "unsafe manual default"),
        (source.replace("github.ref_protected == true", "github.ref_protected == false", 1), "unprotected run"),
        (source.replace(HOSTED_RUNNER, "runs-on: corelink", 1), "corelink self-hosted runner"),
        (
            source.replace(HOSTED_RUNNER, "runs-on: [self-hosted, corelink]", 1),
            "self-hosted runner label",
        ),
        (source.replace(HOSTED_RUNNER, "runs-on: [corelink]", 1), "corelink runner label"),
        (
            source.replace(HOSTED_RUNNER, "runs-on:\n      - self-hosted\n      - corelink", 1),
            "multiline self-hosted runner labels",
        ),
        (
            source.replace(HOSTED_RUNNER, f"{HOSTED_RUNNER}\n    runs-on: corelink", 1),
            "duplicate runner declaration",
        ),
        (
            source.replace("        id: measure\n", "        id: measure\n        continue-on-error: true\n", 1),
            "inconclusive D1 read ignored",
        ),
        (source.replace("page = (clause1 and clause2) or (partitions_failed > 0)", "page = False", 1), "weakened detector predicate"),
        (
            re.sub(
                r"(?ms)^      - name: Fail the job when the archive is absent[^\n]*\n.*?(?=^      - name:|\Z)",
                "",
                source,
                count=1,
            ),
            "red read-only verdict made green",
        ),
        (source.replace('"SELECT COUNT(*) AS pending_old, MIN(enqueued_at)', '"DELETE FROM audit_outbox', 1), "mutating D1 SQL"),
        (source + f"\n# adversarial unguarded call: {PAGERDUTY_URL}\n", "extra PagerDuty request"),
    )
    for mutated, label in mutations:
        if mutated == source:
            raise AssertionError(f"adversarial fixture did not apply: {label}")
        try:
            verify(mutated)
        except AssertionError:
            continue
        raise AssertionError(f"verifier accepted adversarial mutation: {label}")


def main() -> int:
    source = WORKFLOW.read_text(encoding="utf-8")
    verify(source)
    verify_adversarial_mutations(source)
    print("B-063 protected manual no-page boundary and adversarial checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
