### Fixed

- **The B-089 SLA checks failed on `main` because they pinned the SLA v1.0.0
  text from before #2799 (#1655, #2568).** #2799 relabeled
  `legal/sla/v1.0.0.md` as a PRELAUNCH internal draft (`effective_date: null`,
  `legal_review_status: "pending"`). The earlier text falsely claimed an
  approved, effective SLA with counsel sign-off, and there are no customers.
  Since then, `verify_b089_credit_contract.py` and
  `verify_owner_action_packets.py --id B-089` have exited 1. Nothing reported
  it because their lane, `issue-1655-b089-contract.yml`, is disabled. Both pins
  now hold the post-#2799 bytes instead of the old ones, because restoring the
  old text would bring back the false approval claim and fail B-154's
  prelaunch-status check. A section-by-section byte comparison shows that every
  credit clause is unchanged: §1 tiers, the §2 uptime and latency targets and
  coverage, the §4.1–4.5 rates, cap and remedy, the §7 30-day claim window and
  §8 termination. Outside the status text, #2799 removed only the Enterprise
  BYOK kill-switch SLO, which had no §4 credit row and is already excluded by
  v1.1.0, and the CMK-revocation carve-out tied to it. Any change to the bytes,
  including a return to the pre-#2799 text, still fails both checks.
