---
audience: internal_prelaunch_review
classification: not_for_customer_distribution
wi: WI-S14-006
version: "1.2.0"
updated: "2026-09-30"
supersedes: "docs/customer/byok-kill-switch.md at prior revision sha256:3d75eae3abd07a3b86e44123657d4811f4824d2d385d82a0cd4da309d35a2e2c"
---

# CoreLink BYOK — Prelaunch capability notice

> **PRELAUNCH LIMITATION — NO CUSTOMER FEATURE OR SLA.** CoreLink has not
> launched and has no customers. BYOK, customer-managed-key activation, key
> revocation, crypto-erase, and a BYOK kill switch are unavailable and are not
> offered. This document is not for customer distribution.

The repository contains BYOK-related source code, including a real-provider
build feature, but no accepted authenticated lifecycle evidence establishes
customer-controlled KMS operation from the shipped CoreLink runtime. Code,
mock tests, staging configuration, and provider-only experiments are not proof
of a complete service capability.

The former **≤5-minute p99** statement is not a verified measurement, active
SLO, or customer commitment. No kill-switch timing guarantee is made. The
current prelaunch service source uses provider-managed R2 encryption and the
ordinary DSR erasure workflow; BYOK does not cover the shared D1 control plane.

Before any future BYOK offer, the accountable owners must complete the
protected runtime lifecycle and exact-image evidence in #1653/#2165, including
measured revoke/restore timing, then obtain required security, legal, and launch
approvals. Those provider issues remain open; this notice does not close them.

Historical design and procedure text remains available in the prior Git
revision identified in the front matter. It was not evidence that the listed
customer actions, alerts, regional behavior, or timing targets were operational.
