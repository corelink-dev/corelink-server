---
id: "DEMO-60-SEC-ELEVATOR"
type: "marketing"
doc_status: "DRAFT"
audit_status: "ACTIVE"
version: "1.0.0"
created: "2026-05-15"
updated: "2026-05-15"
owner: "VPMkt"
final_approver: "Gustavo Schneiter"
reviewers: ["CTO", "VPSec"]
supersedes: null
superseded_by: null
parent: "marketing/launch/LAUNCH-CHECKLIST-V2.md §2 L? (T-7d demos recorded)"
tags:
  - "marketing"
  - "launch"
  - "demo"
  - "elevator"
  - "r8"
---

# 60-second elevator demo — CoreLink GA

> **Format:** vertical / landscape screen recording (1080×1920 for socials; 1920×1080 for web).
> **Tooling:** asciinema for terminal lane + OBS or screen.studio for narrator + cuts.
> **Voice:** narrator off-screen; CEO can do v2 with face-cam in a vertical bottom-right inset.
> **Tone:** calm, fast, no superlatives. Engineers smell sales spray instantly.
> **Cross-refs:** `5-MIN-DEEPDIVE.md`, `cli-asciinema-script.sh`, `marketing/launch/BLOG-POSTS/01-introducing-corelink.md`.

---

## Time budget — exact

| Beat | Duration | Cumulative | Lane(s) on screen |
|---|---|---|---|
| Hook | 0:00 → 0:05 | 0:05 | Title card + narrator |
| Problem | 0:05 → 0:15 | 0:15 | Animated illustration |
| CLI demo (3 commands) | 0:15 → 0:45 | 0:45 | Terminal (asciinema) full-bleed |
| Outcome (admin-UI shot) | 0:45 → 0:55 | 0:55 | Admin UI screenshot zoom |
| CTA | 0:55 → 1:00 | 1:00 | End-card + URL |

Total = 60 seconds. Hard cap. If you go over, cut the outcome beat to 5s and trim CTA to 4s; never trim CLI.

---

## Beat 1 — Hook (0:00 → 0:05, 5s)

**Visual:** black background, white sans-serif type, dramatic but not loud. Logo bottom-left.

**On-screen text (animated in over 1.5s):**

```
Your build cache is leaking your IP.
```

**Voiceover (spoken at 0:02, ~3s):**

> "Your build cache is leaking your IP. Every CI run, every developer machine, every fine-tuning job."

**Sound:** one short tonal sting at 0:00, then silence under the VO.

**Asset:** static title card PNG `marketing/launch/demos/assets/elevator-hook.png` (to be designed by VPMkt — placeholder until brand pass).

---

## Beat 2 — Problem (0:05 → 0:15, 10s)

**Visual:** simple line illustration — three boxes labeled `Bazel`, `Buck2`, `ML training` all pointing into a single shared bucket labeled `bazel-remote / Redis / S3`. A red dotted line wraps around the bucket labeled "no per-tenant audit, no BYOK, no residency."

**On-screen subtitle (sync with VO):**

```
Today: shared cache, no audit, no per-tenant boundary.
```

**Voiceover (~9s):**

> "Today's shared build caches treat every artifact the same. No per-tenant boundary. No audit trail. No customer-managed keys. That's fine for a hackathon — and a non-starter for anyone shipping under SOC 2, HIPAA, or LGPD."

**Cut hint:** 1-frame whip-pan into terminal at 0:14.99 — feels like the demo "answers" the problem.

---

## Beat 3 — CLI demo (0:15 → 0:45, 30s)

**Visual:** terminal occupies 100% of frame. Use the **`asciinema`** cast produced by `cli-asciinema-script.sh` step 1 (clip 1). Display at **1.5× playback speed** so the three commands feel snappy without looking sped-up. Prompt is the standard `$ ` so it reads as someone's laptop.

**Spoken VO is paced to land BETWEEN command outputs**, never on top of them. Engineers want to read the terminal.

### Sub-beat 3a — Install + auth (0:15 → 0:22, 7s)

**Commands shown (real, copy-pasteable, cross-checked against `crates/corelink-cli/src/main.rs`):**

```bash
$ corelink version
corelink 1.0.0
  git rev:      abc1234
  built:        epoch:1767225600
  target:       aarch64-apple-darwin

$ export CORELINK_PAT="corelink_pat_0123456789ABCDEF.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBA" # synthetic shape
$ corelink doctor
8/8 checks PASS  — net OK, auth OK (tenant=sandbox-7f3a, ttl=23h59m), storage OK, client-verify OK
```

**VO (over the prompt before commands, ~6s):**

> "Single binary. One env var for auth. `corelink doctor` confirms the eight readiness checks before you touch production data."

### Sub-beat 3b — put + get (0:22 → 0:37, 15s)

**Commands shown:**

```bash
$ echo "release-artifact" > build/out.bin
$ corelink put build/out.bin
digest=af1c3e9b…  size=17  uploaded=ok

$ corelink get af1c3e9b… --out /tmp/restored.bin
downloaded 17 bytes, blake3 verified ok
```

**VO (~13s):**

> "Upload a build artifact. CoreLink computes a BLAKE3 digest client-side — the digest *is* the storage key. From any other machine, anywhere on Earth, fetch it back by digest. Bytes are re-verified before they leave the client. Tamper a single bit and the download fails closed."

### Sub-beat 3c — audit (0:37 → 0:45, 8s)

**Commands shown:**

```bash
$ corelink ls --tenant sandbox-7f3a --limit 3
digest          size   age     actor
af1c3e9b…       17 B   23s     pat_a8c2…
…
```

**VO (~7s):**

> "Every put and get is recorded against the tenant — actor, digest, age, IP — visible from the CLI and the admin UI."

---

## Beat 4 — Outcome — admin UI (0:45 → 0:55, 10s)

**Visual:** cut from terminal to a **screenshot of the admin UI Audit page** (`/en/admin/audit`) showing the same `af1c3e9b…` event row that was just produced by the CLI. Highlight ring (subtle, animated draw-in over 0.8s) around the digest column. Then a sub-screenshot zoom of the event detail page (`/en/admin/audit/<event_id>`) revealing Merkle-chain proof reference and signed-attestation badge.

**See `admin-ui-screenshot-guide.md` numbered shots:**

- Shot #06 — `/[locale]/admin/audit` filtered to last 5 minutes
- Shot #07 — `/[locale]/admin/audit/[event_id]` detail with Merkle proof block visible

**On-screen subtitle:**

```
Same digest. Audited. BYOK-encrypted at rest. Per-tenant boundary.
```

**Voiceover (~9s):**

> "Same digest. Audited. BYOK-encrypted at rest. Per-tenant boundary. The audit chain is cryptographically signed — your compliance team replays it against your root of trust, not ours."

---

## Beat 5 — CTA (0:55 → 1:00, 5s)

**Visual:** logo + URL on a clean background.

**On-screen text (final hold for 3s):**

```
humangr.com/corelink  —  10-minute quickstart, free sandbox tenant.
```

**Voiceover (~4s):**

> "CoreLink — generally available today. Ten-minute quickstart, free sandbox tenant. humangr.com/corelink."

**Sound:** same tonal sting as opening, mirrored. End on a half-second of silence over the URL.

---

## Pre-flight checklist (before recording)

- [ ] Sandbox tenant `sandbox-7f3a` provisioned and warm (digest `af1c3e9b…` pre-seeded so timestamps look realistic on Shot #06).
- [ ] `corelink doctor` returns 8/8 on the demo laptop (run once to warm DNS + auth caches).
- [ ] Terminal font: Berkeley Mono or JetBrains Mono at 18pt; window 100 cols × 28 rows.
- [ ] Color scheme: high-contrast (Solarized Light or "Modus Operandi") — soft Dracula colors muddy on social re-encodes.
- [ ] All five blog post URLs from `marketing/launch/BLOG-POSTS/` validated as 200 (the CTA card may rotate URLs).
- [ ] Captions burned-in (accessibility + sound-off social autoplay).

## Cross-reference

- `5-MIN-DEEPDIVE.md` — the long-form version (5 minutes) for the website hero embed.
- `cli-asciinema-script.sh` — provides the cast file used in Beat 3.
- `admin-ui-screenshot-guide.md` — provides screenshots used in Beat 4 (#06 + #07).
- `marketing/launch/LAUNCH-CHECKLIST-V2.md` row L0 (T-7d) — "demos recorded" prerequisite.
- `marketing/launch/BLOG-POSTS/01-introducing-corelink.md` — narrative source for VO copy.
