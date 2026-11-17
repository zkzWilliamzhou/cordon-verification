# Session scope — pre-registered before evidence review

**Focal question.** What single open-source program, whose function does not already exist as an integrated tool, can (a) remove a real and widespread pain created by AI coding agents in 2026, (b) be built and verified inside a restricted sandbox, (c) plausibly aim at >105k GitHub stars, and (d) make a genuine difference rather than being a thin wrapper?

**Decision owner.** The manager (this session). Human sign-off is not available in this run; the owner records dissent and uncertainty explicitly instead of hiding it.

**Audience.** Developers who run Claude Code / Codex / Cursor / Gemini CLI / OpenCode and install third-party skills; OSS maintainers; security-conscious teams.

**Time horizon.** Ship a working v0.1 now; adoption is a 12–24 month aspiration.

**In scope.** Problem framing, independent idea generation, novelty check, adversarial review, decision, workflow design, implementation, 8+ review rounds, architecture refactor with behaviour preservation.

**Out of scope.** Actually publishing to GitHub, guaranteeing any star count, claiming legal/certification compliance, human-subjects or safety-critical deployment, medical/financial/legal advice.

**Constraint ledger**
- REAL: sandbox has no `git clone` to github.com (403) but codeload/raw over HTTPS work; Python 3 available; implementation must run offline with stdlib-first dependencies.
- REAL: only one spawnable sub-agent type exists and it produces Markdown research, not code. Implementation and QA therefore run as explicit, logged passes in this session.
- REAL: a star count is an outcome controlled by other people, not by the builder.
- ASSUMED: agent-skill adoption keeps growing; untrusted SKILL.md is a growing attack surface.
- NEGOTIABLE: language, name, scope of v0.1, number of adapters.
- UNKNOWN: whether any single tool already binds provenance + capability manifest + runtime enforcement + attributable audit at one seam.

**Pre-registered criteria and weights (fixed BEFORE scoring)**
| ID | Criterion | Direction | Weight | Anchor 1 / 5 / 10 |
|---|---|---|---|---|
| C1 | Novelty of the *integrated* function (not components) | higher better | 0.20 | 1 = exact clone exists; 5 = components exist, seam unclaimed; 10 = no comparable integration located |
| C2 | Pain breadth & severity | higher better | 0.20 | 1 = niche hobby; 5 = one class of devs; 10 = nearly every agent user |
| C3 | Buildability & verifiability here | higher better | 0.15 | 1 = needs kernel work; 5 = needs external services; 10 = stdlib + tests, fully runnable offline |
| C4 | Time-to-"aha" (demo in <60s) | higher better | 0.10 | 1 = needs setup; 10 = one command, visible result |
| C5 | Distribution surface (agent-agnostic, CI-friendly, spec-able) | higher better | 0.15 | 1 = one harness; 10 = 75+ harnesses + a published format |
| C6 | Integrity / dual-use safety | higher better | 0.10 | 1 = enables harm; 10 = pure defence, auditable |
| C7 | Reversibility & maintenance burden | higher better | 0.10 | 1 = invasive fork; 10 = opt-in wrapper, no upstream changes |

**Vetoes (not averaged).** V1: any idea whose core function is already shipped as a maintained mainstream tool. V2: any idea that requires executing untrusted code to demonstrate value. V3: any idea that only works by spying on or exfiltrating user data. V4: any idea that cannot be tested offline.

**Bias controls used.** Independent round written before evidence search; pseudonymous contributor IDs; leader's preference disclosed only after the independent round; minority and negative evidence retained; adversarial reviewer assigned to each shortlisted idea; scores kept as ranges; decision logged with dissent and revisit triggers.

**Status of evidence at this point:** `not-checked` for every idea. Absence from a bounded search will be recorded as "no direct evidence located", never as "does not exist".
