# Cordon v0.1 design

Status: approved by the decision owner in `build/03_decision_log.md`. The user
instructed autonomous completion ("continue and keep working until finish and
give me the zip"), which opts out of the interactive question gate. Every
default below is the manager's call, not a user decision.

## Intent and why

Installing an AI agent skill hands an LLM instructions with the user's
privileges. Scanners, pins, per-harness sandboxes and tracing tools exist. The
decision that binds them is missing: you cannot take one scan finding, turn it
into one least-privilege rule, enforce that rule at a tool call, and show the
decision later in a portable ledger. Cordon makes that chain explicit.

The audience is developers who run Claude Code, Codex, Cursor, Gemini CLI or
OpenCode and install third-party skills. Success means a developer can answer
"what did this skill try, and did my contract stop it" in under a minute.

## Goals

- One offline command that produces a visible, reviewable verdict.
- A derived, default-deny capability contract with attributable decisions.
- A content pin with optional Ed25519 signing and immediate re-verification.
- One policy engine shared by a Claude Code PreToolUse hook, a generic JSON
  hook and an advisory PATH shim.
- A portable, hash-chained, replayable ledger.
- Two versioned formats that other harnesses can implement.
- Nine adversarial review rounds and an architecture refactor that provably
  preserves every output.

## Non-goals

A kernel sandbox, a registry, telemetry, a hosted service, Windows or macOS
enforcement backends, a package manager, star acquisition.

## Anti-goals

Calling an advisory shim "enforced". Printing "safe" after a clean scan.
Promising a star count. Blocking merges on documentation prose. Executing
untrusted skill content. Adding a runtime network call.

## Constraints

Real: Python 3.10, offline, stdlib first, `cryptography` imported lazily; no
`git clone` to github.com from this sandbox; one spawnable research sub-agent
type that produces Markdown, so code and QA run as logged passes here. Assumed:
agent-skill adoption keeps growing. Unknown: whether another tool already binds
all five capabilities; the bounded search found none and says so.

## Approaches considered

**A. Scanner only.** Cheap, commodity. Near-clones already ship it
(NVIDIA SkillSpector, Cisco Skill Scanner, skillshare audit, skills.sh audits).
Rejected: no defensible unit of value, no 30-second aha beyond another report.

**B. Published format only.** A spec spreads fast and costs little. Rejected as
a standalone: no runnable proof, so nobody can test whether the format works.
Kept as a component.

**C. Integrated five-stage seam (chosen).** Scan, derive, pin, decide, record.
One finding becomes one rule becomes one denied call becomes one ledger entry.
Higher build cost, but every stage is testable offline and the integration is
the novelty. Ships formats B as part of the work.

**D. OS sandbox first.** Strongest enforcement, weakest reach. Rejected for
v0.1: needs root or platform-specific setup, which excludes most users and
cannot run in this sandbox. Kept as a documented backend upgrade.

## Design

**Modules.** `util` (canonical bytes, ids, bounds), `model` (records),
`fs` (bounded enumeration), `scan` (rules and entity extraction), `manifest`
(derivation, policy hash), `pin` (tree hash, signing), `ledger` (chain, diff),
`hook` (policy decisions), `guard` (advisory shim), `report` (text, JSON,
SARIF), `cli` (commands). Each module has one interface the tests exercise.

**Data.** A `Finding` has a stable id, rule id, severity, confidence,
capability, location and redacted evidence. A manifest is default deny with
`policy_hash` over canonical capabilities. A pin lists sorted file path, mode,
size and SHA-256; `tree_hash` binds the list. A ledger entry carries index,
`prev_hash`, canonical event and `entry_hash`.

**Policy.** Unknown tools and unparseable commands fail closed. Prose matches
get medium severity and medium confidence, so documentation does not block.
High or critical findings with high confidence set `--fail-on high` to exit 1.
Operator grants are recorded with origin `operator`.

**Trust labels.** Every renderer prints an advisory disclaimer. `guard` prints
an advisory notice before launch. `SECURITY.md` lists the bypasses. No command
claims enforcement.

**Exit codes.** 0 success, 1 findings or error, 2 usage, 3 integrity failure,
126 denied by policy, 130 interrupted.

## What is left to the builder

Rule tuning against a public corpus, adapter conformance tests for each
harness, OS backends, encrypted-key storage in an OS keychain, and a published
false-positive rate. None of these changes the v0.1 formats.

## Revisit triggers

A maintained tool that binds all five capabilities; failure of AT-07; a
false-positive rate above the documented threshold on the benign corpus; a
bypass described as enforced rather than advisory.
