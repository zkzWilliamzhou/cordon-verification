# Workflow and agent roster (strict manager gates)

The manager owns scope, rejects work, and signs only on evidence. Three research passes ran as delegated sub-agents (Novelty, Security, Adoption) and produced `agentA_novelty.md`, `agentB_security.md`, `agentC_adoption.md`. All other roles below are defined as specialised passes executed in this session, with an input, an output artefact, an acceptance test, and a rejection rule. A pass that produces prose without a runnable artefact is rejected.

| ID | Role | Input | Output | Acceptance | Reject when |
|---|---|---|---|---|---|
| A0 | Manager / boss | scope, all artefacts | `03_decision_log.md`, gate log | every stage has an artefact and a command that ran | any stage claims a test that did not execute |
| A1 | Grill / product | ideation register | `02_grill_and_advisarial.md`, design doc | design tree frontier empty, dissent recorded | unasked decision silently defaults |
| A2 | Architect | design, Agent B | `docs/design/*`, `docs/spec/*`, ADRs, GLOSSARY | formats versioned, trust labels explicit | any "enforced" claim about a pure-Python shim |
| A3 | Implementer | spec | `src/cordon/*`, CLI | `python3 -m cordon --help` works offline | code not runnable, or executes untrusted skill content |
| A4 | Test | spec, code | `tests/*`, conformance snapshots | unittest suite green, AT-01..AT-07 pass | a test that asserts nothing |
| A5 | Red team | code, Agent B | `docs/review/round*.md`, exploit fixtures | each attack has a real command and a real result | a "fixed" bug without a regression test |
| A6 | Docs / stop-slop | code, Agent C | README, SECURITY, CONTRIBUTING, demo | README < 200 words before features, limitations first, no star promise | marketing claims, adverbs, em dashes, "safe" without evidence |
| A7 | Release | everything | CI, Makefile, packaging, zip | clean install and `cordon demo` in < 10s | broken install path |
| A8 | Architecture deepening | code + GLOSSARY + ADRs | HTML report, refactor, equivalence proof | golden before/after byte-identical | any output diff, any function change |

## Stages and gates

- **W0 Scope.** Pre-register criteria before scoring. Gate: criteria file exists with weights.
- **W1 Independent ideation.** Gate: 12 ideas, private round, provenance, no leader preference.
- **W2 Evidence.** Three delegated agents. Gate: reports on disk, strongest near-clones named.
- **W3 Grill + decision.** Gate: frontier empty, vetoes logged, revisit triggers.
- **W4 Design + plan + formats.** Gate: spec files versioned; honesty labels in every command's help.
- **W5 Skills install.** Reproducible vendoring of 5 GitHub repos with pinned tarball hashes. Gate: lockfile + NOTICE + scan of installed skills with Cordon itself.
- **W6 Implementation (TDD).** Tests first for every module. Gate: suite green.
- **W7 Nine review rounds.** R1 correctness, R2 injection/evasion, R3 filesystem/TOCTOU, R4 crypto/ledger, R5 CLI/exit codes/determinism, R6 resource limits/DoS, R7 Unicode/encoding/cross-platform, R8 packaging/offline/dependencies, R9 docs honesty + architecture deepening. Each round runs a harness, logs output, files findings, fixes, adds regression tests, re-runs.
- **W8 Architecture deepening.** Apply `improve-codebase-architecture` vocabulary (module, interface, depth, seam, adapter, leverage, locality, deletion test), produce self-contained HTML report, refactor, prove byte-for-byte functional equivalence with golden snapshots.
- **W9 Release.** Zip, present files, state plainly what was not achieved.

## Boss rules

1. An agent's output is evidence only when a command ran and its output is stored.
2. A failed gate sends the specific part back to the same role. Rework is logged with a reason, not hidden.
3. No agent may widen scope, add a dependency, or change the program's function during architecture work.
4. Any claim about safety, stars, or novelty must cite an artefact in this repo.
5. Round 9 signs only if the equivalence proof is byte-identical and all earlier rounds are closed.
