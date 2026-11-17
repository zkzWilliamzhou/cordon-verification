# Final manager report

Date: 2026-11-12. Program: Cordon v0.1.

## What was built

Cordon scans an untrusted AI-agent skill folder, derives a default-deny
capability manifest, pins its bytes with an optional Ed25519 signature, returns
policy decisions through a Claude Code PreToolUse hook or a generic JSON hook,
runs a command behind an advisory PATH shim, and records every decision in a
portable hash-chained ledger. The chain runs offline on Python 3.10 with the
standard library. `cryptography` is imported only for signing.

Two frozen formats are published in `docs/spec/`: the capability manifest and
the audit ledger. Adapters, ADRs, a glossary, a 30-second demo, CI, SARIF
output, a security policy and third-party notices ship with the code.

## Skills installed

`scripts/install_skills.py` vendored 30 skill folders and the five pinned
GitHub tarballs themselves: `anthropics/skills`, `mattpocock/skills`
(including `improve-codebase-architecture` and `grilling`), `obra/superpowers`
(including `brainstorming`), `vercel-labs/skills` (the `npx skills` CLI repo)
and `hardikpandya/stop-slop`. `docs/skills-lock.json` records source URLs,
tarball SHA-256 hashes and each installed `SKILL.md` hash. `NOTICE.md` records
upstream licences. The installer never executes skill content.

A late packaging review found a real defect: extracting the ZIP without the
host cache made `--verify-only` attempt a network fetch, and `fetch` could fail
writing to a missing directory. The manager sent that part back. The archive
now carries the tarballs in `.vendor/github_skills/`; the installer checks
their hashes against the lockfile before extraction, rejects tar traversal,
links, devices, oversized members and symlinked skill sources, and provides a
strictly offline `--verify-only`. Nine new regression tests plus two round-8
probes cover it. The second probe rebuilds all 30 skill folders from the
vendored tarballs with Python networking and spawned `curl` blocked, then
requires a byte-identical lockfile.

## Workflow and gates

`docs/research/` holds the pre-registered scope, the independent ideation
register, the self-grilling design tree, the decision log with dissent, the
agent roster, the plan, and three delegated research reports (novelty,
security, adoption). The manager rejected a first pass of the review harness
that had 16 failures, sent each part back, and required a regression test for
every fix.

Nine adversarial review rounds ran real commands. All 55 unit tests and all 42
harness probes pass. Logs with commands, real output and exit codes sit in
`docs/review/round01.md` through `round09.md`; `harness_final.txt` holds the
combined run.

## Architecture deepening, with no function changed

`docs/architecture-review.html` presents three deepening opportunities using
the vocabulary module, interface, depth, seam, adapter, leverage, locality and
the deletion test. The refactor added `inspector` (one line walk produces
findings and capabilities), `policy` (one exec rule shared by the hook and the
shim) and split `manifest.derive` behind its unchanged interface.

The manager rejected a post-hoc normalisation of the before-snapshot as weak
evidence. `scripts/legacy_reconstruction.py` now rebuilds the exact pre-refactor
modules in a temporary checkout. `scripts/verify_equivalence.py` runs the same
golden tool on both versions and requires four byte-identical comparisons. The
real output is in `docs/review/equivalence-proof.txt`. Golden snapshots cover
14 CLI commands (stdout, stderr, exit codes), four scan digests and report
hashes, four derived manifests, five hook decisions, ledger verify/replay/diff,
a signed pin digest and the guard dry run. No function changed.

## What was not achieved

- The program was not published to GitHub and has not received 105,000 stars.
  Stars come from other people. No release note promises them.
- Novelty is `support-located` for the narrow claim that no single maintained
  mainstream tool binds all five capabilities at one seam. A bounded search
  cannot prove that no similar tool exists anywhere. `agentA_novelty.md` names
  skillshare, NVIDIA SkillSpector, Cisco Skill Scanner, skills.sh audits and
  `npx skills` as strong near-clones.
- v0.1 does not ship a kernel sandbox. Landlock, bubblewrap and AppContainer
  are documented backend upgrades. The PATH shim is advisory and the bypasses
  are listed in `SECURITY.md`.
- No human approved the design interactively. The user opted out of the
  question gate by instructing autonomous completion. Defaults are recorded as
  the manager's calls, not user decisions.

## Honest limits

A clean scan is not a safety verdict. A hash chain is tamper evident under
control of the local writer; deletion, truncation, clock rollback and a stolen
key stay outside its reach. Semantic prompt injection, unknown encodings and
runtime behaviour remain out of scope. `docs/ADOPTION.md` lists the eight ways
this project fails to gain traction.

## Verify it yourself

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m cordon demo
PYTHONPATH=src python3 scripts/install_skills.py --verify-only
PYTHONPATH=src python3 scripts/review_harness.py --all
PYTHONPATH=src python3 scripts/verify_equivalence.py
```
