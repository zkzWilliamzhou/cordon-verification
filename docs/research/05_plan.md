# Implementation plan (executable, testable steps)

Derived from the approved design. Every step names files, the test that verifies it, and the expected diff size. Time is measured in this session; no external services are required.

| # | Step | Files | Verifying test | Size |
|---|---|---|---|---|
| 1 | Scaffold project, licence, packaging | `pyproject.toml`, `LICENSE`, `Makefile`, `src/cordon/__init__.py` | `python3 -m cordon --help` prints version | S |
| 2 | Shared model and canonical JSON | `src/cordon/model.py`, `util.py` | AT-01 canonical bytes stable, NaN/duplicate keys rejected | S |
| 3 | Safe enumeration + bounded reads | `src/cordon/fs.py` | AT-02 symlink escape, `..`, oversize, device file all refuse | M |
| 4 | Static scanner | `src/cordon/scan.py` | AT-03 injection corpus detected, benign corpus clean, IDs stable | L |
| 5 | Capability manifest derivation | `src/cordon/manifest.py` | AT-04 default deny, derived allowlist, policy filter | M |
| 6 | Pin + Ed25519 sign/verify | `src/cordon/pin.py` | AT-05 tamper rejected, wrong key rejected | M |
| 7 | Hash-chained ledger | `src/cordon/ledger.py` | AT-06 reorder/forge/truncate detected, diff works | M |
| 8 | Hook + advisory guard shim | `src/cordon/hook.py`, `guard.py` | AT-07 scan→manifest→deny→ledger chain end to end | L |
| 9 | CLI, JSON/SARIF/text reports, demo | `src/cordon/cli.py`, `report.py`, `examples/*` | AT-08 all exit codes, `cordon demo` under 10s | M |
| 10 | Specs, ADRs, glossary, adapters, README, CI | `docs/**`, `.github/**`, `README.md` | docs build offline, workflow YAML parses | M |
| 11 | Skill install with pinned hashes | `scripts/install_skills.py`, `docs/skills-lock.json`, `.agents/skills/**` | lockfile hashes match; Cordon scans its own installed skills | M |
| 12 | Nine review rounds + regression fixes | `scripts/review_harness.py`, `docs/review/**`, `tests/**` | harness green, each round has output | L |
| 13 | Architecture deepening + equivalence | `docs/architecture-review.html`, refactored modules, `scripts/golden.py` | before/after golden snapshots byte-identical | L |
| 14 | Zip and present | `/data/workspace/cordon.zip` | `unzip -t` passes | S |

**Exit codes (contract):** 0 success / no blocking finding, 1 findings or error, 2 usage error, 3 integrity failure, 126 denied by policy, 130 interrupted.

**Non-goals for v0.1:** kernel sandbox, macOS/Windows enforcement backends, network calls, a registry, telemetry, star acquisition.

**Definition of done:** all 14 steps have artefacts, `unittest discover` green, nine review rounds closed, architecture report written, golden equivalence byte-identical, zip opens.
