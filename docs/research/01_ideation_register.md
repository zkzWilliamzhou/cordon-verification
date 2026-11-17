# Independent ideation register (written BEFORE any evidence search)

Stage: `independent`. No literature, no search results, no leader preference shown to contributors.
Contributors are pseudonymous perspectives used to force divergence: P01 systems/security, P02 dev-productivity, P03 OSS maintainer, P04 agent researcher, P05 non-expert end user, P06 contrarian/economics, P07 privacy/data, P08 education/accessibility. Origin of all ideas: `AI-assisted` (disclosed), generated in one private parallel round.

For each idea: statement, core assumption, predicted observation if true, possible disconfirming evidence, and the biggest risk. Evidence status: `not-checked`.

---

**I01 — Cordon: a verified, capability-scoped skill installer + runtime trust boundary** (P01, P03)
One local CLI that (1) statically analyses an untrusted SKILL.md + its scripts for prompt injection, exfiltration and destructive commands, (2) derives a least-privilege capability manifest, (3) pins the content hash and optional author signature, (4) enforces that manifest when an agent runs, and (5) writes a hash-chained, replayable action ledger.
- Assumption: installing a skill today means handing an agent full permissions with no review surface.
- Prediction: a scan of popular skill repos produces non-trivial findings; users cannot currently answer "what is this skill allowed to do?"
- Disconfirming: a maintained mainstream tool already does provenance + manifest + enforcement + audit together.
- Risk: runtime enforcement needs OS-level primitives; a pure-Python shim can be bypassed. Must be labelled honestly.

**I02 — Agent flight recorder** (P02, P04)
A portable, deterministic record/replay of any coding-agent session (prompts, tool calls, file diffs, commands, exit codes) into one signed file a teammate can replay, diff and audit locally.
- Assumption: existing observability traces LLM calls, not OS-level actions, and is SaaS-bound.
- Prediction: teams cannot reconstruct "which agent changed this file and why" after the fact.
- Disconfirming: Langfuse/rr/auditd/asciinema composition already covers this with a portable open format.
- Risk: overlap with I01's ledger; likely a component rather than a standalone.

**I03 — Context meter & redaction proxy** (P07, P05)
Local proxy that shows and controls exactly which files, secrets and snippets leave the machine for a model, with deterministic redaction rules.
- Assumption: users do not know what their agent uploads.
- Prediction: naive repos contain secrets in context.
- Disconfirming: several commercial/local tools already do this.
- Risk: crowded category; hard to differentiate.

**I04 — Semantic merge driver** (P03)
AST-aware git merge that resolves conflicts by symbol identity instead of line ranges.
- Assumption: line-based merges break refactors and agent-generated parallel edits.
- Prediction: measurable conflict-rate reduction on real repos.
- Disconfirming: mature implementations exist (e.g. research tooling, IDE merge engines).
- Risk: very hard to build correctly; wrong merges are worse than conflicts. Veto risk C3.

**I05 — Transactional shell / universal undo** (P01, P06)
Every command runs in a snapshot; one `undo` reverts fs, env and side effects.
- Assumption: cheap snapshotting is universally available.
- Prediction: users would use it constantly.
- Disconfirming: btrfs/zfs/nix/Time Machine plus shell-specific undo tools already approximate it.
- Risk: portability is brutal; partial rollback can corrupt state.

**I06 — Executable documentation gate** (P03, P08)
CI check that runs every code block in every README and verifies every API claim against the built artefact.
- Assumption: docs rot is a top-3 repo complaint.
- Prediction: most repos fail on first run.
- Disconfirming: doctest / mdbook test / rustdoc / embedme / vale already cover most languages.
- Risk: incremental, not novel.

**I07 — Dependency behaviour diff** (P01, P07)
Before upgrading a package, show the delta in filesystem, network and exec behaviour between two versions, not just the textual changelog.
- Assumption: supply-chain attacks hide in behaviour, not in changelogs.
- Prediction: install-script diffs reveal undeclared side effects.
- Disconfirming: Socket.dev / Diffend / OpenSSF tooling already covers this.
- Risk: crowded, well-funded category.

**I08 — Prompt-injection firewall for tool results** (P04)
Interpose on MCP/tool outputs and strip or quarantine embedded instructions before they reach the model.
- Assumption: tool output is the main injection vector.
- Prediction: crafted repo files can steer agents.
- Disconfirming: guardrail frameworks and agent harnesses already filter this.
- Risk: heuristic arms race; subset of I01.

**I09 — Causal "why did my agent do X" debugger** (P02)
Time-travel over a session with causal attribution from each edit back to the prompt/tool result that caused it.
- Assumption: attribution can be inferred from a transcript.
- Prediction: debugging time drops.
- Disconfirming: subset of I02; causal claims are hard to substantiate.
- Risk: over-claims causality; merges into I02.

**I10 — Skill SBOM + signature registry** (P01, P03)
A signed bill of materials and transparency log for agent skills, like Sigstore but for SKILL.md.
- Assumption: skills need the same provenance as packages.
- Prediction: no standard format exists.
- Disconfirming: skills-lock.json already records source + hash; a registry may exist.
- Risk: a registry is infrastructure, needs network and governance; weak standalone demo.

**I11 — Reverse-engineer-any-app-to-spec MCP** (P02)
Given a binary/site, produce an evidence-backed spec an agent can rebuild from.
- Assumption: legacy systems lack specs.
- Disconfirming: a 450k-star repo on the 2026 agent-skills topic list already does exactly this.
- Risk: direct collision. **Flag for veto at evidence check.**

**I12 — Slop ledger** (P06)
Git-native, deterministic scoring of structural overproduction introduced per agent session, with attribution.
- Assumption: teams want to measure agent-generated debt.
- Disconfirming: StopSlop (JS/TS analyser) and similar gates already exist.
- Risk: overlap with I01's scanning but different object (prose/code quality vs trust). Likely merge or reject.

---

**Clustering (structural, by mechanism, not by wording)**
- Cluster A — *trust boundary / provenance*: I01, I08, I10 (+ I02's ledger, I12's scanner as components).
- Cluster B — *observability / attribution*: I02, I09.
- Cluster C — *privacy*: I03.
- Cluster D — *codebase mechanics*: I04, I06, I07.
- Cluster E — *systems*: I05.
- Cluster F — *already contested*: I11.

**Preserved minority / dissent.** P06 argues that security tools rarely break 100k stars because adoption is a chore, and that a *format/spec* (like a tiny portable file everyone can implement) spreads faster than a tool. P05 argues the winning product must be understandable in one sentence by someone who has never heard of "capabilities". P08 warns that if enforcement requires root, most users are excluded. These objections are carried into the shortlist rather than averaged away.

**Leader's preference: withheld until after the independent round and the evidence check.**
