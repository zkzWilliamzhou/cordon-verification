# Self-grilling: the design tree, walked in rounds

The user said "brainstorming deep-thinking and grilling yourself" and "continue and keep working until finish and give me the zip". No human is available to answer, so the manager answers each question with a recommended answer, then attacks it. Facts were looked up, not asked for. This is an explicit opt-out of the interactive approval gate; the dissent is recorded instead of hidden.

## Round 1 (frontier: purpose, success, vetoes)

**Q1 — What is the object: a tool, a format, or a paper?** Recommended: a tool that publishes a format. Answer: yes. Reason: a pure scanner is a commodity, a pure spec has no 30-second demo. The format gives other harnesses something to implement.

**Q2 — Is ">105k stars" a requirement we can satisfy?** Recommended: no, treat it as a target that other people control. Answer: yes. Dissent from P06: optimising for stars distorts engineering. We record the pre-mortem from Agent C and refuse to buy or fake growth. We can only maximise the conditions.

**Q3 — Does "does not exist in the world already" mean literally nothing similar?** Recommended: interpret it as "no single maintained tool binds the five capabilities at one seam", and say so out loud. Answer: yes. A bounded search cannot prove non-existence. Agent A verdict: `support-located`, with skillshare and NVIDIA SkillSpector named as strong near-clones.

**Q4 — Which hard vetoes apply?** V1 exact clone, V2 needs to execute untrusted code, V3 spying/exfiltration, V4 not testable offline. Answer: all four retained.

## Round 2 (frontier unlocked by Q1–Q4: shape, trust, scope)

**Q5 — Can we claim runtime sandboxing?** Recommended: no. A pure-Python PATH shim is bypassable with an absolute path, `LD_PRELOAD`, `ctypes`, or a direct syscall. Answer: yes, reduce the claim. Agent B calls an unqualified shim "security theatre". v0.1 ships two honest enforcement seams: a **documented Claude Code PreToolUse hook** (a real deny path in that harness) and an **advisory PATH shim** for everything else, both driven by the same manifest, with a documented OS-backend upgrade path (Landlock/bubblewrap/AppContainer). Every output labels advisory vs enforced.

**Q6 — Should the scanner try to "understand" prompt injection semantically?** Recommended: no. Detect structural indicators with evidence (invisible Unicode, encoded blobs, override phrases, credential reads next to network sinks) and say the result is advisory. Answer: yes. "No findings" must never render as "safe".

**Q7 — What is the smallest unit that gives an aha moment in 30 seconds?** Recommended: `cordon scan examples/evil-skill` prints three findings with file/line evidence, then `cordon manifest` prints a default-deny capability contract, then `cordon hook` denies a destructive tool call. Answer: yes.

**Q8 — Which language and dependencies?** Recommended: Python 3.10 stdlib, with `cryptography` imported lazily only for Ed25519. Answer: yes. The sandbox cannot clone from github.com, so no build step, no network at runtime.

## Round 3 (frontier unlocked by Q5–Q8: data, crypto, integrity)

**Q9 — What pins the skill?** Recommended: a canonical tree hash over sorted relative paths, byte contents and mode bits, with `O_NOFOLLOW` reads and a re-verify immediately before any guarded run. Answer: yes. TOCTOU is reduced, not eliminated; documented.

**Q10 — Is a hash chain authentication?** Recommended: no. It is tamper-evident under control of the local writer. Ed25519 signs the pin and the manifest; the ledger root hash can be signed separately. Answer: yes. Deletion, truncation and clock rollback remain undetectable from the chain alone.

**Q11 — How do we stop the scanner becoming the attack?** Recommended: never execute, import or fetch skill content; cap file size, total size, file count, line length and regex work; reject symlinks, device files, absolute paths and `..`; normalise Unicode for display, hash raw bytes. Answer: yes.

**Q12 — What would make us kill the project?** Recommended: if a maintained tool is found that already does all five, or if the tests cannot distinguish a malicious skill from a clean one at a documented false-positive rate. Answer: yes, recorded as revisit triggers in the decision log.

## Adversarial review (reviewer did not originate the shortlisted idea)

- **"Scanners already exist, so this is a wrapper."** Response: true for capability 1. The product's unit of value is the *contract* that travels from scan to hook to ledger. If we cannot show one finding turning into one manifest rule turning into one denied tool call turning into one ledger entry, we kill the plan. This becomes acceptance test AT-07.
- **"A vendor ships this in six months."** Response: likely. Mitigation: publish the two formats (manifest v1, ledger v1) under a permissive licence and keep adapters thin; a vendor implementing the format is a win, not a loss. Residual risk unchanged.
- **"Security tools are a chore."** Response: the default must fail closed only on high-severity, high-confidence findings; everything else routes to triage with a stable ID. Agent C's finding #3.
- **"Fake rigour."** Response: every review round runs real commands and stores real output. No claim of a test that did not execute. If a round finds nothing, it says "no finding" and shows the command that passed.

## Shared understanding reached

Frontier empty. Decision owner signs: build **Cordon v0.1**, an offline evidence generator and policy gate, with honest labels, two published formats, a 30-second demo, and nine verification rounds. Unresolved: bounded novelty, no human approval, star count uncontrolled.
