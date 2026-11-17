# No Maintained Mainstream Tool Was Found to Unify All Five AI Coding-Agent SKILL.md Governance Capabilities

## Verdict: **support-located** for the narrow novelty claim

As of **2026-11-11**, this bounded search found no single maintained mainstream tool that demonstrably performs all five required capabilities for AI coding-agent SKILL.md folders: a pre-install injection and destructive-command scan; an automatically generated, machine-readable least-privilege capability manifest; content-hash or signature pinning; runtime enforcement across Claude Code, Codex, Cursor, and Gemini CLI; and a portable, hash-chained, replayable audit ledger. The strongest near-clones are **skillshare/skills.sh** for supply-chain integrity and **NVIDIA SkillSpector** for scanning. Neither closes the full gap: the former has no demonstrated unified capability manifest and no hash-chained replay ledger; the latter is primarily detection and has no demonstrated cross-runtime enforcement or provenance ledger. This supports a novelty claim restricted to the exact conjunction of the five requirements, not a claim that no future tool, internal product, or unpublished research prototype could do so.

| Candidate | Pre-install scan | Auto-generated least-privilege manifest | Hash or signature pinning | Runtime enforcement across the four named CLIs | Portable hash-chained replay ledger | Assessment |
|---|---:|---:|---:|---:|---:|---|
| skillshare / skills.sh | Yes | No direct evidence | Yes | Partial: distributes into each CLI’s skill directory, but does not enforce a shared policy at runtime | No direct evidence | Strongest supply-chain near-clone |
| NVIDIA SkillSpector | Yes | No direct evidence | Partial: connected to a sign-after-scan pipeline, but no direct evidence of hash-chained replay | No direct evidence | No direct evidence | Strongest scanner near-clone |
| Vercel Labs `npx skills` | No direct evidence | No direct evidence | Yes | No direct evidence | No direct evidence | Strongest pinning and restore near-clone |
| Claude Code hooks and sandbox | No direct evidence | No direct evidence | No direct evidence | Partial: Claude Code only | No direct evidence | Strongest runtime-policy component |
| Codex CLI approvals and sandbox | No direct evidence | No direct evidence | No direct evidence | Partial: Codex only | Partial: OpenTelemetry events are documented, not a portable hash chain | Strongest Codex-native runtime component |
| Gemini CLI sandbox | No direct evidence | No direct evidence | No direct evidence | Partial: Gemini CLI only | No direct evidence | Sandbox only |
| Cisco AI Defense Skill Scanner | Yes | No direct evidence | No direct evidence | No direct evidence | No direct evidence | Scanning component |
| Sigstore and Rekor | No direct evidence | No direct evidence | Yes | No direct evidence | Partial: provides an append-only, tamper-evident transparency log, not a SKILL.md audit product | Closest ledger primitive |
| Langfuse | No direct evidence | No direct evidence | No direct evidence | No direct evidence | No direct evidence | Traceability component, not a SKILL.md supply-chain tool |

“Partial” means a source establishes a real but incomplete part of the requirement. “No direct evidence” means the required feature was not found in the sources retrieved for this bounded search; it does not prove that the feature is absent from an unindexed repository, release note, or configuration option.

## Skillshare covers installation and integrity, but stops short of a unified runtime and replay system

Skillshare is the strongest single-tool counterexample because it already combines several lifecycle controls. Its documentation states that `skillshare audit` scans skills for “prompt injection, data exfiltration, credential access, destructive commands, obfuscation, suspicious URLs, and broken local links,” supports install blocking, and emits JSON, SARIF, and Markdown outputs. The v0.15.4 release notes, dated **2026-02-23**, add content-hash pinning through SHA-256 integrity records in `.skillshare-meta.json`, tamper and unexpected-file detection, and post-install or post-update gates with rollback. It also detects the published source-URL mismatch, publisher mismatch, and unrecognized authority language.

The strongest remaining gap is therefore not a missing scanner or hash record. It is the absence of evidence that skillshare produces one **generated machine-readable least-privilege capability manifest** from a skill folder and then enforces that same manifest when Claude Code, Codex, Cursor, and Gemini CLI invoke tools. Skillshare documents support for more than 65 AI CLIs, including those four, and can write each CLI’s skill directory; that is multi-agent distribution, not cross-runtime policy enforcement. The documented security gate acts at installation and update, whereas the required runtime system must intercept shell commands, file operations, network egress, and tool calls according to a single, least-privilege contract.

The second gap is the absence of a **portable hash-chained replayable audit ledger**. Detecting a changed file against an installed hash baseline is an integrity control, not a tamper-evident event ledger. A hash chain requires each audited event to bind to its predecessor—for example through a sequential hash or Merkle-linked record—so an investigator can replay events and detect omission or retroactive modification. The retrieved skillshare documentation describes file hashes, audit findings, diffs, and rollback, but not a signed or hash-chained event sequence that can be exported across machines and independently verified. Skillshare is consequently a materially stronger near-clone than a pure scanner or pure sandbox, but it does not satisfy the full five-part claim.

## SkillSpector and the skills.sh scanners prove the market exists, while exposing the runtime and ledger gaps

SkillSpector’s documentation describes pre-install scanning of Git repositories, URLs, zip files, directories, and individual files for prompt injection, data exfiltration, privilege escalation, supply chain risk, excessive agency, and dangerous-code patterns. It also reports JSON, Markdown, and SARIF output and an exit-code contract for CI gates. Its documentation further states that it is “part of the NVIDIA Verified Skills pipeline, which scans, evaluates, and signs agent skills before publication,” which is the closest evidence found for a combined scanner-and-signing workflow.

That pipeline still does not establish all five capabilities in one tool. The retrieved SkillSpector material does not show it generating a capability manifest from a SKILL.md folder, intercepting runtime calls in Claude Code, Codex, Cursor, and Gemini CLI, or maintaining a portable hash-chained replay log. Signing establishes origin and integrity for a published artifact, but it is not identical to least-privilege enforcement or an append-only event ledger. SkillSpector therefore disproves only the weaker claim that no SKILL.md scanner can exist; it does not falsify the five-part novelty claim.

The skills.sh marketplace adds a second independent audit layer. It runs three external audits—Gen Agent Trust Hub, Socket, and Snyk—on published skills and exposes Pass, Warn, and Fail badges. The published categories include remote code execution, prompt injection, data exfiltration, credential handling, third-party content exposure, and unverified external dependencies. This again shows that static analysis and supply-chain review are commercially available. It does not show a unified, least-privilege runtime contract or hash-chained replay ledger. Multiple scanners can lower installation risk, but their aggregate coverage does not create the missing runtime control plane.

## Native CLIs provide the enforcement primitives, but each is a separate and incomplete policy island

Claude Code is the clearest example of a powerful but agent-specific enforcement layer. Its documentation describes `dontAsk` mode, protected paths, and PreToolUse hooks that can deny a call even when the user selects `bypassPermissions`. A hook cannot relax restrictions set by organization policy, but the same documentation gives no evidence of a SKILL.md-derived capability manifest, a content-hash gate, or a portable hash-chained ledger. It also specifies the Claude Code settings and hooks interface, not a common control plane for Codex, Cursor, and Gemini CLI.

Codex documents an orthogonal set of primitives: sandbox modes such as `read-only` and `workspace-write`, an approval policy, command rules, and OpenTelemetry event export. Its managed guidance also discusses filesystem writes, network domains, MCP credentials, and logs available through an enterprise compliance platform. This addresses authorization and runtime visibility, but the retrieved material does not demonstrate a least-privilege manifest generated from a SKILL.md, nor a portable hash chain. Gemini CLI adds Seatbelt, Docker, or Podman isolation with profiles that constrain writes and networking, but its documentation is about container or OS sandboxing rather than semantic skill governance.

Cursor’s public trust center emphasizes organizational security posture, SOC 2 Type 2, ISO 27001, ISO 42001, and an audit-logs resource, but it does not establish the exact capability set required here. The retrieved page therefore cannot support a claim that Cursor itself is the unified tool. The four CLIs each expose some building blocks—sandboxing, approval policy, hooks, telemetry, or audit infrastructure—but no retrieved source proves that they share one policy schema, one enforcement engine, and one replayable event format.

## Composability is high, but it does not erase the integration novelty

A plausible architecture could combine skillshare or SkillSpector for scanning, `npx skills` or a Git commit hash for pinning, Claude Code hooks plus Codex and Gemini CLI sandbox policies for runtime limits, and Sigstore Rekor or an in-house Merkle log for replay. Rekor’s design records an artifact hash, signature, signing certificate, and timestamp in a Merkle structure with inclusion proofs, making it the closest ledger primitive identified. Landlock, bubblewrap, and seccomp are relevant sandbox primitives; `rr`, auditd, and strace can record or replay execution traces but are not SKILL.md governance products. Langfuse, LangSmith, and Helicone provide agent tracing and observability rather than the exact five-part lifecycle controls.

The remaining novelty therefore lies in the integration boundary: automatically translating a skill’s text and scripts into a precise capability contract, distributing that contract to four independently designed CLIs, intercepting their actual tool calls, and binding every decision and action into a portable hash-chained log. The evidence does not show any one maintained tool owning that end-to-end chain.

## Unresolved uncertainties and caveats

This is a bounded web search, not a formal proof of non-existence. A corporate, closed-source, newly released, renamed, plugin-only, or self-hosted product could combine these features without appearing in the retrieved material. Several capabilities are also open to interpretation. A scanner’s SARIF or JSON report might be treated by some teams as a “machine-readable capability manifest,” while a stricter reading requires an actionable allowlist of files, commands, environment variables, and network destinations. Similarly, a signed provenance record is not necessarily a hash-chained audit ledger, and an agent’s OpenTelemetry events are not necessarily portable or tamper-evident.

No verified star counts, download figures, or independent benchmark results are used in this assessment; such numbers would require primary-source verification and are therefore omitted. The strongest disproof attempt remains **skillshare**, because it already owns the pre-install scan, install/update gate, content-hash pinning, integrity monitoring, and multi-agent distribution layers; it only lacks direct evidence for an automatically generated least-privilege manifest enforced across all four runtimes and a portable hash-chained replay ledger. That gap is substantial enough to support—rather than defeat—the claimed novelty.

## Cited sources

[1] https://github.com/skills-sh/skillshare/blob/main/docs/audit.md
> “Scan skills for prompt injection, data exfiltration, credential access, destructive commands, obfuscation, suspicious URLs, and broken local links.”

[2] https://github.com/skills-sh/skillshare/releases/tag/v0.15.4
> “Content hash pinning — SHA-256 integrity verification detects tampering between updates.”

[3] https://skillshare.runkids.work/docs/reference/targets/supported-targets
> “skillshare supports 65+ AI CLI tools. When you run skillshare init, it automatically detects and configures any installed tools.”

[4] https://github.com/NVIDIA/skillspector
> “SkillSpector is part of the NVIDIA Verified Skills pipeline, which scans, evaluates, and signs agent skills before publication.”

[5] https://skills.sh
> “skills.sh runs three independent security audits on every published skill: Gen Agent Trust Hub, Socket, [and] Snyk.”

[6] https://github.com/vercel-labs/skills
> “skills-lock.json (version 2) records a computedHash for each project skill.”

[7] https://code.claude.com/docs/en/hooks-guide
> “a hook returning permissionDecision: ‘deny’ blocks the tool even in bypassPermissions mode.”

[8] https://github.com/openai/codex
> “approval_policy determines when you should be prompted to approve whether Codex can execute a command.”

[9] https://gemini-cli-docs.pages.dev/zh/sandbox
> “沙盒将潜在危险的操作（如 shell 命令或文件修改）与您的主机系统隔离。”

[10] https://trust.cursor.com/
> “Audit Logs and Monitoring.”

[11] https://landlock.io/#archives
> “Landlock is a stackable LSM [that] enables restricting ambient rights (e.g. global filesystem access) for a set of processes.”

[12] https://rekor.sigstore.dev/
> “A transparency log for signed software supply chains.”

[13] https://www.langfuse.com/
> “Hierarchical traces capture every LLM call, tool invocation, and retrieval step.”

[14] https://modelcontextprotocol.io/
> “MCP is an open-source standard for connecting AI applications to external systems.”

[15] https://cisco-ai-defense.github.io/docs/skill-scanner
> “Skill Scanner is a detection tool. It identifies known and probable risk patterns, but it does not certify security.”

[16] https://skillshare.runkids.work/zh-Hans/docs/understand/audit-engine
> “通过 skillshare install 或 skillshare update 安装或更新的 skill，其文件哈希会记录在 .metadata.json 中。”
