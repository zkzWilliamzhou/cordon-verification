# Skills installed for this program

`scripts/install_skills.py` installed 30 skill folders from five pinned GitHub
tarballs into `.agents/skills/`. The same tarballs are vendored in
`.vendor/github_skills/`, so the archive reproduces and checks the corpus
offline. `docs/skills-lock.json` records source URLs, tarball SHA-256 hashes
and each installed `SKILL.md` hash. Run
`python3 scripts/install_skills.py --verify-only` to recheck the tarballs and
every installed skill, with no network call.

| Source | Installed skills | Why the program uses them |
|---|---|---|
| anthropics/skills | `skill-creator`, `webapp-testing`, `mcp-builder`, `frontend-design` | The SKILL.md format reference, browser-based conformance testing, MCP adapter design, README and HTML report layout |
| mattpocock/skills | `improve-codebase-architecture`, `codebase-design`, `grilling`, `grill-me`, `tdd`, `diagnosing-bugs`, `code-review`, `prototype`, `domain-modeling`, `writing-for-agents` | The architecture deepening pass, the design-tree grilling, red-green-refactor tests, root-cause debugging, review gates and agent-facing docs |
| obra/superpowers | `brainstorming`, `writing-plans`, `executing-plans`, `test-driven-development`, `systematic-debugging`, `verification-before-completion`, `requesting-code-review`, `receiving-code-review`, `writing-skills`, `dispatching-parallel-agents`, `subagent-driven-development`, `using-superpowers` | The design-first gate, the plan, TDD rounds, systematic bug hunting, the completion gate and the agent workflow |
| vercel-labs/skills | `find-skills`, `pr-labeling`, `triage` | The open skills CLI ecosystem, issue triage and CI labelling for the future repository |
| hardikpandya/stop-slop | `stop-slop` | The prose audit for README, design doc and review logs |

The manager applied `stop-slop` rules to the README: cut filler, use active
voice, name concrete things, mix sentence lengths, no em dashes, no dramatic
one-line paragraph endings. The research reports in `docs/research/` keep their
own style; they are evidence, not marketing.

Cordon scanned its own installed skills. See `docs/review/round08.md` for the
command and the result. This is a dogfooding check, not a security verdict on
the upstream repositories.
