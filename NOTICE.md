# Third-party notices

Cordon vendors curated agent skills from five GitHub repositories into
`.agents/skills/`. The five source codeload tarballs are also vendored in
`.vendor/github_skills/` so the archive can be checked and rebuilt without a
live GitHub connection. `scripts/install_skills.py` copies whole skill folders
from those pinned tarballs. `docs/skills-lock.json` records each source URL,
tarball SHA-256, and the SHA-256 of every installed `SKILL.md`. The installer
never executes skill content.

| Source | Licence | Use here |
|---|---|---|
| [anthropics/skills](https://github.com/anthropics/skills) | see upstream `THIRD_PARTY_NOTICES.md` and the repository licence | `skill-creator`, `webapp-testing`, `mcp-builder`, `frontend-design` |
| [mattpocock/skills](https://github.com/mattpocock/skills) | MIT, Copyright 2026 Matt Pocock | `improve-codebase-architecture`, `codebase-design`, `grilling`, `grill-me`, `tdd`, `diagnosing-bugs`, `code-review`, `prototype`, `domain-modeling`, `writing-for-agents` |
| [obra/superpowers](https://github.com/obra/superpowers) | MIT, Copyright 2025 Jesse Vincent | `brainstorming`, `writing-plans`, `executing-plans`, `test-driven-development`, `systematic-debugging`, `verification-before-completion`, `requesting-code-review`, `receiving-code-review`, `writing-skills`, `dispatching-parallel-agents`, `subagent-driven-development`, `using-superpowers` |
| [vercel-labs/skills](https://github.com/vercel-labs/skills) | MIT, Copyright 2026 Vercel, Inc. | `find-skills`, `pr-labeling`, `triage`; the repo also publishes the `npx skills` CLI |
| [hardikpandya/stop-slop](https://github.com/hardikpandya/stop-slop) | MIT, Copyright 2025 Hardik Pandya | `stop-slop` with its `references/` folder |

Licence texts and the Anthropic third-party notice sit in
`.agents/skills/_licenses/`. Upstream repositories keep their own copyright
notices. Verify the Anthropic licence at the upstream repository before
redistributing those four folders; this project treats them as reference
material and does not relicense them. To check the vendored corpus offline,
run `python3 scripts/install_skills.py --verify-only`.

Research in `docs/research/` cites primary sources with dated URLs. The
delegated reports keep their own reference lists and mark unverified numbers as
unverified.
