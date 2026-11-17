# Glossary

Domain terms come first. Architecture terms follow the `codebase-design`
vocabulary: module, interface, depth, seam, adapter, leverage, locality.

| Term | Meaning |
|---|---|
| Skill | A folder with a `SKILL.md` file that instructs a coding agent. |
| Finding | One structural indicator with a stable id, a location and redacted evidence. |
| Capability | A permitted action class: `fs.read`, `fs.write`, `exec`, `net`, `env`, `prompt`. |
| Manifest | A default-deny capability contract. See `docs/spec/CAPABILITY-MANIFEST-v1.md`. |
| Pin | A SHA-256 tree hash over sorted file paths, modes and bytes, optionally signed. |
| Ledger | A hash-chained, replayable event log. See `docs/spec/AUDIT-LEDGER-v1.md`. |
| Hook | A policy decision returned to an agent harness before a tool call runs. |
| Guard | An advisory PATH shim that intercepts executable basenames. |
| Verdict | `allow` or `deny` plus a reason and a capability. |
| Gate | A review round or acceptance test that must pass before the next stage. |
| Module | One Python file with a single responsibility and one tested interface. |
| Interface | The functions another module calls. The interface is the test surface. |
| Depth | The ratio of work hidden behind an interface to the size of that interface. |
| Seam | A place where two modules meet and where a different adapter can attach. |
| Adapter | A harness-specific reader of the shared formats. One adapter is a hypothetical seam; two make it real. |
| Leverage | How much behaviour one small change to a deep module controls. |
| Locality | Related behaviour sits close together; a reader does not jump between files to understand one concept. |
| Deletion test | Would deleting this module concentrate complexity or just move it? A yes means it is shallow. |
