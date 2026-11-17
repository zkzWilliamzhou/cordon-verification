# ADR-0001: v0.1 enforcement is advisory

Date: 2026-11-11. Status: accepted.

## Decision

Cordon v0.1 labels the pure-Python PATH shim `advisory`. The Claude Code
`PreToolUse` hook is described as a deny path inside that harness, not as OS
enforcement. No renderer prints "safe".

## Reason

A PATH shim cannot stop a child that calls an absolute interpreter, sets
`LD_PRELOAD`, uses `ctypes` or issues a direct syscall. Agent B's report calls
an unqualified shim security theatre. Landlock, bubblewrap and AppContainer
provide real boundaries but need platform work or privileges this sandbox does
not have.

## Consequences

`SECURITY.md` lists bypasses. `docs/adapters.md` describes backend upgrades.
`policy.mode` in the manifest stays `advisory` until a kernel boundary is
present and fails closed. Any future change to `enforced` needs a new ADR and
conformance tests on each platform.
