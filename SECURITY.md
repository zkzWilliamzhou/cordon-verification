# Security policy and trust model

Report vulnerabilities through GitHub issues on the public repository. Do not
paste live credentials into an issue. This document explains what Cordon can
and cannot claim.

## What Cordon does

You get deterministic structural findings with file, line, column and redacted
evidence. You get a derived, default-deny capability manifest with a
`policy_hash`. You get a SHA-256 tree pin and an optional Ed25519 detached
signature. You get policy decisions from a hook or an advisory PATH shim. You
get a hash-chained ledger you can verify and diff offline.

## What Cordon does not do

The scanner never executes, imports, fetches or evaluates skill content. It
cannot prove that a skill is harmless. Semantic prompt injection, unknown
encodings, model behaviour and runtime side effects stay out of scope. A clean
scan is not a safety verdict and Cordon never prints one.

A pure-Python PATH shim is advisory. Known bypasses include absolute
interpreter paths, `LD_PRELOAD` and `DYLD_INSERT_LIBRARIES`, inherited
`PYTHONPATH` or `NODE_OPTIONS`, `ctypes`, direct syscalls, and children spawned
without PATH resolution. `guard` strips a fixed list of dangerous environment
variables and covers executable basenames on the original PATH, but a process
that already runs can still escape. Use an OS backend for enforcement:

| Backend | Unprivileged | Limit |
|---|---|---|
| Landlock (Linux) | Yes | Filesystem rules only; no network policy |
| seccomp with `no_new_privs` | Usually | Syscall filter, not a semantic policy |
| bubblewrap | Depends on user namespaces | External binary, not pure Python |
| macOS `sandbox-exec` | Deprecated upstream | Do not build a new default on it |
| Windows AppContainer | Requires process setup | Not a stdlib primitive |

A Claude Code `PreToolUse` hook that returns `permissionDecision: "deny"` blocks
a tool call inside that harness. It does not stop a process the harness has
already launched.

## Crypto limits

Canonical JSON uses sorted keys, ASCII escaping, no whitespace and no
non-finite numbers. Duplicate keys and `NaN` are rejected on load. A SHA-256
chain is tamper evident, not authentication. Ed25519 signs the canonical pin
without its signature field. The private key is an encrypted PEM file with
mode 0600; you supply the passphrase in `CORDON_KEY_PASSPHRASE`. Never store a
signing key inside a skill tree. A compromised local user who controls the
trusted public key, the ledger writer or the verification process defeats the
design. Ledger deletion, tail truncation and clock rollback remain undetectable
from the chain alone. For non-repudiation, ship the root hash to write-only
storage.

## Detection gaps

Publishing detection rules tells attackers what Cordon looks for. Accepted and
documented. Structural rules miss payloads built from encoders outside the
enabled set, split across files, or delivered after install. TOCTOU between
scan and run is reduced by `O_NOFOLLOW`, inode checks and a pin re-verify
immediately before launch. It is not eliminated.

A baseline is a human review decision recorded as a list of stable finding
ids. It suppresses those ids from the exit-code gate only. It does not remove
them from reports, does not make the skill safe, and does not survive a change
to a rule that produces different ids. If a publisher edits an accepted file,
its content hash changes and the finding id changes with it, so the gate sees a
new finding. Review baselines like you review code; never auto-accept an
untrusted corpus.

## Vendored skill supply chain

The runtime makes no network call. `scripts/install_skills.py` is a development
tool: the archive carries five SHA-256-pinned GitHub tarballs so installation
and `--verify-only` work offline. It checks every tarball hash against
`docs/skills-lock.json` before extraction, rejects tar traversal, absolute or
backslash paths, links, devices, FIFOs, oversized members and symlinked skill
sources, and checks every installed `SKILL.md` hash during verification.
`--download` still refuses a tarball whose hash differs from the lockfile.
These are byte-provenance checks, not a judgement about upstream skill safety.

## Sensitive data

Cordon reads local files. It makes no network call at runtime. Evidence output
redacts long tokens and escapes invisible Unicode controls so a crafted skill
cannot spoof a terminal.

## Supported versions

v0.1 receives fixes on the main branch. File an issue with the Cordon version,
Python version, operating system and a minimal skill folder that reproduces
the problem.
