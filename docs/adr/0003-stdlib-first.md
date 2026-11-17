# ADR-0003: stdlib first, cryptography lazy

Date: 2026-11-11. Status: accepted.

## Decision

Core commands run on Python 3.10 with the standard library. `cryptography` is
imported only inside `keygen`, `sign` and signature verification. The runtime
never opens a network connection.

## Reason

The sandbox cannot install packages reliably and cannot clone from github.com.
An offline tool also avoids turning the security check into a supply chain
dependency of its own.

## Consequences

`CORDON_KEY_PASSPHRASE` supplies the passphrase for an encrypted PEM key.
`SECURITY.md` tells users to keep keys outside the skill tree. The installer
for vendored skills is a separate script, not a runtime dependency.
