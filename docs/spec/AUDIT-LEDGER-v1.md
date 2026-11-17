# Audit ledger, version 1

`cordon.ledger/v1` is newline-delimited canonical JSON. One file holds one
session. You can verify it offline, diff two sessions, and replay the events.

## Entry

```json
{
  "schema": "cordon.ledger/v1",
  "tool_version": "0.1.0",
  "index": 1,
  "prev_hash": "0000...0000",
  "ts": 1700000000,
  "kind": "hook",
  "decision": "deny",
  "actor": "cordon",
  "detail": {"reason": "executable 'curl' is not in the allowlist"},
  "entry_hash": "<sha256>"
}
```

`entry_hash` is the SHA-256 of the canonical entry with `entry_hash` removed.
`prev_hash` is the `entry_hash` of the previous entry, or 64 zeros for entry 1.
`index` starts at 1 and increases by 1. `detail` is a JSON object. Kinds in
v0.1: `scan`, `manifest`, `pin`, `hook`, `guard`, `shim`, `verify`. Decisions:
`allow`, `deny`, `info`, `error`.

## Verification

A verifier must reject:

- an unknown `schema`;
- an `index` that does not match the line number;
- a `prev_hash` that differs from the previous `entry_hash`;
- an `entry_hash` that differs from the recomputed hash;
- a line that is not strict JSON (duplicate keys, `NaN`, `Infinity`).

Verification returns the root hash, the entry count and the first and last
timestamps.

## Diff

Diff compares event identity: SHA-256 of canonical
`{kind, decision, detail}`. Timestamps, indexes and hashes are excluded, so a
rerun of the same decisions produces an identical event list. The result lists
identities present in only one file.

## What the chain cannot do

Deleting the whole file, truncating the tail, rolling back the clock, or
stealing the verification key leaves no evidence in the chain. `cordon ledger
verify` prints this disclaimer. For non-repudiation, send the root hash to
write-only storage and sign the pin with an Ed25519 key stored outside the
skill tree.

## Compatibility

Version 1 is frozen. A writer must append under an exclusive file lock where
the platform provides one. A reader must not reorder lines.
