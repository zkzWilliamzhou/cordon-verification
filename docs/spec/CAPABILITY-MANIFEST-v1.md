# Capability manifest, version 1

`cordon.capability-manifest/v1` is a JSON contract. A harness reads it to
decide whether a tool call may proceed. You can implement this format without
using Cordon.

## Rules

1. Default deny. `defaults` must name `deny` for `fs`, `exec`, `net` and `env`.
2. Canonical JSON with sorted keys, no whitespace, ASCII escaping and no
   non-finite numbers. Duplicate keys are invalid.
3. `policy_hash` is the SHA-256 of the canonical `capabilities` object. A
   reader must recompute it and reject a mismatch.
4. Paths in `fs.read` and `fs.write` are relative to `skill_root`. Absolute
   paths, `..`, `~` and backslashes are invalid.
5. `exec.allow` holds executable basenames. `exec.deny` is informational; the
   decision engine denies anything absent from `allow`.
6. `net.allow_hosts` holds hostnames. Ports and schemes are out of scope for
   v1. An empty list denies all network access.
7. `env.allow` holds variable names. Secret-like names (`TOKEN`, `KEY`,
   `SECRET`, `PASSWORD`, `AUTH`, `API`, `CREDENTIAL`, `PRIVATE`) must not
   appear in `allow` without a recorded operator grant.
8. Every `derived` item records `capability`, `value`, `origin`, `decision` and
   `reason`. `origin` is either `file:line` or `operator`.
9. `policy.mode` is `advisory` in v0.1. A future OS-backed implementation may
   set `enforced` only when a kernel boundary is present and fails closed.

## Shape

```json
{
  "schema": "cordon.capability-manifest/v1",
  "tool_version": "0.1.0",
  "skill_root": "./my-skill",
  "scan_digest": "<sha256>",
  "defaults": {"fs": "deny", "exec": "deny", "net": "deny", "env": "deny"},
  "capabilities": {
    "fs": {"read": ["references/style.md"], "write": []},
    "exec": {"allow": ["python3"], "deny": ["curl"]},
    "net": {"allow_hosts": [], "deny_hosts": ["evil.example"]},
    "env": {"allow": ["HOME", "PATH"], "deny": ["AWS_SECRET_ACCESS_KEY"]}
  },
  "derived": [
    {"capability": "net.host", "value": "evil.example",
     "origin": "SKILL.md:17", "decision": "denied",
     "reason": "network is default deny; add --allow-host to grant"}
  ],
  "finding_ids": ["<id>"],
  "policy": {"block_on": ["critical", "high"], "confidence": "high",
             "mode": "advisory", "label": "<human text>"},
  "policy_hash": "<sha256 of canonical capabilities>"
}
```

## Derivation algorithm (informative)

Cordon extracts host, executable, environment and relative-path candidates from
code regions. It excludes a candidate when its origin line carries a high or
critical finding with high confidence. Network hosts stay denied unless an
operator grants them with `--allow-host`. A candidate absent from the v0.1 safe
list gets `review`, not `allowed`.

## Detection rules that feed derivation

`CORDON-UNI-001/002`, `CORDON-ENC-001/002`, `CORDON-INJ-001/002`,
`CORDON-META-001`, `CORDON-SEC-001`, `CORDON-NET-001`, `CORDON-EXE-001/002`,
`CORDON-FS-001`, `CORDON-IO-001`. See `src/cordon/scan.py`.

## Compatibility

Version 1 is frozen. Additive fields need a new schema string. Removing a
field, changing the hash input or reinterpreting `mode` breaks compatibility.
