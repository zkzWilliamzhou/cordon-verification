# Review round 9: Honesty and architecture equivalence

## Command

```
python3 scripts/review_harness.py --round 9
```

## Real output

```text
=== ROUND 9 ===
[PASS] R9 README has no safety or star overclaim: overclaims=[] advisory_present=True
[PASS] R9 versioned formats published: specs=['AUDIT-LEDGER-v1.md', 'CAPABILITY-MANIFEST-v1.md']
[PASS] R9 architecture refactor preserved all functions: before/after byte-identical
[PASS] R9 independent legacy reconstruction proves equivalence: rc=0 checks=4 BYTE_IDENTICAL
[PASS] R9 nine review rounds logged: round logs=9
round 9: 5/5 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

The architecture deepening added inspector (one line walk), policy (one exec rule shared by the hook and the shim) and split manifest.derive behind its unchanged interface. The manager rejected a post-hoc normalisation of the before-snapshot and required an independent proof: scripts/legacy_reconstruction.py rebuilds the exact pre-refactor modules in a temporary checkout, scripts/verify_equivalence.py runs the same golden tool on both versions, and all four comparisons must be byte-identical. No function of the program changed.

## Independent equivalence proof

```
python3 scripts/verify_equivalence.py
```

```text
legacy reconstruction written to /tmp/cordon-equivalence-wmz4_8dn/cordon
[PASS] recorded before == recorded after
[PASS] rebuilt legacy == recorded before
[PASS] final code == recorded before
[PASS] final code == rebuilt legacy
EQUIVALENCE_PROOF: BYTE_IDENTICAL
```
