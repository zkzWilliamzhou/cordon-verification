# Review round 1: Correctness and baseline

## Command

```
python3 scripts/review_harness.py --round 1
```

## Real output

```text
=== ROUND 1 ===
[PASS] R1 unittest suite: rc=0 tests=OK
[PASS] R1 compileall: rc=0 
[PASS] R1 every renderer carries advisory label: scan disclaimer present
round 1: 3/3 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

The full unittest suite and byte-compilation pass. Every renderer carries the advisory disclaimer.
