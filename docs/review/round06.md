# Review round 6: Resource limits and DoS

## Command

```
python3 scripts/review_harness.py --round 6
```

## Real output

```text
=== ROUND 6 ===
[PASS] R6 file count and error list are bounded: files=500 errors=121 duration=0.07s
[PASS] R6 total size cap applies across directories: total_bytes=9800016 duration=0.20s
[PASS] R6 long adversarial line completes quickly: duration=0.00s findings=0
round 6: 3/3 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

File count, total size, error list and regex work stay bounded under adversarial input.
