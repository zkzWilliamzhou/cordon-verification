# Review round 7: Unicode, encoding, cross-platform

## Command

```
python3 scripts/review_harness.py --round 7
```

## Real output

```text
=== ROUND 7 ===
[PASS] R7 evidence output escapes bidi controls: bidi control escaped in evidence
[PASS] R7 UTF-16 BOM is decoded and scanned: note=utf-16-le findings=2
[PASS] R7 CRLF line endings are handled: findings=1
round 7: 3/3 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

Bidi controls are escaped in evidence, UTF-16 BOM and CRLF inputs are decoded and scanned.
