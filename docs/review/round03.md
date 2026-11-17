# Review round 3: Filesystem and TOCTOU

## Command

```
python3 scripts/review_harness.py --round 3
```

## Real output

```text
=== ROUND 3 ===
[PASS] R3 symlink swap fails closed: enumerated 1 files, symlink refused
[PASS] R3 pin re-verify closes scan-to-run gap: refused: pin mismatch: skill content changed
[PASS] R3 traversal filenames never enter records: files=['SKILL.md', 'a..b.md'], is_safe_rel rejects ../
round 3: 3/3 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

Symlink swaps, pin re-verification and traversal names fail closed. A destructive cleanup in an early probe was caught and replaced.
