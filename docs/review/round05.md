# Review round 5: CLI, exit codes, determinism

## Command

```
python3 scripts/review_harness.py --round 5
```

## Real output

```text
=== ROUND 5 ===
[PASS] R5 evil scan exits 1 by default: exit 1
[PASS] R5 clean scan exits 0: exit 0
[PASS] R5 hook deny exits 126 with --exit-on-deny: rc=126 stdout={"capability": "exec", "decision": "deny", "detail": {"exe": "sudo"}, "reason": "executable 'sudo' i
[PASS] R5 demo verdict cites the manifest: demo verdict cites the manifest allowlist
[PASS] R5 malformed hook input errors fast: cordon: invalid tool-call JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)
[PASS] R5 empty stdin does not hang: rc=1 stderr=cordon: invalid tool-call JSON: Expecting value: line 1 column 1 (char 0)
round 5: 6/6 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

Exit codes, deterministic output, the demo verdict and empty-stdin handling all hold. The hook no longer blocks on a terminal.
