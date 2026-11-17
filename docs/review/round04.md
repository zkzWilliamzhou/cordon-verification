# Review round 4: Crypto and ledger

## Command

```
python3 scripts/review_harness.py --round 4
```

## Real output

```text
=== ROUND 4 ===
[PASS] R4 malformed ledger tail fails closed: refused: ledger tail is missing index or entry_hash
[PASS] R4 malformed pin rows fail closed: refused: pin has a malformed file row
[PASS] R4 wrong verification key refused: refused: signature key is not the trusted key
[PASS] R4 canonical JSON rejects duplicate keys: duplicate key rejected
round 4: 4/4 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

Malformed ledger tails and malformed pin rows now raise CordonError instead of leaking KeyError. A wrong verification key is refused.
