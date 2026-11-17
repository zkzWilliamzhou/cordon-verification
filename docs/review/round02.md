# Review round 2: Injection and evasion

## Command

```
python3 scripts/review_harness.py --round 2
```

## Real output

```text
=== ROUND 2 ===
[PASS] R2 html comment override: 2 findings: ['CORDON-INJ-001', 'CORDON-INJ-002']
[PASS] R2 frontmatter override: 2 findings: ['CORDON-INJ-001', 'CORDON-INJ-002']
[PASS] R2 base64 override: 1 findings: ['CORDON-ENC-001']
[PASS] R2 zero width: 2 findings: ['CORDON-INJ-001', 'CORDON-UNI-001']
[PASS] R2 rtl override: 2 findings: ['CORDON-INJ-001', 'CORDON-UNI-001']
[PASS] R2 homoglyph: 2 findings: ['CORDON-INJ-001', 'CORDON-UNI-002']
[PASS] R2 meta evasion: 1 findings: ['CORDON-META-001']
[PASS] R2 URL fragments are not path candidates: URL fragments mistaken for fs.read candidates: []
round 2: 8/8 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

Seven crafted payloads fire the expected rule families. URL fragments no longer leak into fs.read candidates. Two bugs were fixed here with regression tests.
