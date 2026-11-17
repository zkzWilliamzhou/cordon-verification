# Review round 8: Packaging, offline, dogfooding

## Command

```
python3 scripts/review_harness.py --round 8
```

## Real output

```text
=== ROUND 8 ===
[PASS] R8 runtime modules make no network calls: network imports in runtime modules: []
[PASS] R8 pyproject.toml parses: tomllib unavailable; textual fields checked
[PASS] R8 import works without the dev launcher: 0.1.0
[PASS] R8 vendored skill lockfile is complete: sources=5 skills=30
[PASS] R8 vendored skills verify strictly offline: rc=0 OFFLINE_OK sources=5 tarballs=5 skills=30
[PASS] R8 vendored tarballs reproduce the corpus offline: install_rc=0 verify_rc=0 lockfile=byte-identical OFFLINE_OK
[PASS] R8 third-party NOTICE present: NOTICE.md present
round 8: 7/7 passed

TOTAL FAILURES: 0
```

Exit code: `0`

## Manager verdict

Runtime modules make no network call, packaging parses and third-party notices are present. The manager found a real packaging defect: `--verify-only` tried to fetch GitHub tarballs when the ZIP was extracted without the host cache, and `fetch` could fail writing into a missing directory. That part was sent back. Five pinned tarballs are now vendored in `.vendor/github_skills/`; the installer verifies their SHA-256 against the lockfile before extraction, rejects traversal/link/oversized tar members and symlinked skill sources, and exposes a strictly offline `--verify-only`. Nine regression tests cover the fixes. Round 8 blocks Python networking and spawned curl, then rebuilds all 30 skill folders from the vendored tarballs in a throwaway checkout and requires a byte-identical lockfile.
