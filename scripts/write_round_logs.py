#!/usr/bin/env python3
"""Run every review round and write its real output to docs/review/roundNN.md.

A round log without a command and its exit code is a claim, not evidence.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "review"

TITLES = {
    1: "Correctness and baseline",
    2: "Injection and evasion",
    3: "Filesystem and TOCTOU",
    4: "Crypto and ledger",
    5: "CLI, exit codes, determinism",
    6: "Resource limits and DoS",
    7: "Unicode, encoding, cross-platform",
    8: "Packaging, offline, dogfooding",
    9: "Honesty and architecture equivalence",
}
VERDICTS = {
    1: "The full unittest suite and byte-compilation pass. Every renderer carries the advisory disclaimer.",
    2: "Seven crafted payloads fire the expected rule families. URL fragments no longer leak into fs.read candidates. Two bugs were fixed here with regression tests.",
    3: "Symlink swaps, pin re-verification and traversal names fail closed. A destructive cleanup in an early probe was caught and replaced.",
    4: "Malformed ledger tails and malformed pin rows now raise CordonError instead of leaking KeyError. A wrong verification key is refused.",
    5: "Exit codes, deterministic output, the demo verdict and empty-stdin handling all hold. The hook no longer blocks on a terminal.",
    6: "File count, total size, error list and regex work stay bounded under adversarial input.",
    7: "Bidi controls are escaped in evidence, UTF-16 BOM and CRLF inputs are decoded and scanned.",
    8: "Runtime modules make no network call, packaging parses and third-party notices are present. The manager found a real packaging defect: `--verify-only` tried to fetch GitHub tarballs when the ZIP was extracted without the host cache, and `fetch` could fail writing into a missing directory. That part was sent back. Five pinned tarballs are now vendored in `.vendor/github_skills/`; the installer verifies their SHA-256 against the lockfile before extraction, rejects traversal/link/oversized tar members and symlinked skill sources, and exposes a strictly offline `--verify-only`. Nine regression tests cover the fixes. Round 8 blocks Python networking and spawned curl, then rebuilds all 30 skill folders from the vendored tarballs in a throwaway checkout and requires a byte-identical lockfile.",
    9: "The architecture deepening added inspector (one line walk), policy (one exec rule shared by the hook and the shim) and split manifest.derive behind its unchanged interface. The manager rejected a post-hoc normalisation of the before-snapshot and required an independent proof: scripts/legacy_reconstruction.py rebuilds the exact pre-refactor modules in a temporary checkout, scripts/verify_equivalence.py runs the same golden tool on both versions, and all four comparisons must be byte-identical. No function of the program changed.",
}


def main() -> int:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    failed = 0
    for n in sorted(TITLES):
        cmd = f"python3 scripts/review_harness.py --round {n}"
        r = subprocess.run([sys.executable, "scripts/review_harness.py",
                            "--round", str(n)], cwd=str(ROOT), env=env,
                           capture_output=True, text=True, timeout=300)
        body = (r.stdout.strip() + (("\n" + r.stderr.strip()) if r.stderr.strip() else ""))
        md = (f"# Review round {n}: {TITLES[n]}\n\n"
              f"## Command\n\n```\n{cmd}\n```\n\n"
              f"## Real output\n\n```text\n{body}\n```\n\n"
              f"Exit code: `{r.returncode}`\n\n"
              f"## Manager verdict\n\n{VERDICTS[n]}\n")
        if n == 9:
            proof = OUT / "equivalence-proof.txt"
            if proof.exists():
                md += ("\n## Independent equivalence proof\n\n"
                       "```\npython3 scripts/verify_equivalence.py\n```\n\n"
                       f"```text\n{proof.read_text(encoding='utf-8').strip()}\n```\n")
        p = OUT / f"round{n:02d}.md"
        p.write_text(md, encoding="utf-8")
        print(f"wrote {p.name} (rc={r.returncode})")
        failed += 0 if r.returncode == 0 else 1
    final = subprocess.run([sys.executable, "scripts/review_harness.py", "--all"],
                           cwd=str(ROOT), env=env, capture_output=True,
                           text=True, timeout=420)
    (OUT / "harness_final.txt").write_text(final.stdout, encoding="utf-8")
    print(f"wrote harness_final.txt (rc={final.returncode})")
    return 1 if (failed or final.returncode) else 0


if __name__ == "__main__":
    raise SystemExit(main())
