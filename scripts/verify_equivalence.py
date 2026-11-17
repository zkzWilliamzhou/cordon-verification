#!/usr/bin/env python3
"""Prove the architecture refactor changed no function, without trusting a
stored before-snapshot.

It rebuilds the pre-refactor modules in a temporary checkout, runs the same
golden tool on both versions, and requires three byte-identical snapshots:
the recorded before, the freshly rebuilt legacy, and the current final code.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from legacy_reconstruction import build  # noqa: E402

ENV_BASE = {
    **os.environ,
    "CORDON_FIXED_TIME": "1700000000",
    "CORDON_KEY_PASSPHRASE": "golden-passphrase",
}


def run_golden(root: Path, out: Path) -> None:
    env = {**ENV_BASE, "PYTHONPATH": str(root / "src")}
    subprocess.run([sys.executable, str(root / "scripts" / "golden.py"),
                    "--out", str(out)], cwd=str(root), env=env,
                   check=True, capture_output=True, text=True, timeout=180)


def main() -> int:
    before_path = ROOT / "docs" / "review" / "golden_before.json"
    after_path = ROOT / "docs" / "review" / "golden_after.json"
    if not before_path.exists() or not after_path.exists():
        print("FAIL: golden_before.json and golden_after.json must exist")
        return 1
    recorded_before = before_path.read_bytes()
    recorded_after = after_path.read_bytes()

    with tempfile.TemporaryDirectory(prefix="cordon-equivalence-") as td:
        legacy_root = build(Path(td) / "cordon")
        legacy_out = legacy_root / "docs" / "review" / "golden_legacy.json"
        run_golden(legacy_root, legacy_out)
        legacy_bytes = legacy_out.read_bytes()

    final_out = ROOT / "docs" / "review" / "golden_verified.json"
    run_golden(ROOT, final_out)
    final_bytes = final_out.read_bytes()

    checks = {
        "recorded before == recorded after": recorded_before == recorded_after,
        "rebuilt legacy == recorded before": legacy_bytes == recorded_before,
        "final code == recorded before": final_bytes == recorded_before,
        "final code == rebuilt legacy": final_bytes == legacy_bytes,
    }
    for name, ok in checks.items():
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(checks.values())
    print("EQUIVALENCE_PROOF: " + ("BYTE_IDENTICAL" if ok else "BROKEN"))
    if ok:
        final_out.unlink(missing_ok=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
