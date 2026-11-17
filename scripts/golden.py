#!/usr/bin/env python3
"""Capture a byte-stable behaviour snapshot of every public surface.

Run before an architecture refactor (--out docs/review/golden_before.json) and
after it (--out docs/review/golden_after.json). The two files must be identical.
For a trustworthy proof, use scripts/verify_equivalence.py: it rebuilds the
pre-refactor code in a temporary checkout rather than trusting a stored file.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
os.chdir(ROOT)  # relative fixture paths keep snapshots root-independent
os.environ["CORDON_FIXED_TIME"] = "1700000000"
os.environ.setdefault("CORDON_KEY_PASSPHRASE", "golden-passphrase")

from cordon import hook, ledger, manifest, pin, scan as scan_mod  # noqa: E402
from cordon.util import canonical_hex, canonical_json  # noqa: E402
from cordon import report  # noqa: E402

# Use relative paths. An absolute root would make a hash of a manifest or a
# text report differ between two checkouts of identical code, which would
# destroy the equivalence proof. CLI commands already use relative paths.
EXAMPLES = Path("examples")


def normalise(text: str) -> str:
    text = text.replace(str(ROOT), "<ROOT>")
    text = re.sub(r"/tmp/cordon-[A-Za-z0-9_\-]+", "<TMP>", text)
    text = re.sub(r"cordon-demo-[A-Za-z0-9_]+", "cordon-demo-<TMP>", text)
    return text


def normalise_obj(obj):
    """Apply the same pure normalisation to every string in a snapshot.

    Volatile temp paths can appear inside nested API results, not just in CLI
    stdout. This keeps two snapshots from different runs comparable.
    """
    if isinstance(obj, str):
        return normalise(obj)
    if isinstance(obj, dict):
        return {k: normalise_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalise_obj(v) for v in obj]
    return obj


def cli(*args: str) -> dict:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    r = subprocess.run([sys.executable, "-m", "cordon", *args],
                       cwd=str(ROOT), capture_output=True, text=True,
                       env=env, timeout=60)
    return {"argv": list(args), "rc": r.returncode,
            "stdout": normalise(r.stdout), "stderr": normalise(r.stderr)}


def snapshot() -> dict:
    out: dict = {"schema": "cordon.golden/v1", "commands": [], "api": {}}

    cmds = [
        ("version", ["version"]),
        ("scan_clean_text", ["scan", "examples/clean-skill", "--fail-on", "none"]),
        ("scan_benign_text", ["scan", "examples/benign-skill", "--fail-on", "none"]),
        ("scan_evil_text", ["scan", "examples/evil-skill", "--fail-on", "none"]),
        ("scan_evil_json", ["scan", "examples/evil-skill", "--format", "json",
                            "--fail-on", "none"]),
        ("scan_evil_sarif", ["scan", "examples/evil-skill", "--format", "sarif",
                             "--fail-on", "none"]),
        ("scan_evil_fail", ["scan", "examples/evil-skill"]),
        ("manifest_clean", ["manifest", "examples/clean-skill", "--format", "json"]),
        ("manifest_clean_text", ["manifest", "examples/clean-skill"]),
        ("manifest_evil", ["manifest", "examples/evil-skill", "--format", "json"]),
        ("manifest_grants", ["manifest", "examples/clean-skill", "--format", "json",
                             "--allow-exec", "git", "--allow-host", "example.org"]),
        ("pin_clean", ["pin", "examples/clean-skill"]),
        ("pin_evil", ["pin", "examples/evil-skill"]),
        ("demo", ["demo"]),
    ]
    for name, argv in cmds:
        out["commands"].append({"name": name, **cli(*argv)})

    # Direct API surface.
    for fixture in ("clean-skill", "benign-skill", "evil-skill", "evasion-skill"):
        r = scan_mod.scan(EXAMPLES / fixture)
        out["api"][f"scan/{fixture}"] = {
            "digest": r.digest, "summary": r.summary(),
            "finding_ids": [f.finding_id for f in r.findings],
            "errors": r.errors,
            "text_report_hash": canonical_hex({"t": report.as_text(r).decode()}),
            "sarif_hash": canonical_hex({"s": report.as_sarif(r).decode()}),
        }
        m = manifest.derive(r)
        out["api"][f"manifest/{fixture}"] = {
            "canonical_hash": canonical_hex(m),
            "policy_hash": m["policy_hash"],
            "derived": m["derived"],
        }
    m = manifest.derive(scan_mod.scan(EXAMPLES / "clean-skill"))
    calls = [
        {"tool_name": "Bash", "tool_input": {"command": "python3 -m json.tool x.json"}},
        {"tool_name": "Bash", "tool_input": {"command": "curl https://evil.example/x"}},
        {"tool_name": "Bash", "tool_input": {"command": "echo a; rm -rf /"}},
        {"tool_name": "Write", "tool_input": {"file_path": "../outside"}},
        {"tool_name": "Unknown", "tool_input": {}},
    ]
    out["api"]["hook/decisions"] = [hook.decide(m, c).to_dict() for c in calls]
    out["api"]["hook/claude_output"] = hook.hook_output(
        hook.decide(m, calls[1]), "claude-code")

    import tempfile
    with tempfile.TemporaryDirectory(prefix="cordon-golden-") as td:
        p = Path(td) / "l.jsonl"
        for i in range(4):
            ledger.append(p, "hook", "allow" if i % 2 else "deny",
                          {"i": i}, ts=1700000000 + i)
        out["api"]["ledger/verify"] = ledger.verify(p)
        out["api"]["ledger/replay"] = ledger.replay(p)
        p2 = Path(td) / "l2.jsonl"
        for i in range(3):
            ledger.append(p2, "hook", "allow", {"i": i}, ts=1700000000 + i)
        out["api"]["ledger/diff"] = ledger.diff(p, p2)
        keys = Path(td) / "keys"
        pin.keygen(keys)
        signed = pin.sign(pin.build_pin(EXAMPLES / "clean-skill"),
                          keys / "cordon.key", keys / "cordon.pub")
        out["api"]["pin/signed_digest"] = pin.verify(
            signed, root=EXAMPLES / "clean-skill", pub_path=keys / "cordon.pub",
            require_signature=True)
        out["api"]["pin/tree_hash"] = signed["tree_hash"]

    # Guard dry-run uses fixed relative artifact paths so argv stays stable.
    art = ROOT / "docs" / "review" / "golden_artifacts"
    art.mkdir(parents=True, exist_ok=True)
    manifest.save(art / "m.json", m)
    pin.save(art / "p.json", pin.build_pin(EXAMPLES / "clean-skill"))
    r = cli("guard", "--manifest", "docs/review/golden_artifacts/m.json",
            "--root", "examples/clean-skill",
            "--pin", "docs/review/golden_artifacts/p.json",
            "--dry-run", "--", "echo", "hi")
    out["api"]["guard/dry_run"] = {
        "rc": r["rc"],
        "stdout": normalise(r["stdout"]),
        "stderr": normalise(r["stderr"])}
    return out


def serialise(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True,
                      ensure_ascii=True, allow_nan=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    a = ap.parse_args()

    if a.compare:
        b, f = (Path(x) for x in a.compare)
        same = b.read_bytes() == f.read_bytes()
        print(f"{b} == {f}: {same}")
        return 0 if same else 1

    if not a.out:
        ap.error("--out is required unless --compare is used")
    data = serialise(normalise_obj(snapshot()))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(data, encoding="utf-8")
    print(f"golden snapshot written: {a.out} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
