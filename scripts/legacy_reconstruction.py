#!/usr/bin/env python3
"""Rebuild the exact pre-refactor modules in an isolated copy of the repo.

Manager's independent equivalence check. It does not trust a stored
before-snapshot. It reconstructs the code that existed before the architecture
refactor so the same golden tool can be run against both versions.
"""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT
DST: Path | None = None  # bound by build()

LEGACY_MANIFEST = '''"""Derive a least-privilege capability contract from a scan.

Default deny. A candidate becomes allowed only when it is on the safe list,
came from code rather than prose, and no blocking finding touches its origin.
Operator grants are recorded with origin "operator" so every decision is
attributable.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .model import ScanResult
from .scan import extract_entities
from .util import VERSION, canonical_hex, is_safe_rel, read_json_file, write_json_file

SCHEMA = "cordon.capability-manifest/v1"

SAFE_EXEC = {"ls", "cat", "grep", "rg", "sed", "head", "tail", "wc", "jq",
             "git", "echo", "printf", "pytest", "make", "cargo", "go",
             "rustc", "node", "npm", "npx", "python3", "python",
             "find", "awk", "sort", "uniq", "diff", "tar", "unzip"}
DANGEROUS_EXEC = {"sh", "bash", "zsh", "curl", "wget", "nc", "ncat", "sudo",
                  "rm", "chmod", "chown", "mv", "cp", "tee", "eval", "xargs"}
SAFE_ENV = {"HOME", "PATH", "LANG", "LC_ALL", "TERM", "USER", "SHELL", "PWD", "TMPDIR"}
SECRET_ENV = re.compile(r"(?i)(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|API|PRIVATE|AUTH)")


def _blocking_origins(scan: ScanResult) -> set[str]:
    out: set[str] = set()
    for f in scan.findings:
        if f.severity in ("critical", "high") and f.confidence == "high":
            out.add(f"{f.file}:{f.line}")
    return out


def derive(scan: ScanResult, grants: dict[str, list[str]] | None = None) -> dict[str, Any]:
    grants = grants or {}
    entities = extract_entities(scan.files)
    blocked = _blocking_origins(scan)
    derived: list[dict[str, str]] = []

    def note(cap: str, value: str, origin: str, decision: str, reason: str) -> None:
        derived.append({"capability": cap, "value": value, "origin": origin,
                        "decision": decision, "reason": reason})

    fs_read: list[str] = []
    for item in entities["paths"]:
        p = item["value"]
        if not is_safe_rel(p) or item["origin"] in blocked:
            note("fs.read", p, item["origin"], "denied", "unsafe path or blocking finding")
            continue
        fs_read.append(p)
        note("fs.read", p, item["origin"], "allowed", "relative path inside skill root")

    exec_allow: list[str] = []
    exec_deny: list[str] = []
    for item in entities["execs"]:
        name = item["value"]
        if name in DANGEROUS_EXEC or item["origin"] in blocked:
            exec_deny.append(name)
            note("exec", name, item["origin"], "denied", "dangerous executable or blocking finding")
        elif name in SAFE_EXEC:
            exec_allow.append(name)
            note("exec", name, item["origin"], "allowed", "safe executable in code context")
        else:
            note("exec", name, item["origin"], "review", "not on the v0.1 safe list")

    net_allow: list[str] = []
    net_deny: list[str] = []
    for item in entities["hosts"]:
        host = item["value"]
        net_deny.append(host)
        note("net.host", host, item["origin"], "denied",
             "network is default deny; add --allow-host to grant")

    env_allow: list[str] = []
    env_deny: list[str] = []
    for item in entities["envs"]:
        name = item["value"]
        if SECRET_ENV.search(name) or item["origin"] in blocked:
            env_deny.append(name)
            note("env", name, item["origin"], "denied", "secret-like or blocked")
        elif name in SAFE_ENV:
            env_allow.append(name)
            note("env", name, item["origin"], "allowed", "safe environment variable")
        else:
            note("env", name, item["origin"], "review", "unknown variable")

    for cap, key, target in (
        ("exec", "exec", exec_allow), ("net.host", "host", net_allow),
        ("env", "env", env_allow), ("fs.write", "write", []),
    ):
        granted = grants.get(key, [])
        for value in granted:
            if value not in target:
                target.append(value)
            if cap == "fs.write":
                note(cap, value, "operator", "allowed", "explicit operator grant")
            else:
                note(cap, value, "operator", "allowed", "explicit operator grant")
            if cap == "net.host" and value in net_deny:
                net_deny.remove(value)
            if cap == "exec" and value in exec_deny:
                exec_deny.remove(value)

    fs_write = [v for v in grants.get("write", []) if is_safe_rel(v)]
    capabilities = {
        "fs": {"read": sorted(set(fs_read)), "write": sorted(set(fs_write))},
        "exec": {"allow": sorted(set(exec_allow)), "deny": sorted(set(exec_deny))},
        "net": {"allow_hosts": sorted(set(net_allow)), "deny_hosts": sorted(set(net_deny))},
        "env": {"allow": sorted(set(env_allow)), "deny": sorted(set(env_deny))},
    }
    m: dict[str, Any] = {
        "schema": SCHEMA,
        "tool_version": VERSION,
        "skill_root": scan.root,
        "scan_digest": scan.digest,
        "defaults": {"fs": "deny", "exec": "deny", "net": "deny", "env": "deny"},
        "capabilities": capabilities,
        "derived": sorted(derived, key=lambda d: (d["capability"], d["value"], d["origin"])),
        "finding_ids": [f.finding_id for f in scan.findings],
        "policy": {"block_on": ["critical", "high"], "confidence": "high",
                   "mode": "advisory",
                   "label": "Advisory. A pure-Python hook or PATH shim is bypassable. "
                            "Use an OS backend (Landlock/bubblewrap/AppContainer) for enforcement."},
        "policy_hash": canonical_hex(capabilities),
    }
    return m


def load(path: Path) -> dict[str, Any]:
    m = read_json_file(path)
    if not isinstance(m, dict) or m.get("schema") != SCHEMA:
        raise ValueError(f"{path}: not a {SCHEMA} manifest")
    caps = m.get("capabilities")
    if not isinstance(caps, dict) or "policy_hash" not in m:
        raise ValueError(f"{path}: manifest missing capabilities or policy_hash")
    if canonical_hex(caps) != m["policy_hash"]:
        raise ValueError(f"{path}: manifest policy_hash mismatch (tampered?)")
    return m


def save(path: Path, manifest: dict[str, Any]) -> None:
    write_json_file(path, manifest)
'''

HEADER = '''"""Pre-refactor scan.py, reconstructed for the equivalence proof."""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from .fs import enumerate_skill
from .model import Finding, ScanResult, SkillFile, findings_key
from .util import (CONFUSABLES, INVISIBLE, MAX_FINDINGS, MAX_LINE_CHARS,
                   clamp, fold, redact, stable_id)

'''

TAIL = '''

def scan(root: Path) -> ScanResult:
    errors: list[str] = []
    files = enumerate_skill(root, errors)
    lines: list[Line] = []
    for f in files:
        if f.lang == "binary":
            continue
        if f.encoding_note == "invalid-utf8":
            errors.append(f"{f.rel}: invalid UTF-8, decoded with replacement for detection only")
        lines.extend(_lines(f))
    findings = scan_lines(lines)
    if len(findings) >= MAX_FINDINGS:
        errors.append(f"finding cap {MAX_FINDINGS} reached; output truncated")
    return ScanResult(str(root), files, findings, errors)


def extract_entities(files: Iterable[SkillFile]) -> dict[str, list[dict[str, str]]]:
    """Deterministic candidate capabilities used by manifest derivation."""
    hosts: dict[str, dict[str, str]] = {}
    execs: dict[str, dict[str, str]] = {}
    envs: dict[str, dict[str, str]] = {}
    paths: dict[str, dict[str, str]] = {}
    for f in files:
        if f.lang == "binary":
            continue
        for line in _lines(f):
            t = line.folded
            without_urls = URL.sub(" ", t)
            for m in URL.finditer(t):
                try:
                    host = urllib.parse.urlsplit(m.group(0)).hostname or ""
                except ValueError:
                    host = ""
                if host:
                    hosts.setdefault(host, {"value": host, "origin": f"{f.rel}:{line.no}"})
            if line.is_code or f.lang in ("shell", "python", "javascript"):
                for m in EXEC_TOKEN.finditer(t):
                    execs.setdefault(m.group(1).lower(),
                                     {"value": m.group(1).lower(),
                                      "origin": f"{f.rel}:{line.no}"})
            if ("$" in without_urls or "environ" in without_urls
                    or "getenv" in without_urls or "process.env" in without_urls
                    or "printenv" in without_urls):
                for m in ENV_TOKEN.finditer(without_urls):
                    envs.setdefault(m.group(1), {"value": m.group(1),
                                                  "origin": f"{f.rel}:{line.no}"})
            for m in PATH_TOKEN.finditer(without_urls):
                p = m.group(1)
                if ".." not in p and not p.startswith("/"):
                    paths.setdefault(p, {"value": p, "origin": f"{f.rel}:{line.no}"})
    return {"hosts": sorted(hosts.values(), key=lambda d: d["value"]),
            "execs": sorted(execs.values(), key=lambda d: d["value"]),
            "envs": sorted(envs.values(), key=lambda d: d["value"]),
            "paths": sorted(paths.values(), key=lambda d: d["value"])}
'''


def build(dst: Path, src: Path | None = None) -> Path:
    global SRC, DST
    SRC = src or ROOT
    DST = dst
    if DST.exists():
        shutil.rmtree(DST)
    shutil.copytree(SRC, DST, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", "cordon.zip"))
    s = DST / "src" / "cordon"

    # 1. ScanResult without the entities field
    p = s / "model.py"
    t = p.read_text()
    old = ("    errors: list[str]\n"
           "    # Derived capabilities travel with the result so manifest derivation does\n"
           "    # not parse the files a second time. Not part of the serialised interface.\n"
           "    entities: dict = field(default_factory=dict, repr=False, compare=False)\n")
    assert old in t, "model.py entity field not found"
    p.write_text(t.replace(old, "    errors: list[str]\n"))

    # 2. The original single-module scanner
    ins = (s / "inspector.py").read_text()
    start = ins.index("SHELL_LANGS = ")
    end = ins.index("@dataclass(frozen=True)\nclass Inspection:")
    (s / "scan.py").write_text(HEADER + ins[start:end] + TAIL)
    (s / "inspector.py").unlink()
    (s / "policy.py").unlink()

    # 3. Original inline exec check in the hook
    p = s / "hook.py"
    t = p.read_text()
    t = t.replace("from .policy import exec_allowed, hook_deny_reason\n", "")
    old = ("    if not exec_allowed(manifest, exe):\n"
           "        return _deny(hook_deny_reason(exe), \"exec\", exe=exe)\n")
    assert old in t, "hook.py policy call not found"
    t = t.replace(old,
                  "    if exe not in caps[\"exec\"][\"allow\"]:\n"
                  "        return _deny(f\"executable '{exe}' is not in the allowlist\", \"exec\", exe=exe)\n")
    p.write_text(t)

    # 4. Original inline exec check in the shim
    p = s / "guard.py"
    t = p.read_text()
    t = t.replace("from .policy import SHIM_DENY_REASON, exec_allowed\n", "")
    old = ("    if not exec_allowed(manifest, name, extra_deny=BLOCK_SHIMS):\n"
           "        log(\"deny\", {\"name\": name, \"args\": args[:5],\n"
           "                     \"reason\": SHIM_DENY_REASON})\n")
    assert old in t, "guard.py policy call not found"
    t = t.replace(old,
                  "    allowed = manifest[\"capabilities\"][\"exec\"][\"allow\"]\n"
                  "    if name not in allowed or name in BLOCK_SHIMS:\n"
                  "        log(\"deny\", {\"name\": name, \"args\": args[:5],\n"
                  "                     \"reason\": \"executable not allowed\"})\n")
    p.write_text(t)

    # 5. Original monolithic derive()
    (s / "manifest.py").write_text(LEGACY_MANIFEST)
    print(f"legacy reconstruction written to {DST}")
    return DST


if __name__ == "__main__":
    import sys
    build(Path(sys.argv[1]))
