"""Derive a least-privilege capability contract from a scan.

Default deny. A candidate becomes allowed only when it is on the safe list,
came from code rather than prose, and no blocking finding touches its origin.
Operator grants are recorded with origin "operator" so every decision is
attributable.

The module has one public interface, derive(scan, grants). Classification and
grant application sit behind it. Output records stay byte-stable; ADR-0005
gates any change to them with a golden snapshot comparison.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
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


@dataclass
class Classification:
    fs_read: list[str] = field(default_factory=list)
    exec_allow: list[str] = field(default_factory=list)
    exec_deny: list[str] = field(default_factory=list)
    net_allow: list[str] = field(default_factory=list)
    net_deny: list[str] = field(default_factory=list)
    env_allow: list[str] = field(default_factory=list)
    env_deny: list[str] = field(default_factory=list)
    derived: list[dict[str, str]] = field(default_factory=list)

    def note(self, cap: str, value: str, origin: str,
             decision: str, reason: str) -> None:
        self.derived.append({"capability": cap, "value": value,
                             "origin": origin, "decision": decision,
                             "reason": reason})


def _classify(entities: dict[str, list[dict[str, str]]],
              blocked: set[str]) -> Classification:
    """Sort each candidate class into allowed, denied or review."""
    c = Classification()

    for item in entities["paths"]:
        p = item["value"]
        if not is_safe_rel(p) or item["origin"] in blocked:
            c.note("fs.read", p, item["origin"], "denied",
                   "unsafe path or blocking finding")
            continue
        c.fs_read.append(p)
        c.note("fs.read", p, item["origin"], "allowed",
               "relative path inside skill root")

    for item in entities["execs"]:
        name = item["value"]
        if name in DANGEROUS_EXEC or item["origin"] in blocked:
            c.exec_deny.append(name)
            c.note("exec", name, item["origin"], "denied",
                   "dangerous executable or blocking finding")
        elif name in SAFE_EXEC:
            c.exec_allow.append(name)
            c.note("exec", name, item["origin"], "allowed",
                   "safe executable in code context")
        else:
            c.note("exec", name, item["origin"], "review",
                   "not on the v0.1 safe list")

    for item in entities["hosts"]:
        host = item["value"]
        c.net_deny.append(host)
        c.note("net.host", host, item["origin"], "denied",
               "network is default deny; add --allow-host to grant")

    for item in entities["envs"]:
        name = item["value"]
        if SECRET_ENV.search(name) or item["origin"] in blocked:
            c.env_deny.append(name)
            c.note("env", name, item["origin"], "denied", "secret-like or blocked")
        elif name in SAFE_ENV:
            c.env_allow.append(name)
            c.note("env", name, item["origin"], "allowed",
                   "safe environment variable")
        else:
            c.note("env", name, item["origin"], "review", "unknown variable")
    return c


def _apply_grants(c: Classification, grants: dict[str, list[str]]) -> None:
    """Record every operator grant, including ones a later filter drops."""
    for cap, key, target in (
        ("exec", "exec", c.exec_allow), ("net.host", "host", c.net_allow),
        ("env", "env", c.env_allow), ("fs.write", "write", []),
    ):
        for value in grants.get(key, []):
            if value not in target:
                target.append(value)
            c.note(cap, value, "operator", "allowed", "explicit operator grant")
            if cap == "net.host" and value in c.net_deny:
                c.net_deny.remove(value)
            if cap == "exec" and value in c.exec_deny:
                c.exec_deny.remove(value)


def derive(scan: ScanResult, grants: dict[str, list[str]] | None = None) -> dict[str, Any]:
    grants = grants or {}
    # The inspection pass already produced these candidates. Reuse them; the
    # fallback keeps derive usable with a ScanResult built by an older caller.
    entities = scan.entities or extract_entities(scan.files)
    c = _classify(entities, _blocking_origins(scan))
    _apply_grants(c, grants)

    fs_write = [v for v in grants.get("write", []) if is_safe_rel(v)]
    capabilities = {
        "fs": {"read": sorted(set(c.fs_read)), "write": sorted(set(fs_write))},
        "exec": {"allow": sorted(set(c.exec_allow)), "deny": sorted(set(c.exec_deny))},
        "net": {"allow_hosts": sorted(set(c.net_allow)),
                "deny_hosts": sorted(set(c.net_deny))},
        "env": {"allow": sorted(set(c.env_allow)), "deny": sorted(set(c.env_deny))},
    }
    return {
        "schema": SCHEMA,
        "tool_version": VERSION,
        "skill_root": scan.root,
        "scan_digest": scan.digest,
        "defaults": {"fs": "deny", "exec": "deny", "net": "deny", "env": "deny"},
        "capabilities": capabilities,
        "derived": sorted(c.derived,
                          key=lambda d: (d["capability"], d["value"], d["origin"])),
        "finding_ids": [f.finding_id for f in scan.findings],
        "policy": {"block_on": ["critical", "high"], "confidence": "high",
                   "mode": "advisory",
                   "label": "Advisory. A pure-Python hook or PATH shim is bypassable. "
                            "Use an OS backend (Landlock/bubblewrap/AppContainer) for enforcement."},
        "policy_hash": canonical_hex(capabilities),
    }


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
