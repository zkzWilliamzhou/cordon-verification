"""Renderers: human text, JSON and SARIF 2.1.0."""
from __future__ import annotations

import json
from typing import Any

from .model import ScanResult
from .scan import RULES
from .util import VERSION

LEVEL = {"critical": "error", "high": "error", "medium": "warning",
         "low": "note", "info": "note"}


def as_json(result: ScanResult) -> bytes:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True,
                      ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"


def as_text(result: ScanResult) -> bytes:
    s = result.summary()
    lines = [f"cordon {VERSION}  scanned {len(result.files)} file(s) in {result.root}",
             f"findings: {s['total']} (critical {s['critical']}, high {s['high']}, "
             f"medium {s['medium']}, low {s['low']}, info {s['info']})",
             f"digest: {result.digest}"]
    blocking = result.blocking()
    lines.append(f"blocking (high confidence): {len(blocking)}")
    lines.append("")
    if not result.findings:
        lines.append("No structural indicators found. This is not a safety verdict.")
    for f in result.findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule_id} {f.finding_id} "
                     f"{f.file}:{f.line}:{f.column} ({f.context}/{f.confidence})")
        lines.append(f"    {f.message}")
        lines.append(f"    evidence: {f.evidence}")
    for e in result.errors:
        lines.append(f"[note] {e}")
    lines.append("")
    lines.append("Advisory static analysis. No findings does not mean safe.")
    return ("\n".join(lines) + "\n").encode("utf-8")


def as_sarif(result: ScanResult) -> bytes:
    rules = []
    for rid, (sev, _cap, msg) in sorted(RULES.items()):
        rules.append({
            "id": rid, "name": rid, "shortDescription": {"text": msg},
            "defaultConfiguration": {"level": LEVEL.get(sev, "warning")},
            "properties": {"severity": sev},
        })
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule_id,
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.message} | evidence: {f.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line),
                               "startColumn": max(1, f.column)},
                },
            }],
            "properties": {"findingId": f.finding_id, "capability": f.capability,
                           "confidence": f.confidence, "context": f.context},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "cordon", "version": VERSION,
                                "informationUri": "https://github.com/cordon/cordon",
                                "rules": rules}},
            "results": results,
            "properties": {"digest": result.digest,
                           "summary": result.summary(),
                           "disclaimer": "Advisory. No findings does not mean safe."},
        }],
    }
    return json.dumps(doc, indent=2, sort_keys=True,
                      ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"


def render(result: ScanResult, fmt: str) -> bytes:
    if fmt == "json":
        return as_json(result)
    if fmt == "sarif":
        return as_sarif(result)
    if fmt == "text":
        return as_text(result)
    raise ValueError(f"unknown format: {fmt}")


def manifest_text(m: dict[str, Any]) -> bytes:
    caps = m["capabilities"]
    out = [f"cordon {VERSION} capability manifest ({m['schema']})",
           f"root: {m['skill_root']}",
           f"scan_digest: {m['scan_digest']}",
           f"policy_hash: {m['policy_hash']}",
           f"mode: {m['policy']['mode']}  (block_on: {', '.join(m['policy']['block_on'])})",
           "",
           f"fs.read   : {', '.join(caps['fs']['read']) or '(deny all)'}",
           f"fs.write  : {', '.join(caps['fs']['write']) or '(deny all)'}",
           f"exec.allow: {', '.join(caps['exec']['allow']) or '(deny all)'}",
           f"exec.deny : {', '.join(caps['exec']['deny']) or '(none)'}",
           f"net.allow : {', '.join(caps['net']['allow_hosts']) or '(deny all)'}",
           f"net.deny  : {', '.join(caps['net']['deny_hosts']) or '(none)'}",
           f"env.allow : {', '.join(caps['env']['allow']) or '(deny all)'}",
           "", "derived decisions:"]
    for d in m["derived"]:
        out.append(f"  {d['decision']:7} {d['capability']:9} {d['value']} "
                   f"<- {d['origin']} ({d['reason']})")
    out += ["", m["policy"]["label"]]
    return ("\n".join(out) + "\n").encode("utf-8")
