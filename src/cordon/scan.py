"""Thin adapter: bounded enumeration plus one deep inspection call.

The line model, the rules and the capability candidates live in `inspector`.
Names below are re-exported so the interface stays the test surface.
"""
from __future__ import annotations

from pathlib import Path

from .fs import enumerate_skill
from .inspector import (RULES, Inspection, Line, _lines, entities_from_lines,
                        extract_entities, inspect, scan_lines)
from .model import Finding, ScanResult, SkillFile, findings_key

__all__ = ["scan", "scan_lines", "extract_entities", "entities_from_lines",
           "inspect", "Inspection", "Line", "RULES", "_lines"]


def scan(root: Path) -> ScanResult:
    errors: list[str] = []
    files = enumerate_skill(root, errors)
    ins = inspect(files)
    errors.extend(ins.errors)
    return ScanResult(str(root), files, ins.findings, errors, ins.entities)
