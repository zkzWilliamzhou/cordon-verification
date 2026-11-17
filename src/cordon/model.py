"""Typed records shared by every module. The interface is the test surface."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .util import VERSION

SEVERITIES = ("critical", "high", "medium", "low", "info")
BLOCKING = ("critical", "high")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    capability: str
    file: str
    line: int
    column: int
    context: str
    message: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SkillFile:
    rel: str
    path: str
    size: int
    mode: int
    sha256: str
    text: str
    encoding_note: str | None
    lang: str

    def to_dict(self) -> dict[str, Any]:
        return {"rel": self.rel, "size": self.size, "mode": self.mode,
                "sha256": self.sha256, "lang": self.lang,
                "encoding_note": self.encoding_note}


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    capability: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"decision": "allow" if self.allow else "deny",
                "reason": self.reason, "capability": self.capability,
                "detail": self.detail}


@dataclass(frozen=True)
class ScanResult:
    root: str
    files: list[SkillFile]
    findings: list[Finding]
    errors: list[str]
    # Derived capabilities travel with the result so manifest derivation does
    # not parse the files a second time. Not part of the serialised interface.
    entities: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def digest(self) -> str:
        from .util import canonical_hex
        return canonical_hex({"files": [f.sha256 for f in self.files],
                              "findings": [f.finding_id for f in self.findings],
                              "errors": self.errors})

    def to_dict(self) -> dict[str, Any]:
        return {"schema": "cordon.scan/v1", "tool_version": VERSION,
                "root": self.root, "digest": self.digest,
                "file_count": len(self.files),
                "files": [f.to_dict() for f in self.files],
                "findings": [f.to_dict() for f in self.findings],
                "errors": list(self.errors),
                "summary": self.summary(),
                "disclaimer": (
                    "Advisory static analysis. No findings does not mean safe. "
                    "Semantic prompt injection, unknown encodings and runtime "
                    "behaviour are out of scope.")}

    def summary(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        out["total"] = len(self.findings)
        return out

    def blocking(self) -> list[Finding]:
        return [f for f in self.findings
                if f.severity in BLOCKING and f.confidence == "high"]


def findings_key(f: Finding) -> tuple[str, int, int, str]:
    return (f.file, f.line, f.column, f.rule_id)
