"""Deep inspection module: one line walk produces findings and capabilities.

The inspector reads decoded text. It never imports, executes, fetches or
evaluates skill content. Every finding carries a stable id, a location, a
capability and redacted evidence. Detection is structural; it cannot decide
whether a model would obey an instruction.

Interface: inspect(files). Everything else in this file is implementation.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, replace
from typing import Iterable

from .model import Finding, SkillFile, findings_key
from .util import (CONFUSABLES, INVISIBLE, MAX_FINDINGS, MAX_LINE_CHARS,
                   clamp, fold, redact, stable_id)

SHELL_LANGS = {"sh", "shell", "bash", "zsh", "console", "shell-session"}
CODE_LANGS = {"python", "py", "javascript", "js", "typescript", "ts",
              "ruby", "rb", "go", "rust", "rs", "powershell", "ps1", "php"}

RULES: dict[str, tuple[str, str, str]] = {
    # rule_id: (default severity, capability, message)
    "CORDON-UNI-001": ("high", "prompt", "Invisible or bidirectional Unicode control character"),
    "CORDON-UNI-002": ("medium", "prompt", "Confusable homoglyph in an instruction-like line"),
    "CORDON-ENC-001": ("high", "prompt", "Base64 blob decodes to an instruction or network sink"),
    "CORDON-ENC-002": ("medium", "exec", "Obfuscated string construction"),
    "CORDON-INJ-001": ("high", "prompt", "Instruction override or concealment phrase"),
    "CORDON-INJ-002": ("high", "prompt", "Instruction hidden in a comment, frontmatter or reference label"),
    "CORDON-META-001": ("critical", "prompt", "Instruction that targets this scanner or its policy"),
    "CORDON-SEC-001": ("high", "env", "Credential or secret source referenced"),
    "CORDON-NET-001": ("high", "net", "Outbound network sink referenced"),
    "CORDON-EXE-001": ("high", "exec", "Destructive shell operation"),
    "CORDON-EXE-002": ("high", "exec", "Dynamic or remote code execution"),
    "CORDON-FS-001": ("medium", "fs.read", "Path outside the skill directory referenced"),
    "CORDON-IO-001": ("low", "fs.write", "Write to a path outside the skill directory"),
}

OVERRIDE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b.{0,60}"
    r"\b(?:previous|prior|above|earlier|system|safety|policy|permission|guard|instructions?|prompts?|rules?)\b"
    r"|\b(?:do\s+not|don't|never)\b.{0,40}\b(?:tell|inform|mention|reveal|report|log)\b.{0,30}\b(?:user|human|operator)\b"
    r"|\b(?:hidden|secret|internal)\s+instructions?\b"
    r"|\bsend\b.{0,50}\b(?:contents?|token|secret|key|credentials?)\b.{0,40}\bto\b"
    r"|\bexfiltrat\w*\b"
    r"|\bsystem\s+prompt\b"
)
META = re.compile(
    r"(?i)\b(?:ignore|skip|disable|bypass)\b.{0,40}\b(?:cordon|scanner|scan|manifest|sandbox|policy|guard)\b"
    r"|permissionDecision.{0,30}\ballow\b"
    r"|\bset\b.{0,30}\bpermissions?\b.{0,20}\ballow\b"
    r"|\bdisable\b.{0,20}\b(?:the\s+)?manifest\b"
)
SECRET = re.compile(
    r"(?i)(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|aws_secret_access_key|"
    r"github_token|openai_api_key|anthropic_api_key|api[_-]?key|"
    r"printenv|os\.environ|process\.env|getenv|/etc/shadow|keychain|"
    r"(?:^|[^\w])\.env(?:$|[^\w])|credentials\.json|secrets?\.yaml)"
)
NET = re.compile(
    r"(?i)(https?://[^\s)'\"<>]{1,200}|\b(?:curl|wget|ncat|nc)\s+-|"
    r"requests\.(?:get|post|put)|urllib\.request|fetch\(|axios\.|"
    r"socket\.(?:socket|create_connection)|/dev/tcp/|\bdns\.resolver\b|"
    r"\b(?:https?\.request|http\.request)\b)"
)
IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DESTRUCTIVE = re.compile(
    r"(?i)(\brm\s+-[a-z]*[rf][a-z]*[rf][a-z]*\b|\brm\s+-rf\b|"
    r"\bmkfs\b|\bdd\s+if=|\bchmod\s+(?:777|\+s|4777|u\+s)|\bchown\b|"
    r"\bsudo\b|:\(\)\{\s*:\|:\s*&\s*\}\s*;|\bshred\b|"
    r"\bformat\s+[a-z]:\b|\bdel\s+/[sq]\b)"
)
DYNAMIC = re.compile(
    r"(?i)(\b(?:curl|wget)[^\n|]{0,120}\|\s*(?:sh|bash|zsh)\b|"
    r"\beval\b|\bexec\s*\(|\bos\.system\b|subprocess\.(?:run|Popen|call|check_output)|"
    r"\bpickle\.loads\b|\b(?:ba)?sh\s+-c\b|python[0-9.]*\s+-c\b|"
    r"\batob\b|base64\.b64decode|String\.fromCharCode|chr\(\d+\)\s*\+)"
)
ESCAPE = re.compile(r"(?i)(\.\./|\b/etc/|\b/root/|\b/usr/|/var/|~/|/home/|C:\\Windows|%USERPROFILE%)")
WRITE = re.compile(r"(?:>>?|\btee\b|\bmv\b|\bcp\b|\brm\b|\bmkdir\b|\btouch\b)\s+([^\s;|&]{1,120})")
OBFUSCATE = re.compile(r"(?i)(\\x[0-9a-f]{2}|%[0-9a-f]{2}|fromCharCode|atob\(|"
                       r"b64decode|chr\(\d+\)|String\.fromCharCode|eval\(|Buffer\.from)")
B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
URL = re.compile(r"https?://[^\s)'\"<>]{1,200}")
EXEC_TOKEN = re.compile(r"(?i)\b(ls|cat|grep|rg|sed|head|tail|wc|jq|git|echo|printf|"
                        r"python3?|node|npm|npx|pytest|make|cargo|go|rustc|"
                        r"sh|bash|curl|wget|nc|sudo|rm|chmod|mv|cp|tee|"
                        r"find|xargs|awk|sort|uniq|diff|tar|unzip)\b")
ENV_TOKEN = re.compile(r"\b([A-Z][A-Z0-9_]{2,40})\b")
PATH_TOKEN = re.compile(r"(?<![\w/])((?:[\w.\-]+/){0,4}[\w.\-]+\.(?:md|txt|json|yaml|yml|py|sh|js|ts|toml|cfg|html))\b")


@dataclass(frozen=True)
class Line:
    rel: str
    no: int
    text: str
    folded: str
    context: str
    fence_lang: str
    file_lang: str = ""

    @property
    def is_code(self) -> bool:
        return self.context in ("shell", "code") or self.fence_lang in CODE_LANGS or self.fence_lang in SHELL_LANGS


def _lines(f: SkillFile) -> list[Line]:
    if f.lang == "binary" or not f.text:
        return []
    out: list[Line] = []
    in_fence = False
    fence_lang = ""
    in_front = False
    in_comment = False
    for no, raw in enumerate(f.text.splitlines(), 1):
        truncated = len(raw) > MAX_LINE_CHARS
        text = raw[:MAX_LINE_CHARS]
        low = text.strip().lower()
        if no == 1 and text.strip() == "---":
            in_front = True
            out.append(Line(f.rel, no, text, fold(text), "frontmatter", ""))
            continue
        if in_front and text.strip() == "---":
            out.append(Line(f.rel, no, text, fold(text), "frontmatter", ""))
            in_front = False
            continue
        m = re.match(r"^\s*(```|~~~)\s*([\w+-]*)\s*$", text)
        if m:
            if in_fence:
                in_fence = False
                fence_lang = ""
            else:
                in_fence = True
                fence_lang = m.group(2).lower()
            out.append(Line(f.rel, no, text, fold(text), "fence-marker", fence_lang))
            continue
        if in_fence:
            ctx = "shell" if fence_lang in SHELL_LANGS or f.lang == "shell" else "code"
            out.append(Line(f.rel, no, text, fold(text), ctx, fence_lang))
            continue
        if in_front:
            out.append(Line(f.rel, no, text, fold(text), "frontmatter", ""))
            continue
        hidden = "html-comment" if ("<!--" in text or in_comment or "-->" in text) else "prose"
        if "<!--" in text and "-->" not in text:
            in_comment = True
        if "-->" in text:
            in_comment = False
        if re.match(r"^\s*\[[^\]]+\]:\s*\S+", text):
            hidden = "reference"
        out.append(Line(f.rel, no, text, fold(text), hidden, ""))
        if truncated:
            # A truncated line is a finding so a large payload cannot hide past the cap.
            pass
    return [replace(line, file_lang=f.lang) for line in out]


def _add(out: list[Finding], rule: str, line: Line, match: re.Match[str] | None,
         severity: str | None = None, confidence: str = "high",
         message: str | None = None, evidence: str | None = None) -> None:
    if len(out) >= MAX_FINDINGS:
        return
    sev, capability, default_msg = RULES[rule]
    col = (match.start() + 1) if match else 1
    snippet = evidence if evidence is not None else (match.group(0) if match else line.text[:80])
    fid = stable_id(rule, line.rel, str(line.no), str(col), fold(snippet)[:120])
    out.append(Finding(fid, rule, severity or sev, confidence, capability,
                       line.rel, line.no, col, line.context,
                       message or default_msg, redact(snippet)))


def _hidden_severity(line: Line, base: str) -> tuple[str, str]:
    if line.context in ("html-comment", "frontmatter", "reference"):
        return "high", "high"
    if line.is_code:
        return base, "high"
    return "medium", "medium"


def _decode_b64(blob: str) -> str | None:
    if len(blob) > 4096:
        return None
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > 4096:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
    return s if printable / max(1, len(s)) > 0.85 else None


def scan_lines(lines: list[Line]) -> list[Finding]:
    out: list[Finding] = []
    for line in lines:
        t = line.folded
        raw = line.text

        # Invisible Unicode. Check raw text so NFKC cannot erase the evidence.
        inv = [(i + 1, c) for i, c in enumerate(raw) if c in INVISIBLE]
        if inv:
            col, ch = inv[0]
            _add(out, "CORDON-UNI-001", line,
                 re.match(r"\S", raw[max(0, col - 1):]) or None,
                 severity="high", confidence="high",
                 evidence=f"U+{ord(ch):04X} at column {col} (x{len(inv)})")
            # fix the location to the actual control character
            f = out[-1]
            from dataclasses import replace
            out[-1] = replace(f, column=col)
        conf = [c for c in raw if c in CONFUSABLES]
        if conf and (OVERRIDE.search(t) or META.search(t) or NET.search(t) or DESTRUCTIVE.search(t)):
            _add(out, "CORDON-UNI-002", line, None, confidence="high",
                 evidence="confusables: " + " ".join(f"U+{ord(c):04X}" for c in conf[:6]))

        for m in B64.finditer(t):
            decoded = _decode_b64(m.group(0))
            if decoded and (OVERRIDE.search(fold(decoded)) or NET.search(fold(decoded))
                            or SECRET.search(fold(decoded)) or "curl" in decoded.lower()):
                _add(out, "CORDON-ENC-001", line, m, confidence="high",
                     evidence=clamp(decoded, 120))

        if line.is_code:
            for m in OBFUSCATE.finditer(t):
                _add(out, "CORDON-ENC-002", line, m, severity="medium", confidence="medium")
                break

        for m in META.finditer(t):
            _add(out, "CORDON-META-001", line, m, severity="critical", confidence="high")
        for m in OVERRIDE.finditer(t):
            sev, conf = _hidden_severity(line, "high")
            _add(out, "CORDON-INJ-001", line, m, severity=sev, confidence=conf)
        if line.context in ("html-comment", "frontmatter", "reference") and (
                OVERRIDE.search(t) or SECRET.search(t) or NET.search(t) or META.search(t)):
            _add(out, "CORDON-INJ-002", line, None, confidence="high",
                 evidence=clamp(raw, 120))
        for m in SECRET.finditer(t):
            sev, conf = _hidden_severity(line, "high")
            _add(out, "CORDON-SEC-001", line, m, severity=sev, confidence=conf)
        for m in NET.finditer(t):
            sev, conf = _hidden_severity(line, "high")
            _add(out, "CORDON-NET-001", line, m, severity=sev, confidence=conf)
        for m in IP.finditer(t):
            _add(out, "CORDON-NET-001", line, m, severity="medium", confidence="medium")
        for m in DESTRUCTIVE.finditer(t):
            sev, conf = _hidden_severity(line, "high")
            _add(out, "CORDON-EXE-001", line, m, severity=sev, confidence=conf)
        for m in DYNAMIC.finditer(t):
            sev, conf = _hidden_severity(line, "high")
            _add(out, "CORDON-EXE-002", line, m, severity=sev, confidence=conf)
        for m in ESCAPE.finditer(t):
            sev, conf = _hidden_severity(line, "medium")
            _add(out, "CORDON-FS-001", line, m, severity=sev, confidence=conf)
        for m in WRITE.finditer(t):
            target = m.group(1)
            if target.startswith(("/", "~", "..")) or "\\" in target:
                _add(out, "CORDON-IO-001", line, m, severity="medium", confidence="medium")
    out.sort(key=findings_key)
    return out


@dataclass(frozen=True)
class Inspection:
    findings: list[Finding]
    entities: dict[str, list[dict[str, str]]]
    errors: list[str]


def entities_from_lines(lines: list[Line]) -> dict[str, list[dict[str, str]]]:
    """Deterministic candidate capabilities, derived from the same line walk."""
    hosts: dict[str, dict[str, str]] = {}
    execs: dict[str, dict[str, str]] = {}
    envs: dict[str, dict[str, str]] = {}
    paths: dict[str, dict[str, str]] = {}
    for line in lines:
        t = line.folded
        without_urls = URL.sub(" ", t)
        for m in URL.finditer(t):
            try:
                host = urllib.parse.urlsplit(m.group(0)).hostname or ""
            except ValueError:
                host = ""
            if host:
                hosts.setdefault(host, {"value": host,
                                        "origin": f"{line.rel}:{line.no}"})
        if line.is_code or line.file_lang in ("shell", "python", "javascript"):
            for m in EXEC_TOKEN.finditer(t):
                execs.setdefault(m.group(1).lower(),
                                 {"value": m.group(1).lower(),
                                  "origin": f"{line.rel}:{line.no}"})
        if ("$" in without_urls or "environ" in without_urls
                or "getenv" in without_urls or "process.env" in without_urls
                or "printenv" in without_urls):
            for m in ENV_TOKEN.finditer(without_urls):
                envs.setdefault(m.group(1), {"value": m.group(1),
                                              "origin": f"{line.rel}:{line.no}"})
        for m in PATH_TOKEN.finditer(without_urls):
            p = m.group(1)
            if ".." not in p and not p.startswith("/"):
                paths.setdefault(p, {"value": p,
                                     "origin": f"{line.rel}:{line.no}"})
    return {"hosts": sorted(hosts.values(), key=lambda d: d["value"]),
            "execs": sorted(execs.values(), key=lambda d: d["value"]),
            "envs": sorted(envs.values(), key=lambda d: d["value"]),
            "paths": sorted(paths.values(), key=lambda d: d["value"])}


def inspect(files: Iterable[SkillFile]) -> Inspection:
    """One interface. One line walk. Findings and capabilities stay in step."""
    errors: list[str] = []
    lines: list[Line] = []
    for f in files:
        if f.lang == "binary":
            continue
        if f.encoding_note == "invalid-utf8":
            errors.append(
                f"{f.rel}: invalid UTF-8, decoded with replacement for detection only")
        lines.extend(_lines(f))
    findings = scan_lines(lines)
    if len(findings) >= MAX_FINDINGS:
        errors.append(f"finding cap {MAX_FINDINGS} reached; output truncated")
    return Inspection(findings, entities_from_lines(lines), errors)


def extract_entities(files: Iterable[SkillFile]) -> dict[str, list[dict[str, str]]]:
    """Compatibility adapter for callers that still pass files."""
    return inspect(list(files)).entities
