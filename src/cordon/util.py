"""Shared constants and deterministic primitives.

Nothing in this module executes skill content. All hashing uses raw bytes;
Unicode normalisation is for display and matching only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
TOOL = "cordon"

MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 10_000_000
MAX_FILES = 500
MAX_LINE_CHARS = 4000
MAX_FINDINGS = 2000
ZERO_HASH = "0" * 64

TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".rst", ".py", ".sh", ".bash", ".zsh",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yaml",
    ".yml", ".toml", ".cfg", ".ini", ".rb", ".pl", ".php", ".ps1",
    ".bat", ".cmd", ".html", ".htm", ".css", ".sql", ".rs", ".go",
    ".java", ".c", ".h", ".cpp", ".cc", ".lua", ".r", ".svg", ".xml",
    "", ".lock", ".env.example",
}
BINARY_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
               ".zip", ".gz", ".tgz", ".woff", ".woff2", ".ttf", ".so",
               ".dll", ".exe", ".bin", ".pyc", ".wasm", ".mp4", ".mp3"}

# Invisible or direction-changing code points. UAX #9 warns about overrides.
INVISIBLE = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\u2061", "\u2062",
    "\u2063", "\u2064", "\u180e",
}
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0458": "j",
    "\u0501": "d", "\u0391": "A", "\u039f": "O", "\u0395": "E",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P",
}


class CordonError(Exception):
    """A user-facing, deterministic error."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key: {k}")
        out[k] = v
    return out


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def json_loads(data: str | bytes) -> Any:
    """Strict JSON: rejects duplicate keys, NaN and Infinity."""
    return json.loads(data, object_pairs_hook=_no_duplicates,
                      parse_constant=_reject_constant)


def canonical_json(obj: Any) -> bytes:
    """Stable UTF-8 JSON for hashing and signing (RFC 8785 inspired).

    Sorted keys, no whitespace, ASCII-escaped, no non-finite numbers.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def canonical_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def stable_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()[:12].upper()


def clamp(text: str, limit: int = 160) -> str:
    """Make evidence safe to print: no raw control or bidi characters."""
    out: list[str] = []
    for ch in text:
        if ch == "\n":
            out.append("\\n")
        elif ch in ("\r", "\t"):
            out.append(" ")
        elif ch in INVISIBLE or (unicodedata.category(ch) == "Cc"):
            out.append(f"[U+{ord(ch):04X}]")
        else:
            out.append(ch)
    text = "".join(out)
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def redact(text: str) -> str:
    """Hide long tokens that may be real secrets in evidence output."""
    def cut(m: re.Match[str]) -> str:
        s = m.group(0)
        return s[:6] + "…" if len(s) > 14 else s
    return re.sub(r"[A-Za-z0-9_\-]{28,}", cut, clamp(text))


def fold(text: str) -> str:
    """NFKC + confusable folding, used only for detection, never for hashing."""
    out = []
    for ch in unicodedata.normalize("NFKC", text):
        out.append(CONFUSABLES.get(ch, ch))
    return "".join(out)


def decode_bytes(raw: bytes) -> tuple[str, str | None]:
    """Return (text, encoding_note). Raw bytes stay authoritative for hashing."""
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16-le", "replace"), "utf-16-le"
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16-be", "replace"), "utf-16-be"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace"), "utf-8-bom"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace"), "invalid-utf8"


def fixed_time() -> int | None:
    v = os.environ.get("CORDON_FIXED_TIME")
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def now() -> int:
    t = fixed_time()
    if t is not None:
        return t
    import time
    return int(time.time())


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cordon-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json_file(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise CordonError(f"{path}: file too large", 1)
    try:
        return json_loads(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise CordonError(f"{path}: invalid JSON: {e}", 3) from e


def write_json_file(path: Path, obj: Any, mode: int = 0o644) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True,
                                  ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n", mode)


def posix_rel(path: str) -> str:
    return path.replace("\\", "/").lstrip("/")


def is_safe_rel(rel: str) -> bool:
    if not rel or rel.startswith("/") or "\\" in rel:
        return False
    parts = rel.split("/")
    return ".." not in parts and "~" not in parts and "\x00" not in rel
