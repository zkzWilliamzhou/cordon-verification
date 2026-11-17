"""Bounded, symlink-safe enumeration of a skill folder.

The directory is never trusted. We lstat twice, open with O_NOFOLLOW, verify
the descriptor against the earlier stat, and cap every resource. Original bytes
are hashed; decoded text is only used for detection.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .model import SkillFile
from .util import (BINARY_SKIP, MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES,
                   TEXT_SUFFIXES, CordonError, decode_bytes, sha256_bytes,
                   posix_rel, is_safe_rel)


def _dir_identity(path: Path) -> tuple[int, int]:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise CordonError(f"{path}: not a real directory (symlinks refused)", 1)
    return (st.st_dev, st.st_ino)


def _lang(rel: str) -> str:
    ext = Path(rel).suffix.lower()
    return {
        ".py": "python", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
        ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".ps1": "powershell",
        ".rb": "ruby", ".go": "go", ".rs": "rust", ".md": "markdown",
        ".markdown": "markdown", ".yaml": "yaml", ".yml": "yaml",
        ".json": "json", ".html": "html", ".htm": "html",
    }.get(ext, "text")


def _read_bounded(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        got = os.fstat(fd)
        if (got.st_dev, got.st_ino, got.st_size) != (
                expected.st_dev, expected.st_ino, expected.st_size):
            raise CordonError(f"{path}: changed during read (TOCTOU)", 3)
        if stat.S_ISLNK(got.st_mode) or not stat.S_ISREG(got.st_mode):
            raise CordonError(f"{path}: not a regular file", 1)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise CordonError(f"{path}: file exceeds {MAX_FILE_BYTES} bytes", 1)
        return b"".join(chunks)
    finally:
        os.close(fd)


def enumerate_skill(root: Path, errors: list[str] | None = None) -> list[SkillFile]:
    """Return sorted SkillFile records. Refuses to follow symlinks anywhere."""
    root = Path(root)
    if not root.exists():
        raise CordonError(f"{root}: does not exist", 1)
    before = _dir_identity(root)
    errors = errors if errors is not None else []
    out: list[SkillFile] = []
    total = 0
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        entries = sorted(os.scandir(directory), key=lambda e: e.name)
        for entry in entries:
            rel = posix_rel(prefix + entry.name if not prefix else prefix + "/" + entry.name)
            if not is_safe_rel(rel) or entry.name.startswith("."):
                errors.append(f"{rel}: skipped unsafe or hidden name")
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as e:
                errors.append(f"{rel}: stat failed ({e})")
                continue
            if stat.S_ISLNK(st.st_mode):
                errors.append(f"{rel}: symlink refused")
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append((Path(entry.path), rel))
                continue
            if not stat.S_ISREG(st.st_mode):
                errors.append(f"{rel}: non-regular file refused")
                continue
            if st.st_size > MAX_FILE_BYTES:
                errors.append(f"{rel}: oversized file refused")
                continue
            if len(out) >= MAX_FILES:
                errors.append(f"{rel}: file count limit reached")
                continue
            total += st.st_size
            if total > MAX_TOTAL_BYTES:
                errors.append(f"{rel}: total size limit reached")
                break
            ext = Path(entry.name).suffix.lower()
            if ext in BINARY_SKIP:
                # Binary files are pinned by hash but never parsed as text.
                try:
                    raw = _read_bounded(Path(entry.path), st)
                except CordonError as e:
                    errors.append(str(e))
                    continue
                out.append(SkillFile(rel, str(entry.path), st.st_size,
                                     stat.S_IMODE(st.st_mode), sha256_bytes(raw),
                                     "", "binary-not-scanned", "binary"))
                continue
            if ext not in TEXT_SUFFIXES:
                errors.append(f"{rel}: unrecognised extension, hashed but not scanned")
                try:
                    raw = _read_bounded(Path(entry.path), st)
                except CordonError as e:
                    errors.append(str(e))
                    continue
                out.append(SkillFile(rel, str(entry.path), st.st_size,
                                     stat.S_IMODE(st.st_mode), sha256_bytes(raw),
                                     "", "unknown-extension", "binary"))
                continue
            try:
                raw = _read_bounded(Path(entry.path), st)
            except CordonError as e:
                errors.append(str(e))
                continue
            text, note = decode_bytes(raw)
            out.append(SkillFile(rel, str(entry.path), st.st_size,
                                 stat.S_IMODE(st.st_mode), sha256_bytes(raw),
                                 text, note, _lang(rel)))
    after = _dir_identity(root)
    if before != after:
        raise CordonError(f"{root}: directory replaced during scan (TOCTOU)", 3)
    out.sort(key=lambda f: f.rel)
    return out
