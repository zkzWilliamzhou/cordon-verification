#!/usr/bin/env python3
"""Install curated agent skills from pinned GitHub tarballs.

Offline by default: uses the five pinned tarballs vendored in
`.vendor/github_skills`. With --download it fetches codeload tarballs and
refuses a tarball whose SHA-256 differs from the lockfile. With --verify-only
it makes no network call and checks the vendored tarballs, every installed
SKILL.md and every upstream notice against the lockfile.

No skill content is executed, imported, or evaluated. Only files are copied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".vendor" / "github_skills"
LOCK = ROOT / "docs" / "skills-lock.json"
DEST = ROOT / ".agents" / "skills"

SOURCES = {
    "anthropics/skills": {
        "branch": "main",
        "license": "upstream: THIRD_PARTY_NOTICES.md / Apache-2.0 for example skills (verify upstream)",
        "skills": ["skill-creator", "webapp-testing", "mcp-builder", "frontend-design"],
        "prefix": "skills",
        "note": "Anthropic Agent Skills reference repo and SKILL.md format source.",
    },
    "mattpocock/skills": {
        "branch": "main",
        "license": "MIT (upstream LICENSE, Copyright 2026 Matt Pocock)",
        "skills": [
            "engineering/improve-codebase-architecture",
            "engineering/codebase-design",
            "engineering/domain-modeling",
            "engineering/tdd",
            "engineering/diagnosing-bugs",
            "engineering/code-review",
            "engineering/prototype",
            "productivity/grilling",
            "productivity/grill-me",
            "productivity/writing-for-agents",
        ],
        "prefix": "skills",
        "note": "Skills For Real Engineers; includes improve-codebase-architecture and grilling.",
    },
    "obra/superpowers": {
        "branch": "main",
        "license": "MIT (upstream LICENSE, Copyright 2025 Jesse Vincent)",
        "skills": [
            "brainstorming", "writing-plans", "executing-plans",
            "test-driven-development", "systematic-debugging",
            "verification-before-completion", "requesting-code-review",
            "receiving-code-review", "writing-skills",
            "dispatching-parallel-agents", "subagent-driven-development",
            "using-superpowers",
        ],
        "prefix": "skills",
        "note": "Superpowers workflow library; brainstorming is the design-first gate.",
    },
    "vercel-labs/skills": {
        "branch": "main",
        "license": "MIT (upstream LICENSE, Copyright 2026 Vercel, Inc.)",
        "skills": ["find-skills"],
        "prefix": "skills",
        "extra": [
            (".automations/pr-labeling/skills/pr-labeling", "pr-labeling"),
            (".automations/triage/skills/triage", "triage"),
        ],
        "note": "The open agent skills CLI (npx skills) and its own skills.",
    },
    "hardikpandya/stop-slop": {
        "branch": "main",
        "license": "MIT (upstream LICENSE, Copyright 2025 Hardik Pandya)",
        "skills": ["."],
        "prefix": "",
        "note": "Stop Slop: removes predictable AI writing patterns from prose.",
    },
}

EXPECTED_SKILL_COUNT = sum(
    len(m["skills"]) + len(m.get("extra", [])) for m in SOURCES.values())


class InstallError(Exception):
    """A deterministic install or verification failure."""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tarball_name(repo: str) -> str:
    return repo.replace("/", "__") + ".tgz"


def load_lock(path: Path = LOCK) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise InstallError(f"cannot read {path}: {e}") from e
    if not isinstance(lock, dict) or lock.get("schema") != 1:
        raise InstallError(f"{path}: not a cordon skills-lock/v1 file")
    if not isinstance(lock.get("sources"), dict) or not isinstance(lock.get("skills"), list):
        raise InstallError(f"{path}: missing sources or skills")
    return lock


def verify_vendored(lock: dict[str, Any], *, root: Path = ROOT,
                    cache: Path = CACHE, dest: Path = DEST) -> list[str]:
    """Verify the vendored corpus strictly offline. Make no network call."""
    lines: list[str] = []
    sources = lock["sources"]
    if set(sources) != set(SOURCES):
        raise InstallError("lockfile sources do not match the curated source set")
    if len(lock["skills"]) != EXPECTED_SKILL_COUNT:
        raise InstallError(f"expected {EXPECTED_SKILL_COUNT} skills, "
                           f"lockfile has {len(lock['skills'])}")

    for repo in sorted(sources):
        tgz = cache / tarball_name(repo)
        expected = sources[repo].get("sha256", "")
        if len(expected) != 64:
            raise InstallError(f"{repo}: lockfile tarball sha256 is missing or malformed")
        if not tgz.is_file():
            raise InstallError(f"{repo}: vendored tarball missing: {tgz}")
        got = sha256(tgz)
        if got != expected:
            raise InstallError(f"{repo}: vendored tarball sha256 mismatch")
        lines.append(f"tarball {repo} sha256={got[:12]}... OK")

    names: set[str] = set()
    for entry in lock["skills"]:
        name = entry.get("name", "")
        if not name or name != PurePosixPath(name).name or name in ("..", ".", "_licenses"):
            raise InstallError(f"unsafe skill name in lockfile: {name!r}")
        if name in names:
            raise InstallError(f"duplicate skill in lockfile: {name}")
        names.add(name)
        rel = entry.get("installed_path", "")
        if rel != f".agents/skills/{name}":
            raise InstallError(f"{name}: unexpected installed_path {rel!r}")
        skill = dest / name / "SKILL.md"
        if not skill.is_file():
            raise InstallError(f"{name}: SKILL.md missing")
        got = sha256(skill)
        if got != entry.get("sha256_of_skill_md"):
            raise InstallError(f"{name}: SKILL.md sha256 mismatch")
        lines.append(f"skill {name} SKILL.md sha256={got[:12]}... OK")

    actual = {p.name for p in dest.iterdir() if p.is_dir() and p.name != "_licenses"}
    if actual != names:
        raise InstallError(f"installed skill set differs from lockfile: "
                           f"missing={sorted(names - actual)} extra={sorted(actual - names)}")

    ldir = dest / "_licenses"
    for repo in sorted(SOURCES):
        stem = repo.replace("/", "__")
        if not ((ldir / (stem + ".LICENSE")).is_file()
                or (ldir / (stem + ".NOTICES")).is_file()):
            raise InstallError(f"{repo}: upstream licence/notice artifact missing")
    lines.append(f"upstream notices: {len(SOURCES)} sources OK")
    lines.append(f"OFFLINE_OK sources={len(sources)} tarballs={len(sources)} "
                 f"skills={len(names)}")
    return lines


def fetch(repo: str, branch: str, dest: Path) -> None:
    """Fetch one tarball to an existing directory, atomically."""
    url = f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    part.unlink(missing_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as r, part.open("wb") as out:
            shutil.copyfileobj(r, out)
        os.replace(part, dest)
        return
    except Exception:
        part.unlink(missing_ok=True)
    try:
        subprocess.run(["curl", "-sSL", "--fail", "-o", str(part), url], check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        part.unlink(missing_ok=True)
        raise InstallError(f"cannot fetch {url}: {e}") from e
    if not part.is_file() or part.stat().st_size == 0:
        part.unlink(missing_ok=True)
        raise InstallError(f"empty download for {url}")
    os.replace(part, dest)


def safe_member(member: tarfile.TarInfo) -> bool:
    """Reject traversal, links, devices and oversized members."""
    name = member.name
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        return False
    parts = PurePosixPath(name).parts
    if any(p == ".." or p.startswith("~") for p in parts):
        return False
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        return False
    if member.size > 8 * 1024 * 1024:
        return False
    return member.isfile() or member.isdir()


def assert_no_symlinks(src: Path) -> None:
    for p in src.rglob("*"):
        if p.is_symlink():
            raise InstallError(f"refusing symlink in skill source: {p}")


def extract(tgz: Path, into: Path) -> Path:
    into.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz, "r:gz") as tf:
        members = [m for m in tf.getmembers() if safe_member(m)]
        if not members:
            raise InstallError(f"no safe members in {tgz}")
        tf.extractall(into, members=members)
    roots = [p for p in into.iterdir() if p.is_dir()]
    if len(roots) != 1:
        raise InstallError(f"unexpected tarball layout in {tgz}")
    return roots[0]


def copy_tree(src: Path, dst: Path) -> None:
    assert_no_symlinks(src)
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, symlinks=False, ignore=shutil.ignore_patterns(
        "__pycache__", "*.pyc", ".DS_Store", "node_modules", ".git"))


def install(cache: Path, download: bool) -> dict[str, Any]:
    known = load_lock(LOCK)["sources"] if LOCK.exists() else {}
    lock: dict[str, Any] = {"schema": 1, "generated_by": "scripts/install_skills.py",
                            "sources": {}, "skills": []}
    for repo, meta in SOURCES.items():
        tgz = cache / tarball_name(repo)
        if download or not tgz.exists():
            fetch(repo, meta["branch"], tgz)
        if not tgz.is_file():
            raise InstallError(f"MISSING tarball {tgz}")
        digest = sha256(tgz)
        expected = known.get(repo, {}).get("sha256")
        if expected and digest != expected:
            raise InstallError(f"{repo}: downloaded/cached tarball sha256 mismatch "
                               f"with {LOCK}; refusing to install")
        lock["sources"][repo] = {
            "url": f"https://github.com/{repo}",
            "tarball": f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{meta['branch']}",
            "sha256": digest,
            "license": meta["license"],
            "note": meta["note"],
        }
        with tempfile.TemporaryDirectory(prefix="cordon-skills-") as td:
            base = extract(tgz, Path(td) / "x")
            entries = []
            for rel in meta["skills"]:
                src = (base / meta["prefix"] / rel) if meta["prefix"] else (base / rel)
                if rel == ".":
                    src = base
                if not (src / "SKILL.md").is_file():
                    raise InstallError(f"SKILL.md missing: {repo}:{rel}")
                name = rel.split("/")[-1] if rel != "." else "stop-slop"
                if not name or name != PurePosixPath(name).name or name in (".", ".."):
                    raise InstallError(f"unsafe skill name: {name!r}")
                entries.append((src, name, rel))
            for extra_rel, name in meta.get("extra", []):
                src = base / extra_rel
                if not (src / "SKILL.md").is_file():
                    raise InstallError(f"SKILL.md missing: {repo}:{extra_rel}")
                entries.append((src, name, extra_rel))
            for src, name, rel in entries:
                dst = DEST / name
                copy_tree(src, dst)
                lock["skills"].append({
                    "name": name, "source": repo, "source_path": rel,
                    "installed_path": str(dst.relative_to(ROOT)),
                    "sha256_of_skill_md": sha256(dst / "SKILL.md"),
                })
            ldir = DEST / "_licenses"
            ldir.mkdir(parents=True, exist_ok=True)
            for fname, outname in (("LICENSE", ".LICENSE"),
                                   ("THIRD_PARTY_NOTICES.md", ".NOTICES")):
                p = base / fname
                if p.is_file():
                    shutil.copy2(p, ldir / (repo.replace("/", "__") + outname))
    return lock


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="install curated GitHub agent skills")
    ap.add_argument("--cache", type=Path, default=CACHE)
    ap.add_argument("--download", action="store_true",
                    help="fetch tarballs; still refuses a lockfile hash mismatch")
    ap.add_argument("--verify-only", action="store_true",
                    help="strictly offline: verify vendored tarballs and installed skills")
    a = ap.parse_args(argv)

    if a.verify_only:
        if a.download:
            ap.error("--verify-only cannot be combined with --download")
        try:
            lines = verify_vendored(load_lock(LOCK), cache=a.cache)
        except InstallError as e:
            print(f"cordon: verification failed: {e}", file=sys.stderr)
            return 1
        print("\n".join(lines))
        return 0

    try:
        lock = install(a.cache, a.download)
    except InstallError as e:
        print(f"cordon: install failed: {e}", file=sys.stderr)
        return 1
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"installed {len(lock['skills'])} skill folders from {len(lock['sources'])} repos")
    print(f"lockfile: {LOCK}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
