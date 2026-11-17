"""Portable, hash-chained, replayable audit ledger.

Each line is canonical JSON. entry_hash binds the record; prev_hash binds the
previous entry. This is tamper-evident under control of the local writer. It
does not detect deletion of the whole file, truncation of the tail, clock
rollback, or a compromised verification key.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .util import (VERSION, ZERO_HASH, CordonError, canonical_hex,
                   canonical_json, json_loads, now)

SCHEMA = "cordon.ledger/v1"


def _entry_hash(entry: dict[str, Any]) -> str:
    return canonical_hex({k: v for k, v in entry.items() if k != "entry_hash"})


def _lock(f):
    try:
        import fcntl
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return fcntl
    except (ImportError, OSError):
        return None


def _unlock(f, mod) -> None:
    if mod is not None:
        mod.flock(f.fileno(), mod.LOCK_UN)


def append(path: Path, kind: str, decision: str, detail: dict[str, Any] | None = None,
           ts: int | None = None) -> dict[str, Any]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    detail = detail or {}
    with path.open("a+b") as f:
        mod = _lock(f)
        try:
            f.seek(0)
            data = f.read()
            lines = [ln for ln in data.splitlines() if ln.strip()]
            index, prev = 0, ZERO_HASH
            if lines:
                try:
                    last = json_loads(lines[-1])
                except ValueError as e:
                    raise CordonError(f"ledger tail is invalid JSON: {e}", 3) from e
                if not isinstance(last, dict) or last.get("schema") != SCHEMA:
                    raise CordonError("ledger tail has an unknown schema", 3)
                if (not isinstance(last.get("index"), int)
                        or not isinstance(last.get("entry_hash"), str)
                        or len(str(last["entry_hash"])) != 64):
                    raise CordonError("ledger tail is missing index or entry_hash", 3)
                index = int(last["index"])
                prev = str(last["entry_hash"])
            entry: dict[str, Any] = {
                "schema": SCHEMA, "tool_version": VERSION,
                "index": index + 1, "prev_hash": prev,
                "ts": now() if ts is None else int(ts),
                "kind": kind, "decision": decision,
                "actor": "cordon", "detail": detail,
            }
            entry["entry_hash"] = _entry_hash(entry)
            f.seek(0, os.SEEK_END)
            f.write(canonical_json(entry) + b"\n")
            f.flush()
            os.fsync(f.fileno())
            return entry
        finally:
            _unlock(f, mod)


def read(path: Path) -> list[dict[str, Any]]:
    raw = Path(path).read_bytes()
    out = []
    for i, ln in enumerate(raw.splitlines(), 1):
        if not ln.strip():
            continue
        try:
            out.append(json_loads(ln))
        except ValueError as e:
            raise CordonError(f"{path}:{i}: invalid ledger line: {e}", 3) from e
    return out


def verify(path: Path) -> dict[str, Any]:
    entries = read(path)
    prev = ZERO_HASH
    for i, e in enumerate(entries, 1):
        if e.get("schema") != SCHEMA:
            raise CordonError(f"entry {i}: unknown schema", 3)
        if e.get("index") != i:
            raise CordonError(f"entry {i}: index out of order", 3)
        if e.get("prev_hash") != prev:
            raise CordonError(f"entry {i}: broken prev_hash link", 3)
        if e.get("entry_hash") != _entry_hash(e):
            raise CordonError(f"entry {i}: entry_hash mismatch", 3)
        prev = str(e["entry_hash"])
    return {"ok": True, "entries": len(entries), "root_hash": prev,
            "first_ts": entries[0]["ts"] if entries else None,
            "last_ts": entries[-1]["ts"] if entries else None,
            "disclaimer": "Tamper-evident under control of the local writer. "
                          "Deletion, truncation and clock rollback are not detected."}


def _identity(e: dict[str, Any]) -> str:
    return canonical_hex({"kind": e.get("kind"), "decision": e.get("decision"),
                          "detail": e.get("detail")})


def diff(a: Path, b: Path) -> dict[str, Any]:
    ea, eb = read(a), read(b)
    ia, ib = [_identity(e) for e in ea], [_identity(e) for e in eb]
    sa, sb = set(ia), set(ib)
    return {"schema": "cordon.ledger-diff/v1",
            "a": str(a), "b": str(b),
            "a_entries": len(ea), "b_entries": len(eb),
            "only_in_a": sorted(sa - sb), "only_in_b": sorted(sb - sa),
            "identical_events": ia == ib}


def replay(path: Path) -> list[str]:
    out = []
    for e in read(path):
        out.append(f"#{e['index']:04d} [{e['decision'].upper():5}] {e['kind']:10} "
                   f"ts={e['ts']} {json.dumps(e['detail'], sort_keys=True, ensure_ascii=True)}")
    return out
