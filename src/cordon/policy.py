"""The exec decision, shared by every adapter.

One rule. The hook adapter and the shim adapter both call it, which turns a
duplicated check into a real seam. A disagreement between adapters would now
have to live in this module.
"""
from __future__ import annotations

from typing import Any, Iterable

SHIM_DENY_REASON = "executable not allowed"


def exec_allowed(manifest: dict[str, Any], name: str,
                 extra_deny: Iterable[str] = ()) -> bool:
    """True only when the manifest allowlist permits this basename."""
    if name in set(extra_deny):
        return False
    caps = manifest.get("capabilities", {})
    allow = caps.get("exec", {}).get("allow", [])
    return name in allow


def hook_deny_reason(name: str) -> str:
    return f"executable '{name}' is not in the allowlist"
