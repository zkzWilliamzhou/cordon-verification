"""Policy decisions for agent tool calls.

One manifest drives every seam: the Claude Code PreToolUse hook, the generic
JSON hook, and the advisory PATH shim. Unknown tools and unparseable commands
fail closed. This is a policy gate, not an OS sandbox.
"""
from __future__ import annotations

import re
import shlex
import urllib.parse
from pathlib import Path
from typing import Any

from .model import Decision
from .policy import exec_allowed, hook_deny_reason
from .util import canonical_hex, is_safe_rel, read_json_file

BASH_TOOLS = {"Bash", "Shell", "bash", "shell", "execute_command",
              "run_command", "terminal", "exec_command"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file",
               "apply_patch", "create_file", "replace_in_file"}
READ_TOOLS = {"Read", "read_file", "Glob", "Grep", "view_file", "list_dir"}
FETCH_TOOLS = {"WebFetch", "web_fetch", "Fetch", "fetch_url", "http_request"}

OPERATORS = {";", "&&", "||", "|", "&", ">", ">>", "<", "<<", "`", "$(",
             "\n", "(", ")"}
ENV_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
URL_RE = re.compile(r"https?://[^\s)'\"<>]{1,200}")


def _deny(reason: str, capability: str, **detail: Any) -> Decision:
    return Decision(False, reason, capability, detail)


def _allow(reason: str, capability: str, **detail: Any) -> Decision:
    return Decision(True, reason, capability, detail)


def _host(value: str) -> str:
    try:
        return urllib.parse.urlsplit(value).hostname or ""
    except ValueError:
        return ""


def _bash(manifest: dict[str, Any], command: str) -> Decision:
    caps = manifest["capabilities"]
    if not command or not isinstance(command, str):
        return _deny("missing command", "exec")
    if len(command) > 8000:
        return _deny("command too long", "exec")
    for ch in ("\x00", "\r"):
        if ch in command:
            return _deny("control character in command", "exec")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return _deny("unparseable command", "exec", command=command[:120])
    if not tokens:
        return _deny("empty command", "exec")
    for t in tokens:
        if t in OPERATORS:
            return _deny("shell chaining or redirection is outside v0.1 policy",
                         "exec", token=t)
    exe = Path(tokens[0]).name.lower()
    if not exec_allowed(manifest, exe):
        return _deny(hook_deny_reason(exe), "exec", exe=exe)
    for var in ENV_REF.findall(command):
        if var not in caps["env"]["allow"]:
            return _deny(f"environment variable '{var}' is not allowed", "env", var=var)
    for m in URL_RE.finditer(command):
        h = _host(m.group(0))
        if h and h not in caps["net"]["allow_hosts"]:
            return _deny(f"network host '{h}' is not allowed", "net", host=h)
    for t in tokens[1:]:
        if t.startswith("~") or ".." in t.split("/"):
            return _deny(f"path '{t}' escapes the workspace", "fs.read", token=t)
        if t.startswith("/") and not t.startswith("/dev/null"):
            return _deny(f"absolute path '{t}' is outside v0.1 policy",
                         "fs.read", token=t)
        if t.startswith("$") or t.startswith("`"):
            return _deny("dynamic expansion is outside v0.1 policy", "exec", token=t)
    return _allow(f"executable '{exe}' allowed by manifest", "exec",
                  exe=exe, args=len(tokens) - 1,
                  policy_hash=manifest.get("policy_hash"))


def _write(manifest: dict[str, Any], path: str) -> Decision:
    if not path or not isinstance(path, str):
        return _deny("missing file path", "fs.write")
    if path.startswith("/") or path.startswith("~") or not is_safe_rel(path):
        return _deny(f"path '{path}' is outside the skill directory", "fs.write")
    if path not in manifest["capabilities"]["fs"]["write"]:
        return _deny(f"write to '{path}' is not in the allowlist", "fs.write")
    return _allow(f"write to '{path}' allowed", "fs.write")


def _read(manifest: dict[str, Any], path: str) -> Decision:
    if not path or not isinstance(path, str):
        return _deny("missing file path", "fs.read")
    if path.startswith("~") or ".." in path.split("/"):
        return _deny(f"path '{path}' escapes the workspace", "fs.read")
    rel = path.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    if rel.startswith("/"):
        root = str(manifest.get("skill_root", "")).replace("\\", "/")
        if root and rel.startswith(root.rstrip("/") + "/"):
            rel = rel[len(root.rstrip("/")) + 1:]
        else:
            return _deny(f"absolute path '{path}' is outside the skill directory",
                         "fs.read")
    if rel not in manifest["capabilities"]["fs"]["read"]:
        return _deny(f"read of '{rel}' is not in the allowlist", "fs.read")
    return _allow(f"read of '{rel}' allowed", "fs.read")


def _fetch(manifest: dict[str, Any], url: str) -> Decision:
    h = _host(url)
    if not h:
        return _deny("missing or invalid URL", "net")
    if h not in manifest["capabilities"]["net"]["allow_hosts"]:
        return _deny(f"network host '{h}' is not allowed", "net", host=h)
    return _allow(f"network host '{h}' allowed", "net", host=h)


def decide(manifest: dict[str, Any], call: dict[str, Any]) -> Decision:
    """Decide one tool call. `call` is untrusted JSON from an agent harness."""
    if not isinstance(call, dict):
        return _deny("tool call is not an object", "unknown")
    tool = call.get("tool_name") or call.get("tool") or call.get("name") or ""
    inp = call.get("tool_input") or call.get("input") or call.get("arguments") or {}
    if not isinstance(inp, dict):
        inp = {}
    if tool in BASH_TOOLS:
        return _bash(manifest, str(inp.get("command") or inp.get("cmd") or ""))
    if tool in WRITE_TOOLS:
        return _write(manifest, str(inp.get("file_path") or inp.get("path") or ""))
    if tool in READ_TOOLS:
        return _read(manifest, str(inp.get("file_path") or inp.get("path") or ""))
    if tool in FETCH_TOOLS:
        return _fetch(manifest, str(inp.get("url") or inp.get("href") or ""))
    return _deny(f"unknown tool '{tool}' fails closed", "unknown", tool=tool)


def hook_output(d: Decision, agent: str = "claude-code") -> dict[str, Any]:
    word = "allow" if d.allow else "deny"
    if agent == "claude-code":
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": word,
            "permissionDecisionReason": d.reason,
            "additionalContext": f"cordon capability={d.capability}"}}
    return {"decision": word, "reason": d.reason,
            "capability": d.capability, "detail": d.detail}


def load_call(raw: str) -> dict[str, Any]:
    from .util import json_loads
    try:
        obj = json_loads(raw)
    except ValueError as e:
        raise ValueError(f"invalid tool-call JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError("tool-call JSON must be an object")
    return obj


def manifest_from(path: Path) -> dict[str, Any]:
    from .manifest import load
    return load(path)
