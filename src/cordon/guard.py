"""Advisory PATH shim and guarded process launch.

Honest label: a pure-Python shim is bypassable. An agent can call an absolute
interpreter path, set LD_PRELOAD, use ctypes, or spawn a child directly. The
shim makes policy decisions visible and auditable; an OS backend is required
for enforcement. See docs/design and docs/adapters.
"""
from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import ledger, pin
from .manifest import load as load_manifest
from .policy import SHIM_DENY_REASON, exec_allowed
from .util import CordonError, canonical_json

BLOCK_SHIMS = {"sh", "bash", "zsh", "curl", "wget", "nc", "ncat", "sudo",
               "chmod", "chown", "rm", "mv", "cp", "tee", "eval", "xargs"}


def advisory_notice() -> str:
    return ("cordon: advisory PATH shim. A child can bypass it with an absolute "
            "interpreter, LD_PRELOAD or a direct syscall. Use an OS backend for "
            "enforcement. See docs/adapters.md.")


def _real_basenames(real_path: str, limit: int = 1200) -> set[str]:
    """Basenames of executable files on the original PATH.

    Covering the real PATH closes the gap where an undeclared command resolves
    straight to its real binary and never reaches a policy decision.
    """
    names: set[str] = set()
    for d in real_path.split(os.pathsep):
        if not d:
            continue
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.name.startswith(".") or "/" in e.name:
                        continue
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111:
                        names.add(e.name)
                    if len(names) >= limit:
                        return names
        except OSError:
            continue
    return names


def _make_shims(directory: Path, allowed: list[str], real_path: str) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    names = sorted(set(allowed) | BLOCK_SHIMS | _real_basenames(real_path))
    for name in names:
        p = directory / name
        script = (
            "#!/bin/sh\n"
            f"exec \"$CORDON_PYTHON\" \"$CORDON_LAUNCHER\" shim "
            f"--name {shlex.quote(name)} -- \"$@\"\n"
        )
        fd, tmp = tempfile.mkstemp(prefix=".shim-", dir=str(directory))
        os.fchmod(fd, 0o700)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script)
        os.replace(tmp, p)
        os.chmod(p, 0o700)
    return len(names)


def _sanitized_env(manifest_path: Path, ledger_path: Path | None,
                   pin_path: Path | None, root: Path, shim_dir: Path,
                   launcher: Path) -> dict[str, str]:
    drop = {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH", "NODE_OPTIONS", "PYTHONSTARTUP",
            "BASH_ENV", "ENV", "CDPATH", "IFS"}
    env = {k: v for k, v in os.environ.items()
           if k not in drop and not k.startswith("CORDON_")}
    env["PATH"] = str(shim_dir) + os.pathsep + os.environ.get("PATH", "")
    env["CORDON_REAL_PATH"] = os.environ.get("PATH", "")
    env["CORDON_PYTHON"] = sys.executable
    env["CORDON_LAUNCHER"] = str(launcher)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    env["CORDON_ACTIVE"] = "1"
    env["CORDON_SHIM_DIR"] = str(shim_dir)
    env["CORDON_MANIFEST"] = str(manifest_path)
    env["CORDON_SKILL_ROOT"] = str(root)
    if ledger_path:
        env["CORDON_LEDGER"] = str(ledger_path)
    if pin_path:
        env["CORDON_PIN"] = str(pin_path)
    return env


def run_guard(manifest_path: Path, command: list[str], root: Path | None = None,
              pin_path: Path | None = None, ledger_path: Path | None = None,
              dry_run: bool = False) -> int:
    manifest = load_manifest(manifest_path)
    root = Path(root or manifest.get("skill_root") or ".")
    if not root.exists():
        raise CordonError(f"{root}: skill root missing", 1)
    if pin_path is not None:
        pin.verify(pin.load(pin_path), root=root)  # closes the scan-to-run gap
    allowed = manifest["capabilities"]["exec"]["allow"]
    launcher = Path(__file__).resolve().parent.parent.parent / "cordon_launcher.py"
    if not launcher.exists():
        # Installed package: use -m cordon via a tiny launcher in the shim dir.
        launcher = Path(tempfile.mkdtemp(prefix="cordon-launch-")) / "cordon_launcher.py"
        launcher.write_text(
            "import sys\nfrom cordon.cli import main\nraise SystemExit(main(sys.argv[1:]))\n",
            encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="cordon-shims-") as td:
        shim_dir = Path(td) / "bin"
        shim_count = _make_shims(shim_dir, allowed, os.environ.get("PATH", ""))
        env = _sanitized_env(manifest_path, ledger_path, pin_path, root,
                             shim_dir, launcher)
        if ledger_path:
            ledger.append(ledger_path, "guard", "info",
                          {"mode": "advisory", "command": command[:3],
                           "allowed_exec": sorted(allowed)})
        if dry_run:
            print(canonical_json({"mode": "advisory", "command": command,
                                  "shim_dir": "<ephemeral>",
                                  "shim_count": shim_count,
                                  "allowed_exec": sorted(allowed),
                                  "notice": advisory_notice()}).decode())
            return 0
        sys.stderr.write(advisory_notice() + "\n")
        try:
            cp = subprocess.run(command, env=env, check=False)
            return cp.returncode
        except FileNotFoundError as e:
            if ledger_path:
                ledger.append(ledger_path, "guard", "error", {"error": str(e)})
            raise CordonError(f"command not found: {command[0]}", 1) from e


def run_shim(name: str, args: list[str]) -> int:
    """Entry point for a generated shim. Never call this with untrusted `name`."""
    manifest_path = Path(os.environ.get("CORDON_MANIFEST", ""))
    ledger_path = os.environ.get("CORDON_LEDGER")
    pin_path = os.environ.get("CORDON_PIN")
    root = os.environ.get("CORDON_SKILL_ROOT")
    real_path = os.environ.get("CORDON_REAL_PATH", "")
    lp = Path(ledger_path) if ledger_path else None

    def log(decision: str, detail: dict[str, Any]) -> None:
        if lp:
            ledger.append(lp, "shim", decision, detail)

    if not manifest_path.exists():
        log("deny", {"name": name, "reason": "manifest missing"})
        sys.stderr.write("cordon: manifest missing, denied\n")
        return 126
    try:
        manifest = load_manifest(manifest_path)
    except (ValueError, OSError) as e:
        log("deny", {"name": name, "reason": str(e)})
        sys.stderr.write(f"cordon: manifest invalid, denied: {e}\n")
        return 126
    if pin_path and root:
        try:
            pin.verify(pin.load(Path(pin_path)), root=Path(root))
        except CordonError as e:
            log("deny", {"name": name, "reason": str(e)})
            sys.stderr.write(f"cordon: pin re-verify failed, denied: {e}\n")
            return 126
    if not exec_allowed(manifest, name, extra_deny=BLOCK_SHIMS):
        log("deny", {"name": name, "args": args[:5],
                     "reason": SHIM_DENY_REASON})
        sys.stderr.write(f"cordon: '{name}' denied by capability manifest\n")
        return 126
    real = shutil.which(name, path=real_path)
    if not real:
        log("deny", {"name": name, "reason": "real executable not found"})
        return 126
    if os.environ.get("CORDON_SHIM_DIR") and real.startswith(os.environ["CORDON_SHIM_DIR"]):
        log("deny", {"name": name, "reason": "shim recursion"})
        return 126
    try:
        st = os.stat(real)
        if st.st_mode & stat.S_IWOTH:
            log("deny", {"name": name, "reason": "world-writable executable"})
            return 126
    except OSError:
        return 126
    log("allow", {"name": name, "args": args[:8], "real": real})
    os.execv(real, [real, *args])
    return 0
