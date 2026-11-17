"""Content pinning and optional Ed25519 signing.

A pin hashes raw bytes for every enumerated file. Signing is detached over the
canonical pin without its signature field. A hash is not authentication: the
public key must be trusted out of band.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from .fs import enumerate_skill
from .util import (VERSION, CordonError, canonical_hex, canonical_json,
                   now, read_json_file, write_json_file)

SCHEMA = "cordon.pin/v1"


def _tree_hash(rows: list[dict[str, Any]]) -> str:
    import hashlib
    h = hashlib.sha256()
    for row in rows:
        h.update((row["path"] + "\x00" + str(row["mode"]) + "\x00" +
                  row["sha256"] + "\n").encode("utf-8"))
    return h.hexdigest()


def build_pin(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    files = enumerate_skill(root, errors)
    rows = [{"path": f.rel, "sha256": f.sha256, "size": f.size,
             "mode": f.mode} for f in files]
    return {
        "schema": SCHEMA,
        "tool_version": VERSION,
        "created_utc": now(),
        "skill_root": str(root),
        "file_count": len(rows),
        "total_bytes": sum(r["size"] for r in rows),
        "tree_hash": _tree_hash(rows),
        "files": rows,
        "errors": errors,
        "disclaimer": "Integrity pin, not a safety verdict. Re-verify immediately before use.",
    }


def unsigned(pin: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in pin.items() if k != "signature"}


def key_id(public_bytes: bytes) -> str:
    import hashlib
    return hashlib.sha256(public_bytes).hexdigest()[:16]


def _private_key_from_env():
    from cryptography.hazmat.primitives import serialization
    pw = os.environ.get("CORDON_KEY_PASSPHRASE")
    if not pw:
        raise CordonError("CORDON_KEY_PASSPHRASE is required to use a signing key", 1)
    return pw.encode("utf-8"), serialization


def keygen(directory: Path) -> dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    pw = os.environ.get("CORDON_KEY_PASSPHRASE")
    if not pw:
        raise CordonError("set CORDON_KEY_PASSPHRASE before keygen", 1)
    key = Ed25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(pw.encode("utf-8"))
    private = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8, enc)
    public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    kp = directory / "cordon.key"
    pp = directory / "cordon.pub"
    # 0600 for the encrypted private key; never write it into a skill tree.
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".cordon-key-", dir=str(directory))
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private)
    os.replace(tmp, kp)
    pp.write_text(base64.b64encode(public).decode("ascii") + "\n", encoding="ascii")
    os.chmod(pp, 0o644)
    return {"private": str(kp), "public": str(pp), "key_id": key_id(public)}


def sign(pin: dict[str, Any], key_path: Path, pub_path: Path) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pw, _ = _private_key_from_env()
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=pw)
    if not isinstance(key, Ed25519PrivateKey):
        raise CordonError("signing key is not Ed25519", 1)
    public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    trusted = base64.b64decode(Path(pub_path).read_text().strip())
    if trusted != public:
        raise CordonError("public key does not match the signing key", 3)
    sig = key.sign(canonical_json(unsigned(pin)))
    out = dict(pin)
    out["signature"] = {
        "alg": "Ed25519", "key_id": key_id(public),
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "value_b64": base64.b64encode(sig).decode("ascii"),
    }
    return out


def verify(pin: dict[str, Any], root: Path | None = None,
           pub_path: Path | None = None, require_signature: bool = False) -> str:
    if not isinstance(pin, dict) or pin.get("schema") != SCHEMA:
        raise CordonError("not a cordon.pin/v1 record", 3)
    if root is not None:
        current = build_pin(root)
        if current["tree_hash"] != pin.get("tree_hash"):
            raise CordonError("pin mismatch: skill content changed", 3)
        if current["files"] != pin.get("files"):
            raise CordonError("pin mismatch: file list changed", 3)
    rows = pin.get("files")
    if not isinstance(rows, list):
        raise CordonError("pin files must be a list", 3)
    for row in rows:
        if (not isinstance(row, dict)
                or not all(k in row for k in ("path", "sha256", "size", "mode"))):
            raise CordonError("pin has a malformed file row", 3)
    if _tree_hash(rows) != pin.get("tree_hash"):
        raise CordonError("pin tree_hash does not match its file rows", 3)
    sig = pin.get("signature")
    if not sig:
        if require_signature:
            raise CordonError("pin is unsigned but a signature was required", 3)
        return canonical_hex(unsigned(pin))
    if sig.get("alg") != "Ed25519":
        raise CordonError("unsupported signature algorithm", 3)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import binascii
    try:
        public = base64.b64decode(sig["public_key_b64"], validate=True)
        value = base64.b64decode(sig["value_b64"], validate=True)
    except (KeyError, binascii.Error, ValueError) as e:
        raise CordonError(f"malformed signature: {e}", 3) from e
    if pub_path is not None:
        trusted = base64.b64decode(Path(pub_path).read_text().strip(), validate=True)
        if trusted != public:
            raise CordonError("signature key is not the trusted key", 3)
    if key_id(public) != sig.get("key_id"):
        raise CordonError("signature key_id mismatch", 3)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            value, canonical_json(unsigned(pin)))
    except Exception as e:
        raise CordonError("signature verification failed", 3) from e
    return canonical_hex(unsigned(pin))


def load(path: Path) -> dict[str, Any]:
    return read_json_file(path)


def save(path: Path, pin: dict[str, Any]) -> None:
    write_json_file(path, pin)
