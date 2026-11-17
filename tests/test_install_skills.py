"""Regression tests for pinned, offline GitHub skill installation."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install_skills.py"

spec = importlib.util.spec_from_file_location("cordon_install_skills", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)


class _Response:
    def __enter__(self):
        return io.BytesIO(b"pinned-tarball-bytes")

    def __exit__(self, *args):
        return False


class InstallerTests(unittest.TestCase):
    def test_safe_member_rejects_traversal_and_links(self):
        good = tarfile.TarInfo("repo-main/skills/a/SKILL.md")
        good.size = 10
        self.assertTrue(mod.safe_member(good))

        bad = [
            tarfile.TarInfo("../escape"),
            tarfile.TarInfo("repo-main/../../escape"),
            tarfile.TarInfo("/absolute"),
            tarfile.TarInfo("repo-main\\..\\escape"),
            tarfile.TarInfo("~/secret"),
        ]
        for m in bad:
            m.size = 1
            self.assertFalse(mod.safe_member(m), m.name)

        link = tarfile.TarInfo("repo-main/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc/passwd"
        self.assertFalse(mod.safe_member(link))

        huge = tarfile.TarInfo("repo-main/huge")
        huge.size = 9 * 1024 * 1024
        self.assertFalse(mod.safe_member(huge))

        fifo = tarfile.TarInfo("repo-main/pipe")
        fifo.type = tarfile.FIFOTYPE
        self.assertFalse(mod.safe_member(fifo))

    def test_real_vendored_corpus_verifies_offline(self):
        lines = mod.verify_vendored(mod.load_lock())
        self.assertIn("OFFLINE_OK sources=5 tarballs=5 skills=30", lines[-1])

    def test_verify_only_never_calls_fetch_or_network(self):
        out = io.StringIO()
        with mock.patch.object(mod, "fetch", side_effect=AssertionError("fetch called")), \
             mock.patch.object(mod.urllib.request, "urlopen",
                               side_effect=AssertionError("urlopen called")), \
             mock.patch.object(mod.subprocess, "run",
                               side_effect=AssertionError("subprocess called")), \
             redirect_stdout(out):
            rc = mod.main(["--verify-only"])
        self.assertEqual(rc, 0)
        self.assertIn("OFFLINE_OK", out.getvalue())

    def test_verify_detects_tampered_skill_hash(self):
        lock = copy.deepcopy(mod.load_lock())
        lock["skills"][0]["sha256_of_skill_md"] = "0" * 64
        with self.assertRaisesRegex(mod.InstallError, "SKILL.md sha256 mismatch"):
            mod.verify_vendored(lock)

    def test_verify_detects_missing_skill_entry(self):
        lock = copy.deepcopy(mod.load_lock())
        lock["skills"] = lock["skills"][:-1]
        with self.assertRaisesRegex(mod.InstallError, "expected 30 skills"):
            mod.verify_vendored(lock)

    def test_verify_detects_missing_tarball(self):
        with tempfile.TemporaryDirectory(prefix="cordon-inst-") as td:
            with self.assertRaisesRegex(mod.InstallError, "vendored tarball missing"):
                mod.verify_vendored(mod.load_lock(), cache=Path(td))

    def test_install_refuses_hash_mismatch_before_extraction(self):
        with tempfile.TemporaryDirectory(prefix="cordon-inst-") as td:
            cache = Path(td)
            (cache / mod.tarball_name("anthropics/skills")).write_bytes(b"wrong")
            with mock.patch.object(mod, "fetch", side_effect=AssertionError("fetch called")), \
                 mock.patch.object(mod, "extract", side_effect=AssertionError("extract called")):
                with self.assertRaisesRegex(mod.InstallError, "sha256 mismatch"):
                    mod.install(cache, download=False)

    def test_fetch_creates_missing_cache_parent(self):
        with tempfile.TemporaryDirectory(prefix="cordon-inst-") as td:
            dest = Path(td) / "new" / "nested" / "repo.tgz"
            with mock.patch.object(mod.urllib.request, "urlopen",
                                   return_value=_Response()), \
                 mock.patch.object(mod.subprocess, "run",
                                   side_effect=AssertionError("curl fallback called")):
                mod.fetch("anthropics/skills", "main", dest)
            self.assertEqual(dest.read_bytes(), b"pinned-tarball-bytes")

    def test_lockfile_rejects_wrong_schema(self):
        with tempfile.TemporaryDirectory(prefix="cordon-inst-") as td:
            p = Path(td) / "lock.json"
            p.write_text(json.dumps({"schema": 2, "sources": {}, "skills": []}))
            with self.assertRaisesRegex(mod.InstallError, "skills-lock/v1"):
                mod.load_lock(p)


if __name__ == "__main__":
    unittest.main()
