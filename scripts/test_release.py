import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_semver(self):
        self.assertEqual(release.version("v1.2.3"), ((1, 2, 3), False))
        self.assertEqual(release.version("v1.2.3-rc.1"), ((1, 2, 3), True))
        for tag in ("main", "v01.2.3", "v1.2.3-01", "v1.2.3+build", "v1.2.3\n", "v1.2.3;echo bad"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.version(tag)

    def test_reproducible_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for ext in (".tar.gz", ".zip"):
                first, second = root / ("first" + ext), root / ("second" + ext)
                files = [("wardstone", b"binary", 0o755), ("README.md", b"docs", 0o644)]
                release.archive(first, files, 1792800000)
                release.archive(second, files, 1792800000)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                if ext == ".zip":
                    with zipfile.ZipFile(first) as archive:
                        self.assertEqual(archive.read("wardstone"), b"binary")
                else:
                    self.assertIn(b"binary", gzip.decompress(first.read_bytes()))

    def test_manual_dry_run_does_not_contact_gitea(self):
        with tempfile.TemporaryDirectory() as temp:
            event, output = Path(temp) / "event.json", Path(temp) / "output"
            event.write_text('{"inputs":{"publish":"false"}}')
            env = {"GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_OUTPUT": str(output), "GITHUB_RUN_NUMBER": "7"}
            with patch.dict(os.environ, env, clear=True), patch.object(release, "command", side_effect=["a" * 40, "1792800000"]), patch.object(release.API, "request", side_effect=AssertionError("network request in dry run")), contextlib.redirect_stdout(io.StringIO()):
                release.plan(None)
            text = output.read_text()
            self.assertIn("tag=v0.0.0-ci.7\n", text)
            self.assertIn("publish=false\n", text)

    def test_publication_requires_matching_tag_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / "event.json"
            event.write_text('{"inputs":{"publish":"true","tag":"v1.2.3"}}')
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "workflow_dispatch"}, clear=True), patch.object(release, "command", side_effect=["a" * 40, "b" * 40]), self.assertRaisesRegex(ValueError, "does not match"):
                release.plan(None)

    def test_assets_are_not_overwritten(self):
        api = release.API("https://git.example", "repos/wardstone", "test-placeholder")
        with patch.object(api, "download", return_value=b"original"), patch.object(api, "request") as request:
            api.upload(1, "SHA256SUMS", b"original", {"SHA256SUMS": {}})
            request.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
                api.upload(1, "SHA256SUMS", b"modified", {"SHA256SUMS": {}})

    def test_completed_marker_cannot_mask_moved_tag(self):
        api = release.API("https://git.example", "repos/wardstone", "test-placeholder")
        marker = {"complete": True, "commit": "a" * 40}
        with patch.object(api, "assets", return_value=[{"name": release.MANIFEST}]), patch.object(api, "download", return_value=json.dumps(marker).encode()):
            self.assertTrue(api.completed({"id": 1}, "a" * 40))
            with self.assertRaisesRegex(RuntimeError, "another commit"):
                api.completed({"id": 1}, "b" * 40)


if __name__ == "__main__":
    unittest.main()
