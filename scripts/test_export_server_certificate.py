import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

script = Path(__file__).resolve().parents[1] / "deploy" / "pangolin" / "export-server-certificate.py"
spec = importlib.util.spec_from_file_location("export_server_certificate", script)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ServerCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        root = Path(cls.fixture.name)
        config = root / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n[dn]\nCN=*.tainton.uk\n[extensions]\nsubjectAltName=DNS:*.tainton.uk\nextendedKeyUsage=serverAuth\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3", "-config", str(config), "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")], check=True, capture_output=True)
        cls.cert, cls.key = (root / "cert.pem").read_bytes(), (root / "key.pem").read_bytes()
        cls.fingerprint = exporter.leaf_fingerprint(cls.cert)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.acme = self.root / "acme.json"
        self.write_acme(self.cert, self.key)
        self.args = argparse.Namespace(acme_file=str(self.acme), resolver="letsencrypt", hostname="cba.tainton.uk", output_dir=str(self.root / "tls"), owner=os.getuid(), group=os.getgid(), no_restart=True, container="wardstone-test", backend_host="127.0.0.1", backend_port=8443)

    def write_acme(self, cert, key):
        self.acme.write_text(json.dumps({"letsencrypt": {"Certificates": [{"domain": {"main": "*.tainton.uk"}, "certificate": base64.b64encode(cert).decode(), "key": base64.b64encode(key).decode()}]}}))

    def test_wildcard_is_one_label_only(self):
        self.assertTrue(exporter.matches("*.tainton.uk", "cba.tainton.uk"))
        self.assertFalse(exporter.matches("*.tainton.uk", "tainton.uk"))
        self.assertFalse(exporter.matches("*.tainton.uk", "other.cba.tainton.uk"))

    def test_export_and_repeat_preserve_private_permissions(self):
        self.assertEqual(exporter.export(self.args), (True, False))
        root = Path(self.args.output_dir)
        self.assertEqual((root / "server.crt").read_bytes(), self.cert)
        self.assertEqual((root / "server.key").read_bytes(), self.key)
        self.assertEqual(root.stat().st_mode & 0o777, 0o750)
        self.assertEqual((root / "server.key").stat().st_mode & 0o777, 0o640)
        timestamp = (root / "server.key").stat().st_mtime_ns
        self.assertEqual(exporter.export(self.args), (False, False))
        self.assertEqual(timestamp, (root / "server.key").stat().st_mtime_ns)

    def test_invalid_pair_does_not_replace_working_certificate(self):
        exporter.export(self.args)
        self.write_acme(self.cert, b"invalid private key")
        with self.assertRaises((ValueError, OSError)):
            exporter.export(self.args)
        self.assertEqual((Path(self.args.output_dir) / "server.key").read_bytes(), self.key)

    def test_actual_certificate_hostname_is_checked(self):
        with self.assertRaisesRegex(ValueError, "hostname"):
            exporter.validate(Path(self.fixture.name) / "cert.pem", Path(self.fixture.name) / "key.pem", "other.example")

    def test_expiring_material_does_not_replace_working_files(self):
        exporter.export(self.args)
        with patch.object(exporter, "validate", side_effect=ValueError("expires within 24 hours")), self.assertRaisesRegex(ValueError, "expires"):
            exporter.export(self.args)
        self.assertEqual((Path(self.args.output_dir) / "server.crt").read_bytes(), self.cert)

    def test_symlink_output_is_rejected(self):
        root = Path(self.args.output_dir)
        root.mkdir()
        target = self.root / "keep.key"
        target.write_bytes(b"preserve")
        (root / "server.key").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            exporter.export(self.args)
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_stopped_container_is_never_started(self):
        self.args.no_restart = False
        with patch.object(exporter, "running", return_value=False), patch.object(exporter, "restart") as restart:
            self.assertEqual(exporter.export(self.args), (True, False))
            restart.assert_not_called()

    def test_loaded_certificate_does_not_restart_container(self):
        self.args.no_restart = False
        with patch.object(exporter, "running", return_value=True), patch.object(exporter, "live_fingerprint", return_value=self.fingerprint), patch.object(exporter, "restart") as restart:
            exporter.export(self.args)
            self.assertEqual(exporter.export(self.args), (False, False))
            restart.assert_not_called()

    def test_old_loaded_certificate_retries_after_failed_restart(self):
        self.args.no_restart = False
        with patch.object(exporter, "running", return_value=True), patch.object(exporter, "live_fingerprint", return_value="old"), patch.object(exporter, "restart", side_effect=RuntimeError("restart failed")), self.assertRaisesRegex(RuntimeError, "restart failed"):
            exporter.export(self.args)
        with patch.object(exporter, "running", return_value=True), patch.object(exporter, "live_fingerprint", side_effect=["old", self.fingerprint]), patch.object(exporter, "restart") as restart:
            self.assertEqual(exporter.export(self.args), (False, True))
            restart.assert_called_once_with("wardstone-test")

    def test_probe_failure_does_not_restart_unchanged_service(self):
        exporter.export(self.args)
        self.args.no_restart = False
        with patch.object(exporter, "running", return_value=True), patch.object(exporter, "live_fingerprint", side_effect=OSError("unreachable")), patch.object(exporter, "restart") as restart, self.assertRaisesRegex(RuntimeError, "no restart"):
            exporter.export(self.args)
        restart.assert_not_called()


if __name__ == "__main__":
    unittest.main()
