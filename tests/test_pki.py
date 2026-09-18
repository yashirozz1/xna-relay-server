"""Integration tests for the offline fleet PKI, using real OpenSSL."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fleet.pki import init_pki, issue_client, revoke_client


PASSWORD = "correct horse battery staple"


def openssl(cwd: Path, *arguments: str, input_text: str | None = None):
    command = (["openssl"] if shutil.which("openssl") else ["wsl", "openssl"])
    return subprocess.run(
        [*command, *arguments], cwd=cwd, input=input_text,
        capture_output=True, text=True,
    )


def snapshot(path: Path):
    return {
        item.relative_to(path).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in path.rglob("*") if item.is_file()
    }


class PkiTests(unittest.TestCase):
    def make_pki(self, parent: Path, relay_ip: str | None = None) -> Path:
        path = parent / "pki"
        init_pki(path, PASSWORD, relay_ip=relay_ip)
        return path

    def test_init_creates_encrypted_ca_server_certificate_and_empty_crl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory), "203.0.113.10")

            self.assertTrue((path / "ca.key").read_bytes().startswith(
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
            self.assertTrue((path / "ca.crt").is_file())
            self.assertTrue((path / "server.pem").is_file())
            self.assertTrue((path / "crl.pem").is_file())
            self.assertTrue((path / "clients").is_dir())

            correct = openssl(path, "pkey", "-in", "ca.key", "-passin", "stdin",
                              "-noout", input_text=PASSWORD + "\n")
            wrong = openssl(path, "pkey", "-in", "ca.key", "-passin", "stdin",
                            "-noout", input_text="wrong password\n")
            self.assertEqual(correct.returncode, 0, correct.stderr)
            self.assertNotEqual(wrong.returncode, 0)

            verify = openssl(path, "verify", "-CAfile", "ca.crt",
                             "-purpose", "sslserver", "server.pem")
            self.assertEqual(verify.returncode, 0, verify.stderr)
            details = openssl(path, "x509", "-in", "server.pem", "-noout",
                              "-text")
            self.assertIn("DNS:relay.prl.internal", details.stdout)
            self.assertIn("IP Address:203.0.113.10", details.stdout)
            self.assertIn("TLS Web Server Authentication", details.stdout)
            wrong_purpose = openssl(path, "verify", "-CAfile", "ca.crt",
                                    "-purpose", "sslclient", "server.pem")
            self.assertNotEqual(wrong_purpose.returncode, 0)

    def test_issue_creates_unique_client_certificate_with_client_purpose(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            result = issue_client(path, "gpu01", PASSWORD)

            self.assertEqual(result, path / "clients" / "gpu01.pem")
            verify = openssl(path, "verify", "-CAfile", "ca.crt",
                             "-purpose", "sslclient", "clients/gpu01.pem")
            self.assertEqual(verify.returncode, 0, verify.stderr)
            details = openssl(path, "x509", "-in", "clients/gpu01.pem",
                              "-noout", "-subject", "-text")
            self.assertIn("CN = gpu01", details.stdout)
            self.assertIn("TLS Web Client Authentication", details.stdout)
            wrong_purpose = openssl(path, "verify", "-CAfile", "ca.crt",
                                    "-purpose", "sslserver", "clients/gpu01.pem")
            self.assertNotEqual(wrong_purpose.returncode, 0)

    def test_monitor_panel_is_a_valid_management_client_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            issue_client(path, "monitor-panel", PASSWORD)
            verify = openssl(path, "verify", "-CAfile", "ca.crt",
                             "-purpose", "sslclient", "clients/monitor-panel.pem")
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_invalid_ids_are_rejected_without_files(self):
        invalid = ("", "A", "GPU01", "1gpu", "gpu.01", "gpu/01", "a" * 33)
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            before = snapshot(path)
            for client_id in invalid:
                with self.subTest(client_id=client_id):
                    with self.assertRaises(ValueError):
                        issue_client(path, client_id, PASSWORD)
            self.assertEqual(snapshot(path), before)

    def test_existing_client_is_refused_and_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            issued = issue_client(path, "gpu01", PASSWORD)
            before = snapshot(path)
            with self.assertRaises(FileExistsError):
                issue_client(path, "gpu01", PASSWORD)
            self.assertEqual(snapshot(path), before)
            self.assertTrue(issued.exists())

    def test_revoke_updates_crl_and_keeps_other_client_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            issue_client(path, "gpu01", PASSWORD)
            issue_client(path, "gpu02", PASSWORD)

            result = revoke_client(path, "gpu01", PASSWORD)

            self.assertEqual(result, path / "crl.pem")
            revoked = openssl(path, "verify", "-CAfile", "ca.crt",
                              "-CRLfile", "crl.pem", "-crl_check",
                              "clients/gpu01.pem")
            valid = openssl(path, "verify", "-CAfile", "ca.crt",
                            "-CRLfile", "crl.pem", "-crl_check",
                            "clients/gpu02.pem")
            self.assertNotEqual(revoked.returncode, 0)
            self.assertIn("certificate revoked", revoked.stderr.lower())
            self.assertEqual(valid.returncode, 0, valid.stderr)
            with self.assertRaises(ValueError):
                revoke_client(path, "gpu01", PASSWORD)

    def test_wrong_password_does_not_change_state_or_create_client(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            before = snapshot(path)
            with self.assertRaises(RuntimeError):
                issue_client(path, "gpu01", "this password is wrong")
            self.assertEqual(snapshot(path), before)
            self.assertFalse((path / "clients" / "gpu01.pem").exists())

    def test_refresh_crl_preserves_revocations_and_requires_password(self):
        import fleet.pki as pki
        self.assertTrue(callable(getattr(pki, 'refresh_crl', None)), 'CRL renewal is missing')
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            issue_client(path, 'gpu01', PASSWORD)
            issue_client(path, 'gpu02', PASSWORD)
            revoke_client(path, 'gpu01', PASSWORD)
            before = snapshot(path)
            with self.assertRaises(RuntimeError):
                pki.refresh_crl(path, 'this password is wrong')
            self.assertEqual(snapshot(path), before)
            pki.refresh_crl(path, PASSWORD)
            self.assertNotEqual(snapshot(path)['crl.pem'], before['crl.pem'])
            revoked = openssl(path, 'verify', '-CAfile', 'ca.crt', '-CRLfile',
                              'crl.pem', '-crl_check', 'clients/gpu01.pem')
            valid = openssl(path, 'verify', '-CAfile', 'ca.crt', '-CRLfile',
                            'crl.pem', '-crl_check', 'clients/gpu02.pem')
            self.assertNotEqual(revoked.returncode, 0)
            self.assertIn('certificate revoked', revoked.stderr.lower())
            self.assertEqual(valid.returncode, 0, valid.stderr)

    def test_concurrent_renewal_cannot_overwrite_revocation(self):
        import fleet.pki as pki
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            issue_client(path, 'gpu01', PASSWORD)
            signing = threading.Event()
            resume = threading.Event()
            original = pki._run_openssl

            def pause_signing(stage, password, *arguments):
                # Keep the real OpenSSL side effects, pausing at the race window.
                if '-gencrl' in arguments:
                    signing.set()
                    if not resume.wait(timeout=15):
                        raise RuntimeError('test synchronization timeout')
                return original(stage, password, *arguments)

            with patch.object(pki, '_run_openssl', side_effect=pause_signing):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    renewal = pool.submit(pki.refresh_crl, path, PASSWORD)
                    try:
                        self.assertTrue(signing.wait(timeout=10))
                        for operation, args in ((issue_client, ('gpu02', PASSWORD)),
                                                (revoke_client, ('gpu01', PASSWORD)),
                                                (pki.refresh_crl, (PASSWORD,))):
                            with self.assertRaisesRegex(RuntimeError, 'operation'):
                                operation(path, *args)
                    finally:
                        resume.set()
                    renewal.result(timeout=15)
            # The lock is released and revocation remains effective afterwards.
            revoke_client(path, 'gpu01', PASSWORD)
            revoked = openssl(path, 'verify', '-CAfile', 'ca.crt', '-CRLfile',
                              'crl.pem', '-crl_check', 'clients/gpu01.pem')
            self.assertNotEqual(revoked.returncode, 0)
            self.assertIn('certificate revoked', revoked.stderr.lower())

    @unittest.skipUnless(os.name == 'posix', 'kernel-backed Linux PKI lock')
    def test_abrupt_process_exit_releases_authority_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_pki(Path(directory))
            code = ('import os,sys; from fleet.pki import _exclusive_authority_operation; '
                    'operation=_exclusive_authority_operation(lambda path: os._exit(17)); operation(sys.argv[1])')
            process = subprocess.run([sys.executable, '-c', code, str(path)], cwd=ROOT)
            self.assertEqual(process.returncode, 17)
            issue_client(path, 'after-crash', PASSWORD)
            self.assertTrue((path / 'clients/after-crash.pem').is_file())

    def test_init_refuses_weak_password_invalid_ip_and_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with self.assertRaises(ValueError):
                init_pki(parent / "weak", "short")
            with self.assertRaises(ValueError):
                init_pki(parent / "bad-ip", PASSWORD, relay_ip="not-an-ip")
            existing = parent / "existing"
            existing.mkdir()
            marker = existing / "important.txt"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                init_pki(existing, PASSWORD)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_cli_uses_environment_passphrase(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pki"
            environment = os.environ.copy()
            environment["PRL_CA_PASSPHRASE"] = PASSWORD
            init_result = subprocess.run(
                [sys.executable, "-m", "fleet.pki", "init", str(path),
                 "--relay-ip", "203.0.113.10"], cwd=ROOT, env=environment,
                capture_output=True, text=True,
            )
            issue_result = subprocess.run(
                [sys.executable, "-m", "fleet.pki", "issue", str(path), "gpu01"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(init_result.returncode, 0, init_result.stderr)
            self.assertEqual(issue_result.returncode, 0, issue_result.stderr)
            self.assertNotIn(PASSWORD, init_result.stdout + init_result.stderr)
            self.assertNotIn(PASSWORD, issue_result.stdout + issue_result.stderr)


if __name__ == "__main__":
    unittest.main()
