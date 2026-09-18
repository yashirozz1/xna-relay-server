"""Installer UX boundary tests; never install system packages or services."""
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class MenuTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.menu = importlib.import_module('fleet.menu')
        except ModuleNotFoundError:
            cls.menu = None

    def require_menu(self):
        self.assertIsNotNone(self.menu, 'Installer menu is not implemented')
        return self.menu

    def test_redirected_input_never_installs_or_emits_ansi(self):
        self.require_menu()
        result = subprocess.run([sys.executable, str(ROOT / 'fleet/menu.py')],
                                input='', capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('XNA', result.stdout)
        self.assertIn('--help', result.stdout)
        self.assertNotIn('\x1b', result.stdout)

    def test_quit_menu_has_no_side_effects(self):
        menu = self.require_menu()
        stream = io.StringIO()
        terminal = menu.Terminal(stream=stream, interactive=True, animation=False, color=False)
        with patch('builtins.input', return_value='0'):
            self.assertEqual(menu.run_menu(terminal, ROOT), 0)
        self.assertIn('Preparar', stream.getvalue())
        self.assertNotIn('\x1b', stream.getvalue())

    def test_prepare_builds_real_complete_packages_with_individual_keys(self):
        menu = self.require_menu()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            result = menu.prepare_fleet('203.0.113.10', 2, path / 'pki',
                                        path / 'bundle', 'temporary test passphrase')
            self.assertEqual(result, path / 'bundle')
            manifest = json.loads((result / 'manifest.json').read_text())
            self.assertEqual([i['id'] for i in manifest['instances']], ['gpu0001', 'gpu0002'])
            self.assertTrue((path / 'pki/ca.key').is_file())
            self.assertFalse(list(result.rglob('ca.key')))
            self.assertNotEqual((result / 'clients/gpu0001/client.pem').read_bytes(),
                                (result / 'clients/gpu0002/client.pem').read_bytes())
            completed = subprocess.run([sys.executable, str(result / 'relay/menu.py'), '--role', 'relay'],
                                       input='', capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('Relay', completed.stdout)
            self.assertNotIn((result / 'relay/api-token').read_text().strip(), completed.stdout)

    def test_prepare_rejects_invalid_inputs_before_creating_pki(self):
        menu = self.require_menu()
        for ip, count, password in [('0.0.0.0', 2, 'long test password'),
                                    ('203.0.113.10', 1025, 'long test password'),
                                    ('203.0.113.10', 2, 'short')]:
            with self.subTest(ip=ip, count=count), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)
                with self.assertRaises(ValueError):
                    menu.prepare_fleet(ip, count, path / 'pki', path / 'bundle', password)
                self.assertFalse((path / 'pki').exists())
                self.assertFalse((path / 'bundle').exists())

    def test_prepare_preserves_existing_output(self):
        menu = self.require_menu()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            output = path / 'bundle'
            output.mkdir()
            (output / 'important').write_text('keep')
            with self.assertRaises(ValueError):
                menu.prepare_fleet('203.0.113.10', 1, path / 'pki', output, 'long test password')
            self.assertFalse((path / 'pki').exists())
            self.assertEqual((output / 'important').read_text(), 'keep')

    def test_prepare_never_copies_authority_into_output(self):
        menu = self.require_menu()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with self.assertRaises(ValueError):
                menu.prepare_fleet('203.0.113.10', 1, path / 'bundle/pki', path / 'bundle', 'long test password')
            self.assertFalse((path / 'bundle').exists())

    def test_cancel_install_does_not_launch_subprocess(self):
        menu = self.require_menu()
        terminal = menu.Terminal(stream=io.StringIO(), interactive=True, animation=False, color=False)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for name in ('install-common.sh', 'haproxy.cfg', 'server.pem', 'ca.crt', 'crl.pem',
                         'registry.json', 'api-token', 'prl-fleet.service', 'prl-monitor.service'):
                (path / name).write_text('fixture')
            with patch('builtins.input', return_value='n'), patch.object(menu.subprocess, 'run') as launch:
                self.assertEqual(menu.install_bundle(terminal, path, 'relay'), 0)
                launch.assert_not_called()

    def test_missing_bundle_never_launches_install(self):
        menu = self.require_menu()
        terminal = menu.Terminal(stream=io.StringIO(), interactive=True, animation=False, color=False)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(menu.subprocess, 'run') as launch:
                with self.assertRaises(ValueError):
                    menu.install_bundle(terminal, Path(temporary), 'relay')
                launch.assert_not_called()

    def test_declined_or_failed_install_is_reported(self):
        menu = self.require_menu()
        terminal = menu.Terminal(stream=io.StringIO(), interactive=True, animation=False, color=False)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for name in ('install-common.sh', 'stunnel.conf', 'client.pem', 'ca.crt', 'prl-fleet-client.service'):
                (path / name).write_text('fixture')
            with patch('builtins.input', return_value='s'), patch.object(menu, 'is_linux', return_value=True), \
                 patch.object(menu, 'is_root', return_value=True), \
                 patch.object(menu.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as launch:
                self.assertEqual(menu.install_bundle(terminal, path, 'client'), 7)
                self.assertEqual(launch.call_args.args[0], ['bash', str(path / 'install-common.sh'), 'client'])
                self.assertEqual(launch.call_args.kwargs['cwd'], path)


if __name__ == '__main__':
    unittest.main()
