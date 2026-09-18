"""Exercise the Linux downloader with a local archive at the network boundary."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux bootstrap')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xna-bootstrap-test-')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.destination = self.path / 'destination with spaces'
        archive = self.path / 'source.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            for name in ('install.sh', 'fleet/menu.py', 'fleet_bundle.py'):
                output.add(ROOT / name, arcname='xna-relay-server-main/' + name)
        self.bin = self.path / 'bin'
        self.bin.mkdir()
        downloader = self.bin / 'curl'
        downloader.write_text('''#!/usr/bin/env bash
set -euo pipefail
if [[ ${XNA_TEST_DOWNLOAD_FAIL:-0} == 1 ]]; then exit 22; fi
while (($#)); do
  if [[ $1 == --output ]]; then /bin/cp -- "$XNA_TEST_ARCHIVE" "$2"; exit 0; fi
  shift
done
exit 9
''')
        downloader.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        XNA_INSTALL_DIR=str(self.destination), XNA_TEST_ARCHIVE=str(archive))

    def run_bootstrap(self, *args):
        self.assertTrue((ROOT / 'bootstrap.sh').is_file(), 'Linux bootstrap is missing')
        return subprocess.run(['bash', str(ROOT / 'bootstrap.sh'), *args], env=self.env,
                              input='', capture_output=True, text=True, timeout=20)

    def test_download_and_launch_real_menu_without_tty(self):
        result = self.run_bootstrap('--no-color')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('XNA RELAY SERVER', result.stdout)
        self.assertIn('terminal interativo', result.stdout)
        self.assertNotIn('\x1b', result.stdout)
        self.assertTrue((self.destination / 'fleet/menu.py').is_file())

    def test_download_without_launch(self):
        result = self.run_bootstrap('--no-launch')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.destination / 'install.sh').is_file())
        self.assertNotIn('Central de instalacao', result.stdout)

    def test_existing_destination_is_preserved(self):
        self.destination.mkdir()
        (self.destination / 'keep').write_text('keep')
        result = self.run_bootstrap('--no-launch')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([p.name for p in self.destination.iterdir()], ['keep'])

    def test_failed_download_never_creates_destination(self):
        self.env['XNA_TEST_DOWNLOAD_FAIL'] = '1'
        self.assertNotEqual(self.run_bootstrap('--no-launch').returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_invalid_archive_never_creates_destination(self):
        Path(self.env['XNA_TEST_ARCHIVE']).write_bytes(b'not a tar archive')
        self.assertNotEqual(self.run_bootstrap('--no-launch').returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_incomplete_archive_never_creates_destination(self):
        with tarfile.open(self.env['XNA_TEST_ARCHIVE'], 'w:gz') as output:
            info = tarfile.TarInfo('xna-relay-server-main/README.md')
            info.size = 4
            output.addfile(info, io.BytesIO(b'test'))
        self.assertNotEqual(self.run_bootstrap('--no-launch').returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_help_and_unknown_option_do_not_download(self):
        self.assertEqual(self.run_bootstrap('--help').returncode, 0)
        self.assertNotEqual(self.run_bootstrap('--unknown').returncode, 0)
        self.assertFalse(self.destination.exists())

    def test_failed_copy_reports_partial_destination_without_claiming_success(self):
        copier = self.bin / 'cp'
        copier.write_text('#!/usr/bin/env bash\nexit 28\n')
        copier.chmod(0o755)
        result = self.run_bootstrap('--no-launch')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('parcial preservada', result.stderr)
        self.assertIn('XNA_INSTALL_DIR', result.stderr)
        self.assertNotIn('Projeto instalado', result.stdout)
