"""Exercise the public CLI, including hostile configuration inputs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BundleTests(unittest.TestCase):
    def invoke(self, output, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / 'relay_bundle.py'),
             '--relay-ip', '203.0.113.10', '--client-ip', '198.51.100.20',
             '--output', str(output), *extra],
            capture_output=True, text=True,
        )

    def test_bundle_can_be_generated_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bundle'
            result = self.invoke(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads((output / 'settings.json').read_text())
            self.assertEqual(metadata['pool_host'], 'prl.kryptex.network')
            for name in ('relay/install.sh', 'client/install.sh',
                         'relay/prl-relay.service', 'client/prl-client.service',
                         'relay/haproxy.cfg', 'client/stunnel.conf'):
                data = (output / name).read_bytes()
                self.assertNotIn(b'\r', data, name)

    def test_invalid_inputs_create_no_output(self):
        cases = [
            ('--client-ip', '0.0.0.0/0'),
            ('--client-ip', '0.0.0.0'),
            ('--relay-ip', '224.0.0.1'),
            ('--relay-ip', '255.255.255.255'),
            ('--relay-ip', '::1'),
            ('--pool-host', 'pool.example\nverifyChain = no'),
            ('--pool-host', 'pool.example:8048'),
            ('--pool-host', '-pool.example'),
            ('--relay-port', '22'),
            ('--local-port', '443'),
            ('--pool-port', '65536'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for i, arguments in enumerate(cases):
                with self.subTest(arguments=arguments):
                    output = Path(directory) / str(i)
                    result = self.invoke(output, *arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('error:', result.stderr)
                    self.assertFalse(output.exists())

    def test_existing_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bundle'
            output.mkdir()
            marker = output / 'important.txt'
            marker.write_text('keep this')
            result = self.invoke(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('error:', result.stderr)
            self.assertEqual(marker.read_text(), 'keep this')
            self.assertEqual(list(output.iterdir()), [marker])


if __name__ == '__main__':
    unittest.main()
