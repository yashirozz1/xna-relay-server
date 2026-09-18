import base64
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dual_bundle import generate_dual


class DualBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fleet = self.root / 'fleet'
        self.fleet.mkdir()
        manifest = {'relay_ip': '169.58.109.245', 'instances': [{'id': 'gpu0001'}, {'id': 'gpu0002'}],
                    'xmr_pool_host': 'xmr.kryptex.network', 'xmr_pool_port': 8029}
        (self.fleet / 'manifest.json').write_text(json.dumps(manifest))
        for identity in ('gpu0001', 'gpu0002'):
            folder = self.fleet / 'clients' / identity
            folder.mkdir(parents=True)
            (folder / 'ca.crt').write_text('public-ca')
            (folder / 'client.pem').write_text('private-' + identity)
        (self.fleet / 'ca.key').write_text('never-distribute-ca-key')
        self.installer = self.root / 'install.py'
        self.installer.write_text('print("test installer")\n')
        self.output = self.root / 'output'
        self.verification = patch('dual_bundle.verify_credentials')
        self.verification.start()
        self.addCleanup(self.verification.stop)

    def generate(self, **kwargs):
        return generate_dual(self.fleet, 'gpu0002', 'krxYZDM8VP', self.output,
                             installer=self.installer, **kwargs)

    def test_only_selected_identity_is_in_private_cloud_init(self):
        self.generate()
        cloud = (self.output / 'cloud-init.yaml').read_text()
        document = json.loads(cloud.split('\n', 1)[1])
        self.assertTrue(cloud.startswith('#cloud-config\n'))
        contents = {entry['path']: gzip.decompress(base64.b64decode(entry['content'])).decode()
                    for entry in document['write_files'] if entry.get('encoding') == 'gz+b64'}
        root = '/var/lib/xna-dual-bootstrap/'
        self.assertEqual(contents[root + 'client.pem'], 'private-gpu0002')
        self.assertNotIn('private-gpu0001', '\n'.join(contents.values()))
        self.assertNotIn('never-distribute-ca-key', '\n'.join(contents.values()))
        settings = json.loads(contents[root + 'settings.json'])
        self.assertEqual(settings['instance_id'], 'gpu0002')
        self.assertEqual(settings['reserve_cpu_percent'], 10)
        self.assertLess(len(cloud.encode()), 65536)
        self.assertTrue(all(entry['permissions'] == '0600' for entry in document['write_files']))
        self.assertIn('--no-block', document['runcmd'][-1])
        unit = contents['/etc/systemd/system/xna-dual-bootstrap.service']
        self.assertIn('Restart=on-failure', unit)
        self.assertIn('After=network-online.target cloud-final.service', unit)

    def test_invalid_or_missing_identity_and_account_do_not_create_output(self):
        for identity, account in (('../gpu0001', 'krxYZDM8VP'), ('monitor-panel', 'krxYZDM8VP'),
                                  ('gpu9999', 'krxYZDM8VP'), ('gpu0002', 'krxX\nExecStart=bad')):
            with self.subTest(identity=identity, account=account), self.assertRaises(ValueError):
                generate_dual(self.fleet, identity, account, self.output, installer=self.installer)
            self.assertFalse(self.output.exists())

    def test_existing_output_and_missing_certificate_are_preserved(self):
        self.generate()
        original = (self.output / 'client.pem').read_bytes()
        with self.assertRaises(FileExistsError):
            self.generate()
        self.assertEqual((self.output / 'client.pem').read_bytes(), original)
        (self.fleet / 'clients/gpu0001/client.pem').unlink()
        other = self.root / 'other'
        with self.assertRaises(FileNotFoundError):
            generate_dual(self.fleet, 'gpu0001', 'krxYZDM8VP', other, installer=self.installer)
        self.assertFalse(other.exists())

    def test_oversize_userdata_rejected_before_writing(self):
        import random
        self.installer.write_bytes(random.Random(4).randbytes(90000))
        with self.assertRaisesRegex(ValueError, '64 KiB'):
            self.generate()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
