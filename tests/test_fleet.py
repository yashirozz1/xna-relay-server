import importlib.util
from pathlib import Path
import unittest
import tempfile
import json

from fleet_bundle import generate

ROOT = Path(__file__).resolve().parents[1]


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'fleet_bundle.py'
        if path.exists():
            spec = importlib.util.spec_from_file_location('fleet_bundle', path)
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)
        else:
            cls.module = None

    def validate(self, manifest):
        self.assertIsNotNone(self.module, 'fleet generator not implemented')
        return self.module.validate_manifest(manifest)

    def base(self):
        return {'relay_ip': '203.0.113.10', 'instances': [{'id': 'gpu001', 'label': 'GPU 1'}]}

    def test_supports_more_than_100_named_instances(self):
        data = self.base()
        data['instances'] = [{'id': f'gpu{i:03}', 'label': f'GPU {i}'} for i in range(150)]
        result = self.validate(data)
        self.assertEqual(len(result['instances']), 150)
        self.assertEqual(result['max_connections_per_instance'], 8)

    def test_rejects_duplicate_reserved_and_injected_identities(self):
        for identities in (['gpu01', 'gpu01'], ['monitor-panel'], ['../gpu01'], ['gpu01\nfoo'], ['']):
            with self.subTest(identities=identities):
                data = self.base()
                data['instances'] = [{'id': identity} for identity in identities]
                with self.assertRaises(ValueError):
                    self.validate(data)

    def test_rejects_dangerous_addresses_ports_and_unknown_fields(self):
        for key, value in (('relay_ip', '0.0.0.0'), ('api_port', 22),
                           ('api_port', 18443), ('pool_host', 'host\nverify none'),
                           ('max_connections', 0), ('extra', 'ignored?')):
            with self.subTest(key=key):
                data = self.base()
                data[key] = value
                with self.assertRaises(ValueError):
                    self.validate(data)

    def test_rejects_label_control_characters(self):
        data = self.base()
        data['instances'][0]['label'] = 'a\nb'
        with self.assertRaises(ValueError):
            self.validate(data)


class BundleTests(unittest.TestCase):
    def test_complete_bundle_keeps_each_secret_with_its_recipient(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pki = root / 'pki'
            (pki / 'clients').mkdir(parents=True)
            for name in ('ca.crt', 'server.pem', 'crl.pem', 'ca.key',
                         'clients/gpu01.pem', 'clients/gpu02.pem', 'clients/monitor-panel.pem'):
                (pki / name).write_text('fixture-' + name)
            manifest = {'relay_ip': '203.0.113.10',
                        'instances': [{'id': 'gpu01'}, {'id': 'gpu02'}]}
            output = root / 'bundle'
            try:
                generate(manifest, pki, output)
            except FileNotFoundError as exc:
                self.fail(f'Bundle cannot be generated: {exc.filename}')
            for name in ('relay/install.sh', 'relay/install-common.sh',
                         'relay/prl-fleet.service', 'relay/prl-monitor.service',
                         'relay/monitor/app.py', 'clients/gpu01/install.sh',
                         'clients/gpu01/install-common.sh',
                         'clients/gpu01/prl-fleet-client.service', 'README.md'):
                self.assertTrue((output / name).is_file(), name)
            self.assertFalse(list(output.rglob('ca.key')))
            self.assertEqual((output / 'clients/gpu01/client.pem').read_text(), 'fixture-clients/gpu01.pem')
            self.assertEqual(sorted(p.name for p in (output / 'clients/gpu01').glob('*.pem')), ['client.pem'])
            self.assertEqual((output / 'panel/client.pem').read_text(), 'fixture-clients/monitor-panel.pem')
            token = (output / 'relay/api-token').read_text()
            self.assertGreaterEqual(len(token.strip()), 32)
            self.assertEqual((output / 'panel/api-token').read_text(), token)
            registry = json.loads((output / 'relay/registry.json').read_text())
            self.assertEqual(registry, {'instances': [{'id': 'gpu01', 'label': 'gpu01'},
                                                     {'id': 'gpu02', 'label': 'gpu02'}]})
            with self.assertRaises(ValueError):
                generate(manifest, pki, output)
            self.assertEqual((output / 'relay/api-token').read_text(), token)

    def test_incomplete_pki_leaves_no_partial_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'bundle'
            with self.assertRaises(ValueError):
                generate({'relay_ip': '203.0.113.10', 'instances': [{'id': 'gpu01'}]},
                         Path(temporary) / 'missing', output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
