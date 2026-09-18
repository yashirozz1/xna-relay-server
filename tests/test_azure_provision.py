"""Relay allocation integration tests: real PKI, isolated files, fake systemd."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fleet.pki import init_pki, issue_client, revoke_client
from fleet_bundle import render_haproxy


class SystemRunner:
    def __init__(self, service):
        self.service = service
        self.commands = []
        self.fail_validation = False
        self.fail_restart_once = False
        self.crash_restart_once = False
        self.inactive_once = False
        self.overrides = ''

    def __call__(self, command, *, cwd):
        self.commands.append((command, cwd))
        output = ''
        if command[:2] == ['systemctl', 'show']:
            output = str(self.service) if 'FragmentPath' in ' '.join(command) else self.overrides
        elif command[:3] == ['runuser', '-u', 'prl-fleet']:
            if self.fail_validation:
                raise RuntimeError('validation rejected')
            candidate = Path(command[-1]).read_text()
            assert 'frontend fleet_ingress' in candidate
            assert cwd == '/'
        elif command[:2] == ['systemctl', 'restart'] and self.fail_restart_once:
            self.fail_restart_once = False
            raise RuntimeError('restart failed')
        elif command[:2] == ['systemctl', 'restart'] and self.crash_restart_once:
            self.crash_restart_once = False
            raise KeyboardInterrupt('simulated process termination')
        elif command[:2] == ['systemctl', 'is-active'] and self.inactive_once:
            self.inactive_once = False
            raise RuntimeError('service did not become active')
        return subprocess.CompletedProcess(command, 0, output, '')


class AzureProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority_temp = tempfile.TemporaryDirectory()
        cls.authority = Path(cls.authority_temp.name) / 'pki'
        init_pki(cls.authority, 'test authority password', '203.0.113.10')
        issue_client(cls.authority, 'gpu0001', 'test authority password')
        issue_client(cls.authority, 'azgpu0001', 'test authority password')
        revoke_client(cls.authority, 'azgpu0001', 'test authority password')

    @classmethod
    def tearDownClass(cls):
        cls.authority_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'private'
        self.base.mkdir(mode=0o700)
        shutil.copytree(self.authority, self.base / 'pki')
        (self.base / 'ca-passphrase').write_text('test authority password\n')
        (self.base / 'ca-passphrase').chmod(0o600)
        self.fleet = self.base / 'fleet'
        self.fleet.mkdir()
        self.manifest = {'relay_ip': '203.0.113.10', 'instances': [{'id': f'gpu{i:04d}'} for i in range(1, 17)]}
        (self.fleet / 'manifest.json').write_text(json.dumps(self.manifest))
        self.config = self.root / 'etc/prl-fleet'
        self.config.mkdir(parents=True)
        (self.config / 'haproxy.cfg').write_text(render_haproxy(self.manifest, config_dir=str(self.config)))
        for name in ('server.pem', 'ca.crt', 'crl.pem'):
            shutil.copyfile(self.base / 'pki' / name, self.config / name)
        self.registry = self.root / 'etc/prl-monitor/registry.json'
        self.registry.parent.mkdir()
        self.registry.write_text(json.dumps({'instances': [{'id': 'gpu0001', 'label': 'gpu0001'}]}))
        self.token = self.registry.parent / 'api-token'
        self.token.write_text('unchanged token')
        self.service = self.root / 'etc/systemd/system/prl-fleet.service'
        self.service.parent.mkdir(parents=True)
        self.service.write_bytes((Path(__file__).resolve().parents[1] / 'fleet/templates/prl-fleet.service').read_bytes())
        self.runner = SystemRunner(self.service)

    def provisioner(self):
        from fleet.azure_provision import Provisioner
        return Provisioner(self.base, config_dir=self.config, registry_path=self.registry,
                           service_path=self.service, runner=self.runner)

    def request(self, operation='a' * 64, **changes):
        return dict(action='prepare', operation_id=operation, spec_hash='b' * 64,
                    account='krxExample1', reserve_cpu_percent=10) | changes

    def test_new_id_real_certificate_repeat_and_public_status(self):
        provisioner = self.provisioner()
        before_serial = (self.base / 'pki/serial').read_text()
        result = provisioner.handle(self.request())
        self.assertEqual(result['instance_id'], 'gpu0017')
        serial = (self.base / 'pki/serial').read_text()
        self.assertNotEqual(serial, before_serial)
        document = json.loads(base64.b64decode(result['cloud_init_b64']).decode().split('\n', 1)[1])
        contents = {row['path']: gzip.decompress(base64.b64decode(row['content'])) for row in document['write_files']}
        pem = contents['/var/lib/xna-dual-bootstrap/client.pem']
        self.assertEqual(pem, (self.base / 'pki/clients/gpu0017.pem').read_bytes())
        from dual_bundle import verify_credentials
        verify_credentials(self.fleet / 'clients/gpu0017', 'gpu0017')
        self.assertEqual(provisioner.handle(self.request()), result)
        self.assertEqual((self.base / 'pki/serial').read_text(), serial)
        self.assertEqual(self.token.read_text(), 'unchanged token')
        status = provisioner.handle({'action': 'status', 'operation_id': 'a' * 64})
        self.assertEqual(status, {'operation_id': 'a' * 64, 'instance_id': 'gpu0017', 'status': 'ready'})
        self.assertEqual(provisioner.handle({'action': 'status', 'operation_id': 'c' * 64}),
                         {'operation_id': 'c' * 64, 'status': 'unknown'})
        self.assertEqual(json.loads((self.fleet / 'manifest.json').read_text())['xmr_pool_port'], 8029)
        self.assertEqual(len(json.loads(self.registry.read_text())['instances']), 17)
        self.assertIn('backend pool_gpu0017', (self.config / 'haproxy.cfg').read_text())

    def test_changed_spec_or_credentials_refused_without_reissue(self):
        provisioner = self.provisioner()
        provisioner.handle(self.request())
        serial = (self.base / 'pki/serial').read_bytes()
        for changes in ({'spec_hash': 'c' * 64}, {'account': 'krxDifferent'}, {'reserve_cpu_percent': 20}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                provisioner.handle(self.request(**changes))
        self.assertEqual((self.base / 'pki/serial').read_bytes(), serial)

    def test_parallel_calls_allocate_distinct_ids_and_same_operation_resumes(self):
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda op: self.provisioner().handle(self.request(op)),
                                    ['a' * 64, 'c' * 64, 'a' * 64]))
        self.assertEqual(results[0], results[2])
        self.assertEqual({row['instance_id'] for row in results}, {'gpu0017', 'gpu0018'})
        self.assertEqual(len(json.loads(self.registry.read_text())['instances']), 18)

    def test_validation_failure_preserves_active_files_and_reserved_identity(self):
        provisioner = self.provisioner()
        paths = [self.fleet / 'manifest.json', self.config / 'haproxy.cfg', self.registry, self.service]
        before = [path.read_bytes() for path in paths]
        self.runner.fail_validation = True
        with self.assertRaises(RuntimeError):
            provisioner.handle(self.request())
        self.assertEqual([path.read_bytes() for path in paths], before)
        status = provisioner.handle({'action': 'status', 'operation_id': 'a' * 64})
        self.assertEqual(status['status'], 'allocated')
        self.runner.fail_validation = False
        result = provisioner.handle(self.request())
        self.assertEqual(result['instance_id'], status['instance_id'])

    def test_failed_activation_restores_active_files_and_retry_keeps_id(self):
        provisioner = self.provisioner()
        # The second enrollment only restarts the monitor; failure still rolls back.
        provisioner.handle(self.request())
        paths = [self.fleet / 'manifest.json', self.config / 'haproxy.cfg', self.registry, self.service]
        before = [path.read_bytes() for path in paths]
        self.runner.fail_restart_once = True
        with self.assertRaises(RuntimeError):
            provisioner.handle(self.request('c' * 64))
        self.assertEqual([path.read_bytes() for path in paths], before)
        result = provisioner.handle(self.request('c' * 64))
        self.assertEqual(result['instance_id'], 'gpu0018')

    def test_unfamiliar_service_or_config_drift_refuses_before_issuance(self):
        before = (self.base / 'pki/serial').read_bytes()
        self.runner.overrides = '/etc/systemd/system/prl-fleet.service.d/custom.conf'
        with self.assertRaises(ValueError):
            self.provisioner().handle(self.request())
        self.runner.overrides = ''
        with (self.config / 'haproxy.cfg').open('a') as stream:
            stream.write('\n# unexplained drift\n')
        with self.assertRaises(ValueError):
            self.provisioner().handle(self.request())
        self.assertEqual((self.base / 'pki/serial').read_bytes(), before)

    def test_capacity_preparation_restarts_once_then_registers_without_relay_restart(self):
        self.provisioner().handle(self.request())
        commands = [row[0] for row in self.runner.commands]
        self.assertIn(['systemctl', 'restart', 'prl-fleet.service'], commands)
        config = (self.config / 'haproxy.cfg').read_bytes()
        self.assertIn(b'backend pool_gpu0128', config)
        self.assertNotIn(b'backend pool_gpu0129', config)
        self.runner.commands.clear()
        result = self.provisioner().handle(self.request('c' * 64))
        commands = [row[0] for row in self.runner.commands]
        self.assertNotIn(['systemctl', 'restart', 'prl-fleet.service'], commands)
        self.assertNotIn(['systemctl', 'reload', 'prl-fleet.service'], commands)
        self.assertIn(['systemctl', 'restart', 'prl-monitor.service'], commands)
        self.assertEqual((self.config / 'haproxy.cfg').read_bytes(), config)
        self.assertEqual(result['instance_id'], 'gpu0018')
        self.assertEqual(len(json.loads(self.registry.read_text())['instances']), 18)
        self.assertEqual(len(json.loads((self.fleet / 'manifest.json').read_text())['instances']), 18)

    def test_capacity_boundary_expands_to_256_once_at_identity_129(self):
        from fleet.azure_provision import expanded_manifest
        self.manifest['instances'] = [{'id': f'gpu{i:04d}'} for i in range(1, 128)]
        self.manifest.update(xmr_pool_host='xmr.kryptex.network', xmr_pool_port=8029)
        (self.fleet / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.config / 'haproxy.cfg').write_text(render_haproxy(expanded_manifest(self.manifest), config_dir=str(self.config)))
        result = self.provisioner().handle(self.request())
        self.assertEqual(result['instance_id'], 'gpu0128')
        commands = [row[0] for row in self.runner.commands]
        self.assertNotIn(['systemctl', 'restart', 'prl-fleet.service'], commands)
        self.runner.commands.clear()
        result = self.provisioner().handle(self.request('c' * 64))
        self.assertEqual(result['instance_id'], 'gpu0129')
        commands = [row[0] for row in self.runner.commands]
        self.assertEqual(commands.count(['systemctl', 'restart', 'prl-fleet.service']), 1)
        config = (self.config / 'haproxy.cfg').read_text()
        self.assertIn('backend pool_gpu0256', config)
        self.assertNotIn('backend pool_gpu0257', config)
        self.assertEqual(len(json.loads(self.registry.read_text())['instances']), 129)

    def test_expansion_preserves_arbitrary_id_and_ip_restriction_without_mutating_manifest(self):
        from fleet.azure_provision import expanded_manifest
        manifest = {'relay_ip': '203.0.113.10', 'instances': [
            {'id': 'custom-miner', 'label': 'Custom', 'allowed_ip': '192.0.2.4'}, {'id': 'gpu0002'}]}
        expanded = expanded_manifest(manifest)
        self.assertEqual(len(expanded['instances']), 128)
        self.assertEqual(len(manifest['instances']), 2)
        custom = next(row for row in expanded['instances'] if row['id'] == 'custom-miner')
        self.assertEqual(custom['allowed_ip'], '192.0.2.4')
        self.assertEqual(custom['label'], 'Custom')
        self.assertIn('gpu0127', {row['id'] for row in expanded['instances']})
        manifest['instances'] = [{'id': f'gpu{i:04d}'} for i in range(1, 1025)]
        self.assertEqual(len(expanded_manifest(manifest)['instances']), 1024)

    def test_private_files_and_invalid_request(self):
        provisioner = self.provisioner()
        for changes in ({'operation_id': '../escape'}, {'reserve_cpu_percent': True}, {'account': 'bad'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                provisioner.handle(self.request(**changes))
        provisioner.handle(self.request())
        if os.name == 'posix':
            for path in (self.base / 'automation').rglob('*'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_process_interruption_recovers_journal_before_resuming(self):
        provisioner = self.provisioner()
        self.runner.crash_restart_once = True
        with self.assertRaises(KeyboardInterrupt):
            provisioner.handle(self.request())
        self.assertTrue((self.base / 'automation/transaction.json').exists())
        serial = (self.base / 'pki/serial').read_bytes()
        result = self.provisioner().handle(self.request())
        self.assertEqual(result['instance_id'], 'gpu0017')
        self.assertEqual((self.base / 'pki/serial').read_bytes(), serial)
        self.assertFalse((self.base / 'automation/transaction.json').exists())
        self.assertIn('backend pool_gpu0017', (self.config / 'haproxy.cfg').read_text())

    def test_repeat_repairs_missing_manifest_and_registry_identity(self):
        result = self.provisioner().handle(self.request())
        serial = (self.base / 'pki/serial').read_bytes()
        (self.fleet / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.config / 'haproxy.cfg').write_text(render_haproxy(self.manifest, config_dir=str(self.config)))
        self.registry.write_text(json.dumps({'instances': []}))
        self.assertEqual(self.provisioner().handle(self.request()), result)
        self.assertEqual((self.base / 'pki/serial').read_bytes(), serial)
        self.assertEqual(json.loads(self.registry.read_text())['instances'][-1]['id'], 'gpu0017')

    def test_global_capacity_refuses_before_issuance(self):
        self.manifest['instances'] = [{'id': f'gpu{i:04d}'} for i in range(1, 1025)]
        (self.fleet / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.config / 'haproxy.cfg').write_text(render_haproxy(self.manifest, config_dir=str(self.config)))
        serial = (self.base / 'pki/serial').read_bytes()
        with self.assertRaisesRegex(ValueError, 'capacity'):
            self.provisioner().handle(self.request())
        self.assertEqual((self.base / 'pki/serial').read_bytes(), serial)
        self.assertEqual(list((self.base / 'automation/operations').glob('*.json')), [])

    def test_crl_is_renewed_near_expiry_preserving_revoked_certificates(self):
        class FutureClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(days=25)

        previous = (self.base / 'pki/crlnumber').read_bytes()
        with patch('fleet.azure_provision.datetime', FutureClock):
            self.provisioner().handle(self.request())
        self.assertNotEqual((self.base / 'pki/crlnumber').read_bytes(), previous)
        self.assertEqual((self.config / 'crl.pem').read_bytes(), (self.base / 'pki/crl.pem').read_bytes())
        from dual_bundle import _openssl
        with self.assertRaisesRegex(ValueError, 'revoked'):
            _openssl(self.base / 'pki', 'verify', '-CAfile', 'ca.crt', '-CRLfile', 'crl.pem',
                     '-crl_check', 'clients/azgpu0001.pem')

    def test_maintenance_renews_crl_without_issuing_identity(self):
        class FutureClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(days=25)

        serial = (self.base / 'pki/serial').read_bytes()
        previous = (self.base / 'pki/crlnumber').read_bytes()
        with patch('fleet.azure_provision.datetime', FutureClock):
            result = self.provisioner().maintain()
        self.assertTrue(result['crl_refreshed'])
        self.assertNotEqual((self.base / 'pki/crlnumber').read_bytes(), previous)
        self.assertEqual((self.base / 'pki/serial').read_bytes(), serial)
        self.assertEqual((self.config / 'crl.pem').read_bytes(), (self.base / 'pki/crl.pem').read_bytes())
        self.assertEqual(list((self.base / 'automation/operations').glob('*.json')), [])
        self.assertFalse(self.provisioner().maintain()['crl_refreshed'])

    def test_inactive_service_rolls_back_before_success_response(self):
        paths = [self.fleet / 'manifest.json', self.config / 'haproxy.cfg', self.registry]
        before = [path.read_bytes() for path in paths]
        self.runner.inactive_once = True
        with self.assertRaisesRegex(RuntimeError, 'active'):
            self.provisioner().handle(self.request())
        self.assertEqual([path.read_bytes() for path in paths], before)



if __name__ == '__main__':
    unittest.main()
