import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from dual_bundle import BOOTSTRAP, UNIT, cloud_config


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        from dual import enroll
        self.enroll = enroll
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.claim = 'a' * 64
        self.installer = b'print("installer fixture")\n'
        self.settings = {'version': 1, 'relay_host': '169.58.109.245', 'relay_port': 22,
                         'installer_sha256': hashlib.sha256(self.installer).hexdigest()}

    def response(self):
        files = {BOOTSTRAP + '/install.py': self.installer,
                 BOOTSTRAP + '/settings.json': json.dumps(dict(version=1, instance_id='azgpu0001',
                     relay_ip='169.58.109.245', relay_port=18443, account='krxYZDM8VP',
                     reserve_cpu_percent=10)).encode(),
                 BOOTSTRAP + '/ca.crt': b'CA', BOOTSTRAP + '/client.pem': b'PRIVATE',
                 '/etc/systemd/system/xna-dual-bootstrap.service': UNIT.encode()}
        return dict(operation_id=self.enroll.operation_id(self.claim), instance_id='azgpu0001',
                    cloud_init_b64=base64.b64encode(cloud_config(files).encode()).decode())

    def test_claim_is_durable_unique_and_bound_to_machine(self):
        first = self.enroll.get_claim(self.root / 'one', 'machine-one')
        self.assertEqual(first, self.enroll.get_claim(self.root / 'one', 'machine-one'))
        self.assertNotEqual(first, self.enroll.get_claim(self.root / 'two', 'machine-two'))
        with self.assertRaises(ValueError):
            self.enroll.get_claim(self.root / 'one', 'cloned-machine')

    def test_bundle_unpack_checks_identity_and_pinned_installer(self):
        files = self.enroll.unpack(self.response(), self.claim, self.settings)
        self.assertEqual(files['client.pem'], b'PRIVATE')
        self.assertEqual(files['install.py'], self.installer)
        for key, value in [('instance_id', 'gpu-wrong'), ('operation_id', '0' * 64)]:
            broken = self.response() | {key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.enroll.unpack(broken, self.claim, self.settings)
        with self.assertRaises(ValueError):
            self.enroll.unpack(self.response(), self.claim, self.settings | {'installer_sha256': '0' * 64})

    def test_unexpected_destination_and_oversize_response_rejected(self):
        response = self.response()
        doc = json.loads(base64.b64decode(response['cloud_init_b64']).split(b'\n', 1)[1])
        doc['write_files'][0]['path'] = '/etc/cron.d/unexpected'
        response['cloud_init_b64'] = base64.b64encode(b'#cloud-config\n' + json.dumps(doc).encode()).decode()
        with self.assertRaises(ValueError):
            self.enroll.unpack(response, self.claim, self.settings)
        with self.assertRaises(ValueError):
            self.enroll.unpack(self.response() | {'cloud_init_b64': 'A' * 100000}, self.claim, self.settings)

    def test_ssh_is_noninteractive_pinned_and_uses_only_enrollment_key(self):
        command = self.enroll.ssh_command(self.root, self.settings)
        joined = ' '.join(command)
        self.assertIn('StrictHostKeyChecking=yes', joined)
        self.assertIn('BatchMode=yes', joined)
        self.assertIn('IdentitiesOnly=yes', joined)
        self.assertIn('GlobalKnownHostsFile=/dev/null', joined)
        self.assertNotIn('StrictHostKeyChecking=no', joined)
        self.assertEqual(command[-2:], ['root@169.58.109.245', 'xna-mining-enroll'])

    def test_hostname_only_updates_local_hostname_mapping(self):
        original = '127.0.0.1 localhost\n127.0.1.1 oldvm alias\n46.1.2.3 pool.example\n'
        result = self.enroll.hostname_hosts(original, 'oldvm', 'gpu0017')
        self.assertEqual(result, '127.0.0.1 localhost\n127.0.1.1 gpu0017 alias\n46.1.2.3 pool.example\n')
        self.assertEqual(self.enroll.hostname_hosts(result, 'gpu0017', 'gpu0017'), result)

    def test_readiness_requires_accepted_shares_from_both_miners(self):
        metrics = 'krig_miner_blocks_submitted_total{gpu="0",result="accepted"} 3\n'
        metrics += 'krig_miner_blocks_submitted_total{gpu="1",result="rejected"} 9\n'
        status = self.enroll.mining_status(metrics, {'results': {'shares_good': 2}})
        self.assertEqual(status, {'prl_accepted': 3, 'xmr_accepted': 2, 'ready': True})
        self.assertFalse(self.enroll.mining_status(metrics, {'results': {'shares_good': 0}})['ready'])
        self.assertFalse(self.enroll.mining_status('', {'results': {'shares_good': 2}})['ready'])


class GatewayTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and shutil.which('systemd-analyze'), 'systemd validator')
    def test_maintenance_timer_and_service_have_valid_settings(self):
        from fleet.enroll_setup import maintenance_units, UNIT
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            units = maintenance_units(root / 'private', root / 'release')
            units['xna-dual-bootstrap.service'] = UNIT
            paths = []
            for name, content in units.items():
                path = root / name
                path.write_text(content)
                paths.append(str(path))
            result = subprocess.run(['systemd-analyze', 'verify', *paths], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_snapshot_preserves_previous_installer_version(self):
        from fleet import enroll_setup
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            for name in enroll_setup.SOURCES:
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'first version')
            with patch.object(enroll_setup, 'ROOT', source):
                first = enroll_setup.snapshot(root / 'private')
                self.assertEqual(first, enroll_setup.snapshot(root / 'private'))
                (source / 'dual/install.py').write_bytes(b'second version')
                second = enroll_setup.snapshot(root / 'private')
                self.assertNotEqual(first, second)
                self.assertEqual((first / 'dual/install.py').read_bytes(), b'first version')
                self.assertEqual((second / 'dual/install.py').read_bytes(), b'second version')

    def test_only_claim_is_accepted_and_settings_are_fixed_server_side(self):
        from fleet.enroll_gateway import request_for_claim
        claim = 'b' * 64
        request = request_for_claim({'claim': claim}, 'krxYZDM8VP', 10)
        self.assertEqual(request['account'], 'krxYZDM8VP')
        self.assertEqual(request['operation_id'], hashlib.sha256(('xna-mining-enrollment-v1:' + claim).encode()).hexdigest())
        for body in ({'operation_id': 'a' * 64}, {'claim': claim, 'account': 'krxATTACKER'},
                     {'claim': '../bad'}, {'claim': claim, 'action': 'status'}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                request_for_claim(body, 'krxYZDM8VP', 10)

    def test_authorized_key_update_preserves_other_access_and_restricts_enrollment(self):
        from fleet.enroll_setup import authorized_keys
        original = 'ssh-ed25519 QUJD existing-admin\n'
        public = 'ssh-ed25519 REVG xna-enrollment'
        updated = authorized_keys(original, public, 'python3 /opt/relay/enroll_gateway.py')
        self.assertTrue(updated.startswith(original))
        self.assertIn('restrict,command="python3 /opt/relay/enroll_gateway.py" ssh-ed25519 REVG', updated)
        self.assertEqual(authorized_keys(updated, public, 'python3 /opt/relay/enroll_gateway.py'), updated)
        self.assertEqual(authorized_keys(updated, public, 'python3 /opt/new/enroll_gateway.py').count(' REVG '), 1)
        with self.assertRaises(ValueError):
            authorized_keys('ssh-ed25519 REVG other-key-owner\n', public, 'cmd')

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux shell fixture')
    def test_generated_shell_is_idempotent_and_defers_during_cloud_final(self):
        from fleet.enroll_setup import shell_installer
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            commands = root / 'commands'
            commands.mkdir()
            (commands / 'id').write_text('#!/bin/sh\necho 0\n')
            (commands / 'systemctl').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_LOG"\n'
                'if [ "$1" = "is-active" ]; then exit 3; fi\n'
                'if [ "$1" = "show" ]; then echo activating; fi\nexit 0\n')
            for path in commands.iterdir():
                path.chmod(0o755)
            output = root / 'private/payload'
            script = root / 'install.sh'
            script.write_text(shell_installer({str(output): b'private-fixture'}))
            env = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'], TEST_LOG=str(root / 'calls'))
            subprocess.run(['bash', '-n', str(script)], check=True)
            for _ in range(2):
                subprocess.run(['bash', str(script)], env=env, check=True, capture_output=True)
            self.assertEqual(output.read_bytes(), b'private-fixture')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn('start --no-block xna-dual-bootstrap.service', (root / 'calls').read_text())
            output.write_text('foreign data')
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), 'foreign data')


if __name__ == '__main__':
    unittest.main()
