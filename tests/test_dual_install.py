"""Offline installer safety tests: no package changes, services or mining."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import os
import shutil
import subprocess
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('dual_install', ROOT / 'dual/install.py')


def module():
    assert SPEC.origin and Path(SPEC.origin).is_file(), 'dual installer is missing'
    result = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(result)
    return result


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.install = module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = dict(version=1, instance_id='gpu0002', relay_ip='169.58.109.245',
                             relay_port=18443, account='krxYZDM8VP', reserve_cpu_percent=10)

    def test_settings_reject_injection_unknown_fields_and_bool_numbers(self):
        self.assertEqual(self.install.validate_settings(self.settings)['instance_id'], 'gpu0002')
        for key, value in [('instance_id', '../gpu'), ('instance_id', 'gpu\nfoo'),
                           ('account', 'a/b'), ('relay_ip', 'relay.example'),
                           ('relay_port', True), ('relay_port', 65536), ('version', True),
                           ('reserve_cpu_percent', 0), ('reserve_cpu_percent', 100),
                           ('reserve_cpu_percent', 51), ('account', 'notkryptex'),
                           ('instance_id', 'monitor-panel'), ('instance_id', 'g' * 33),
                           ('unexpected', 1)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.install.validate_settings(dict(self.settings, **{key: value}))
        self.install.validate_settings(dict(self.settings, instance_id='gpu_test-1'))

    def test_physical_cores_reserved_per_numa_and_smt_deduplicated(self):
        rows = [{'cpu': n, 'node': n // 40, 'socket': n // 40, 'core': n % 40,
                 'online': True} for n in range(80)]
        rows += [dict(row, cpu=row['cpu'] + 80) for row in rows]
        plan = self.install.cpu_plan(rows, 10)
        self.assertEqual(plan, {0: list(range(4, 40)), 1: list(range(44, 80))})
        self.assertEqual(self.install.cpu_plan([
            {'cpu': 0, 'node': 0, 'socket': 0, 'core': 0, 'online': True},
            {'cpu': 1, 'node': 0, 'socket': 0, 'core': 1, 'online': False},
            {'cpu': 2, 'node': 0, 'socket': 0, 'core': 2, 'online': True}], 10), {0: [2]})

    def test_too_few_cores_fails_instead_of_consuming_reserved_core(self):
        with self.assertRaises(ValueError):
            self.install.cpu_plan([{'cpu': 0, 'node': 0, 'socket': 0, 'core': 0,
                                    'online': True}], 10)

    def test_driver_version_boundary(self):
        for version in ('580.65.06', '580.65.6', '590.1.0'):
            self.install.validate_driver(version)
        for version in ('575.99.99', '580.65.05', 'unknown', '580.65.06\n575.0.0'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.install.validate_driver(version)

    def test_identity_resume_cannot_change_account_or_certificate(self):
        identity = self.install.state_identity(self.settings, b'ca', b'client')
        self.install.validate_resume({'identity': identity}, identity)
        for changed in [dict(identity, client_sha256='bad'),
                        self.install.state_identity(dict(self.settings, account='other'), b'ca', b'client')]:
            with self.assertRaises(ValueError):
                self.install.validate_resume({'identity': identity}, changed)

    def archive(self, entries):
        path = self.root / 'artifact.tar.gz'
        with tarfile.open(path, 'w:gz') as out:
            for name, content, kind in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(content) if kind == tarfile.REGTYPE else 0
                info.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                out.addfile(info, io.BytesIO(content) if info.size else None)
        return path

    def test_extraction_only_regular_selected_binary_and_licenses(self):
        archive = self.archive([('bin/miner', b'ELF fixture', tarfile.REGTYPE),
                                ('bin/LICENSE', b'license', tarfile.REGTYPE),
                                ('bin/unwanted', b'other', tarfile.REGTYPE)])
        target = self.root / 'out'
        self.install.extract_artifact(archive, 'bin/miner', target)
        self.assertEqual((target / 'miner').read_bytes(), b'ELF fixture')
        self.assertEqual((target / 'LICENSE').read_bytes(), b'license')
        self.assertFalse((target / 'unwanted').exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permissions')
    def test_bootstrap_private_umask_does_not_block_nonroot_miners(self):
        archive = self.archive([('bin/miner', b'ELF fixture', tarfile.REGTYPE)])
        target = self.root / 'miner'
        before = os.umask(0o077)
        try:
            self.install.extract_artifact(archive, 'bin/miner', target)
        finally:
            os.umask(before)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual((target / 'miner').stat().st_mode & 0o777, 0o755)

    def test_traversal_links_and_duplicate_binary_fail_before_writing(self):
        cases = [ [('bin/miner', b'', tarfile.SYMTYPE)],
                  [('bin/miner', b'good', tarfile.REGTYPE), ('../escape', b'bad', tarfile.REGTYPE)],
                  [('bin/miner', b'one', tarfile.REGTYPE), ('bin/miner', b'two', tarfile.REGTYPE)] ]
        for entries in cases:
            with self.subTest(entries=entries):
                path = self.archive(entries)
                target = self.root / 'out'
                with self.assertRaises(ValueError):
                    self.install.extract_artifact(path, 'bin/miner', target)
                self.assertFalse(target.exists())

    def test_checksum_mismatch_never_extracts(self):
        path = self.root / 'archive'
        path.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            self.install.verify_checksum(path, hashlib.sha256(b'correct').hexdigest())
        self.install.verify_checksum(path, hashlib.sha256(b'corrupt').hexdigest())

    def test_hugepage_plan_preserves_foreign_pages_and_group(self):
        self.assertEqual(self.install.hugepage_plan({0: 0, 1: 0}, 0, 123, False),
                         ({0: 1280, 1: 1280}, 123))
        self.assertEqual(self.install.hugepage_plan({0: 2048, 1: 1280}, 456, 123, False),
                         ({0: 2048, 1: 1280}, 456))
        with self.assertRaises(ValueError):
            self.install.hugepage_plan({0: 2048, 1: 0}, 456, 123, False)
        with self.assertRaises(ValueError):
            self.install.hugepage_plan({0: 0}, 456, 123, False)
        with self.assertRaises(ValueError):
            self.install.hugepage_plan({0: 0}, 0, 123, False, foreign=True)

    def test_managed_directory_refuses_existing_unmarked_directory(self):
        target = self.root / 'managed'
        target.mkdir()
        with self.assertRaises(ValueError):
            self.install.owned_directory(target, 'gpu0002')
        target.rmdir()
        self.install.owned_directory(target, 'gpu0002')
        self.install.owned_directory(target, 'gpu0002')
        with self.assertRaises(ValueError):
            self.install.owned_directory(target, 'gpu0003')

    def test_resume_unit_guard_refuses_foreign_unit_or_symlink(self):
        target = self.root / 'unit.service'
        target.write_text('[Service]\nExecStart=/bin/true\n')
        with self.assertRaises(ValueError):
            self.install.guard_unit(target, 'gpu0002')
        target.write_text('# Managed by xna-dual-miner; identity gpu0002\n[Service]\n')
        self.install.guard_unit(target, 'gpu0002')
        with self.assertRaises(ValueError):
            self.install.guard_unit(target, 'gpu0003')

    def test_foreign_listener_cannot_be_adopted_on_retry(self):
        rows = ['  sl local_address rem_address st tx_queue rx tr tm retr uid timeout inode',
                '  0: 0100007F:1F70 00000000:0000 0A 00000000:00000000 00:00000000 00000000 998 0 42']
        self.install.validate_listeners('\n'.join(rows), {8048: 998})
        with self.assertRaises(ValueError):
            self.install.validate_listeners('\n'.join(rows), {8048: 999})

    def test_check_mode_never_calls_install_or_writes_bundle(self):
        bundle = self.root / 'bundle'
        bundle.mkdir()
        (bundle / 'marker').write_bytes(b'unchanged')
        with patch.object(self.install, 'load_bundle', return_value=(self.settings, b'ca', b'client')), \
             patch.object(self.install, 'hardware', return_value=(['0, H100, 580.65.06'], {0: [4, 5]})), \
             patch.object(self.install, 'installed_state', return_value=None), \
             patch.object(self.install, 'install', side_effect=AssertionError('check mutated host')), \
             patch('sys.stdout', new=io.StringIO()) as output:
            self.assertEqual(self.install.main(['--bundle-dir', str(bundle), '--check']), 0)
            self.assertTrue(json.loads(output.getvalue())['check_only'])
        self.assertEqual(list(bundle.iterdir()), [bundle / 'marker'])
        self.assertEqual((bundle / 'marker').read_bytes(), b'unchanged')

    def test_interrupted_package_configuration_recovers_without_removing_locks(self):
        database = {'configured': False, 'repaired': False, 'installed': False, 'locked': True}
        def command(*args, **kwargs):
            if args[0] == 'dpkg':
                if database['locked']:
                    database['locked'] = False
                    return SimpleNamespace(returncode=2, stderr=b'dpkg database lock was locked by another process', stdout=b'')
                if not database['repaired']:
                    return SimpleNamespace(returncode=1, stderr=b'dependency problems prevent configuration', stdout=b'')
                database['configured'] = True
            elif args[0] == 'apt-get' and '-f' in args:
                self.assertIn('--no-remove', args)
                database['repaired'] = True
            elif args[0] == 'apt-get' and 'stunnel4' in args:
                self.assertTrue(database['configured'], 'packages installed before recovering interrupted dpkg')
                database['installed'] = True
            return SimpleNamespace(returncode=0, stderr=b'', stdout=b'')
        with patch.object(self.install, 'run', side_effect=command), patch.object(self.install.time, 'sleep'):
            self.install.install_packages()
        self.assertTrue(database['installed'])

    def test_completion_requires_consecutive_active_samples_without_restarts(self):
        samples = iter([['active', '0'], ['active', '1'], ['active', '1'], ['active', '1']])
        def command(*args, **kwargs):
            status, restarts = next(samples)
            return SimpleNamespace(returncode=0, stdout=(f'ActiveState={status}\nNRestarts={restarts}\n' * 3).encode(), stderr=b'')
        with patch.object(self.install, 'run', side_effect=command), patch.object(self.install.time, 'sleep'):
            self.install.wait_services()
        with self.assertRaises(StopIteration):
            next(samples)

    @unittest.skipUnless(os.name == 'posix', 'POSIX user database')
    def test_service_account_marker_is_valid_passwd_gecos(self):
        account = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir='/nonexistent',
                                  pw_shell='/usr/sbin/nologin', pw_gecos='xna-dual-miner/gpu0002')
        def command(*args):
            self.assertNotIn(':', args[args.index('--comment') + 1])
        with patch('pwd.getpwnam', side_effect=[KeyError, account]), patch.object(self.install, 'run', side_effect=command):
            self.assertIs(self.install.ensure_user('xna-dual-prl', 'gpu0002'), account)

    def test_configs_keep_tls_identity_pool_hostname_and_local_apis(self):
        cfg = self.install.configs(self.settings, {0: [4, 5], 1: [44, 45]}, 1001)
        xm = json.loads(cfg['xmr.json'])
        self.assertEqual(xm['pools'][0]['url'], '127.0.0.1:17029')
        self.assertEqual(xm['pools'][0]['user'], 'krxYZDM8VP/gpu0002-cpu')
        self.assertEqual(xm['cpu']['rx'], [4, 5, 44, 45])
        self.assertFalse(xm['randomx']['wrmsr'])
        self.assertEqual(xm['http']['host'], '127.0.0.1')
        self.assertIn('--url stratum+ssl://prl.kryptex.network:8048', cfg['xna-dual-prl.service'])
        self.assertIn('--gpu-no-reset-oc', cfg['xna-dual-prl.service'])
        self.assertIn('User=xna-dual-prl', cfg['xna-dual-prl.service'])
        self.assertIn('sni = xmr.relay.prl.internal', cfg['stunnel.conf'])
        self.assertIn('checkHost = xmr.kryptex.network', cfg['stunnel.conf'])
        self.assertIn('verifyChain = yes', cfg['stunnel.conf'])

    def test_miners_can_reconnect_when_tunnel_initially_fails(self):
        cfg = self.install.configs(self.settings, {0: [4, 5]}, 1001)
        for miner in ('prl', 'xmr'):
            unit = cfg['xna-dual-' + miner + '.service']
            self.assertIn('Wants=xna-dual-tunnel.service', unit)
            self.assertIn('After=xna-dual-tunnel.service', unit)
            self.assertNotIn('Requires=xna-dual-tunnel.service', unit)


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required for real certificate tests')
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.install = module()
        def openssl(*args):
            subprocess.run(['openssl', *args], cwd=cls.root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=test-ca', '-keyout', 'ca.key', '-out', 'ca.crt')
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=gpu0002',
                '-keyout', 'client.key', '-out', 'client.csr')
        openssl('x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-CAcreateserial', '-days', '1', '-out', 'client.crt')
        cls.client = (cls.root / 'client.crt').read_bytes() + (cls.root / 'client.key').read_bytes()
        cls.ca = (cls.root / 'ca.crt').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.bundle = tempfile.TemporaryDirectory()
        self.addCleanup(self.bundle.cleanup)
        self.path = Path(self.bundle.name)
        self.settings = dict(version=1, instance_id='gpu0002', relay_ip='169.58.109.245',
                             relay_port=18443, account='krxYZDM8VP', reserve_cpu_percent=10)
        (self.path / 'settings.json').write_text(json.dumps(self.settings))
        (self.path / 'ca.crt').write_bytes(self.ca)
        (self.path / 'client.pem').write_bytes(self.client)

    def test_real_matching_certificate_chain_and_key_are_accepted(self):
        settings, ca, client = self.install.load_bundle(self.path)
        self.assertEqual(settings['instance_id'], 'gpu0002')
        self.assertEqual(ca, self.ca)
        self.assertEqual(client, self.client)

    def test_wrong_certificate_cn_is_rejected(self):
        (self.path / 'settings.json').write_text(json.dumps(dict(self.settings, instance_id='gpu0003')))
        with self.assertRaisesRegex(ValueError, 'CN'):
            self.install.load_bundle(self.path)

    def test_unmatched_private_key_is_rejected(self):
        (self.path / 'client.pem').write_bytes((self.root / 'client.crt').read_bytes() + (self.root / 'ca.key').read_bytes())
        with self.assertRaisesRegex(ValueError, 'do not match'):
            self.install.load_bundle(self.path)

    def test_certificate_signed_by_another_ca_is_rejected(self):
        (self.path / 'ca.crt').write_bytes((self.root / 'client.crt').read_bytes())
        with self.assertRaises(ValueError):
            self.install.load_bundle(self.path)

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink behavior')
    def test_symlinked_certificate_is_rejected(self):
        (self.path / 'client.pem').unlink()
        (self.path / 'client.pem').symlink_to(self.root / 'client.crt')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.install.load_bundle(self.path)


@unittest.skipUnless(os.name == 'posix', 'Linux shell and systemd validators')
class LinuxGeneratedArtifactTests(unittest.TestCase):
    def test_iptables_helper_is_idempotent_and_preserves_foreign_rules(self):
        install = module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            fake = path / 'iptables'
            # Replace only the external iptables dependency; execute the real helper.
            fake.write_text('''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
p = Path(os.environ['RULES'])
rules = json.loads(p.read_text())
a = sys.argv[1:]
assert a[:4] == ['-w', '30', '-t', 'nat'], a
action, rule = a[4], a[5:]
assert rule[:7] == ['OUTPUT', '-p', 'tcp', '--dport', '8048', '-m', 'owner'], rule
assert rule[7:] == ['--uid-owner', '1001', '-m', 'comment', '--comment', 'xna-dual-prl', '-j', 'REDIRECT', '--to-ports', '8048'], rule
if action == '-C': sys.exit(0 if rule in rules else 1)
if action == '-A': rules.append(rule)
elif action == '-D': rules.remove(rule)
else: sys.exit(2)
p.write_text(json.dumps(rules))
''')
            fake.chmod(0o755)
            rules = path / 'rules.json'
            rules.write_text(json.dumps([['foreign-rule']]))
            settings = dict(account='krxYZDM8VP', instance_id='gpu0002', relay_ip='169.58.109.245', relay_port=18443)
            helper = path / 'redirect'
            helper.write_text(install.configs(settings, {0: [4]}, 1001)['redirect'].replace('/usr/sbin/iptables', str(fake)))
            env = dict(os.environ, RULES=str(rules))
            for action in ('start', 'start'):
                subprocess.run(['/bin/sh', str(helper), action], env=env, check=True)
                self.assertEqual(len(json.loads(rules.read_text())), 2)
            for action in ('stop', 'stop'):
                subprocess.run(['/bin/sh', str(helper), action], env=env, check=True)
                self.assertEqual(json.loads(rules.read_text()), [['foreign-rule']])

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze unavailable')
    def test_generated_units_pass_systemd_validation(self):
        install = module()
        cfg = install.configs(dict(account='krxYZDM8VP', instance_id='gpu0002',
                                  relay_ip='169.58.109.245', relay_port=18443), {0: [4]}, 1001)
        with tempfile.TemporaryDirectory() as directory:
            units = []
            for name, content in cfg.items():
                if not name.endswith('.service'):
                    continue
                # Executables are absent in tests: replace only executable argv[0].
                import re
                content = re.sub(r'(Exec\w+=\+?)/\S+', r'\1/usr/bin/true', content)
                path = Path(directory) / name
                path.write_text(content)
                units.append(str(path))
            subprocess.run(['systemd-analyze', 'verify', *units], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
