"""Private relay-side provisioning for an already-created mining VM.

Accepts one JSON request on stdin and emits one JSON response on stdout.
The prepare response contains a private client key inside cloud_init_b64.
Run only through an authenticated, trusted root channel; never log that response.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from dual_bundle import _openssl, generate_dual, verify_credentials
from fleet.pki import issue_client, refresh_crl, _certificate_status
from fleet_bundle import render_haproxy, validate_manifest

ROOT = Path(__file__).resolve().parents[1]
MANAGED_UNIT = (ROOT / 'fleet/templates/prl-fleet.service').read_text(encoding='utf-8')
HEX_ID = re.compile(r'[0-9a-f]{64}\Z')


def expanded_manifest(manifest):
    """Reserve HAProxy routing capacity in blocks of 128, without issuing keys.

    Only the returned render input includes unused slots. The private manifest,
    monitor registry and PKI continue to describe actual identities only.
    Stable sorting keeps successive allocations within a block byte-identical.
    """
    expanded = validate_manifest(manifest)
    instances = {row['id']: row for row in expanded['instances']}
    target = min(1024, ((len(instances) + 127) // 128) * 128)
    number = 1
    while len(instances) < target:
        identity = f'gpu{number:04d}'
        if identity not in instances:
            instances[identity] = {'id': identity, 'label': identity, 'allowed_ip': None}
        number += 1
    expanded['instances'] = [instances[identity] for identity in sorted(instances)]
    return expanded


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def _directory(path):
    if path.is_symlink():
        raise ValueError('private directory cannot be a symbolic link')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _sync_dir(path):
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _atomic_write(path, content, *, mode=0o600, preserve=False):
    if path.is_symlink():
        raise ValueError('refusing to replace a symbolic link')
    metadata = path.stat() if preserve and path.exists() else None
    descriptor, filename = tempfile.mkstemp(prefix='.provision-', dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(metadata.st_mode & 0o777 if metadata else mode)
        if metadata and os.name == 'posix':
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
        _sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _lock(path):
    if path.is_symlink():
        raise ValueError('lock cannot be a symbolic link')
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:
            # Used by local Windows tests; production runs under POSIX flock.
            import msvcrt
            deadline = time.monotonic() + 120
            while True:
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('provisioning lock timed out') from None
                    time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def _run(command, *, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        # Do not expose command output or request material to the caller.
        raise RuntimeError('relay service validation or activation failed')
    return result


class Provisioner:
    def __init__(self, base_dir, *, config_dir='/etc/prl-fleet',
                 registry_path='/etc/prl-monitor/registry.json',
                 service_path='/etc/systemd/system/prl-fleet.service', runner=_run):
        self.base = Path(base_dir).absolute()
        self.pki = self.base / 'pki'
        self.fleet = self.base / 'fleet'
        self.manifest_path = self.fleet / 'manifest.json'
        self.config_dir = Path(config_dir).absolute()
        self.config_path = self.config_dir / 'haproxy.cfg'
        self.registry_path = Path(registry_path).absolute()
        self.service_path = Path(service_path).absolute()
        self.runner = runner
        self.automation = self.base / 'automation'
        self.operations = self.automation / 'operations'
        self.bundles = self.automation / 'bundles'
        self.journal = self.automation / 'transaction.json'

    def _command(self, command):
        return self.runner(command, cwd='/')

    def _read_json(self, path):
        if path.is_symlink():
            raise ValueError('state cannot be a symbolic link')
        return json.loads(path.read_text(encoding='utf-8'))

    def _request(self, request):
        if not isinstance(request, dict) or request.get('action') not in ('prepare', 'status'):
            raise ValueError('invalid provisioning action')
        if not isinstance(request.get('operation_id'), str) or not HEX_ID.fullmatch(request['operation_id']):
            raise ValueError('invalid operation ID')
        allowed = {'action', 'operation_id'}
        if request['action'] == 'prepare':
            allowed |= {'spec_hash', 'account', 'reserve_cpu_percent'}
            if not isinstance(request.get('spec_hash'), str) or not HEX_ID.fullmatch(request['spec_hash']):
                raise ValueError('invalid specification hash')
            if not isinstance(request.get('account'), str) or not re.fullmatch(r'krx[A-Za-z0-9]{3,64}', request['account']):
                raise ValueError('invalid Kryptex account')
            reserve = request.get('reserve_cpu_percent')
            if type(reserve) is not int or not 1 <= reserve <= 50:
                raise ValueError('CPU reserve must be an integer from 1 to 50')
        if set(request) != allowed:
            raise ValueError('missing or unknown request fields')

    def _preflight(self, manifest):
        if manifest['pool_host'] != 'prl.kryptex.network' or manifest['pool_port'] != 8048:
            raise ValueError('relay requires the official PRL Kryptex TLS pool')
        if 'xmr_pool_host' in manifest and (manifest['xmr_pool_host'], manifest['xmr_pool_port']) != ('xmr.kryptex.network', 8029):
            raise ValueError('refusing to replace a custom XMR pool')
        expected = {render_haproxy(candidate, config_dir=str(self.config_dir))
                    for candidate in (manifest, expanded_manifest(manifest))}
        if self.config_path.read_text(encoding='utf-8') not in expected:
            raise ValueError('active HAProxy configuration has unmanaged drift')
        for name in ('ca.crt', 'server.pem'):
            if (self.config_dir / name).read_bytes() != (self.pki / name).read_bytes():
                raise ValueError('installed relay certificate differs from private PKI')
        if self.service_path.is_symlink():
            raise ValueError('unmanaged service unit')
        unit = self.service_path.read_text(encoding='utf-8')
        if unit != MANAGED_UNIT:
            raise ValueError('unmanaged service unit')
        fragment = self._command(['systemctl', 'show', 'prl-fleet.service', '--property=FragmentPath', '--value']).stdout.strip()
        overrides = self._command(['systemctl', 'show', 'prl-fleet.service', '--property=DropInPaths', '--value']).stdout.strip()
        if fragment != str(self.service_path) or overrides:
            raise ValueError('unmanaged service unit or overrides')

    def _password(self):
        path = self.base / 'ca-passphrase'
        if path.is_symlink():
            raise ValueError('CA passphrase cannot be a symbolic link')
        if os.name == 'posix' and (path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid()):
            raise ValueError('CA passphrase must be private and owned by the provisioning user')
        return path.read_text(encoding='utf-8').rstrip('\r\n')

    def _allocate(self, manifest, request):
        occupied = {row['id'] for row in manifest['instances']}
        occupied |= {path.stem for path in (self.pki / 'clients').glob('*.pem')}
        occupied |= {path.name for path in (self.fleet / 'clients').glob('*')}
        for path in self.operations.glob('*.json'):
            occupied.add(self._read_json(path)['instance_id'])
        for line in (self.pki / 'index.txt').read_text(encoding='ascii').splitlines():
            match = re.search(r'/CN=([a-z][a-z0-9_-]{0,31})$', line)
            if match:
                occupied.add(match.group(1))
        occupied.discard('monitor-panel')
        occupied.discard('relay.prl.internal')
        if len(occupied) >= 1024:
            raise ValueError('relay identity capacity exhausted')
        number = 1
        while f'gpu{number:04d}' in occupied:
            number += 1
        state = {key: request[key] for key in ('operation_id', 'spec_hash', 'account', 'reserve_cpu_percent')}
        state.update(instance_id=f'gpu{number:04d}', status='allocated')
        # Durable reservation precedes every PKI mutation.
        _atomic_write(self.operations / (request['operation_id'] + '.json'), _json_bytes(state))
        return state

    def _refresh_crl(self, password):
        expiry = _openssl(self.pki, 'crl', '-in', 'crl.pem', '-noout', '-nextupdate').decode().strip().split('=', 1)[1]
        next_update = datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        if next_update <= datetime.now(timezone.utc) + timedelta(days=7):
            refresh_crl(self.pki, password)
            return True
        return False

    def _credentials(self, state):
        identity = state['instance_id']
        password = self._password()
        self._refresh_crl(password)
        certificate = self.pki / 'clients' / (identity + '.pem')
        if not certificate.exists():
            if _certificate_status(self.pki / 'index.txt', identity) is not None:
                raise ValueError('reserved certificate is missing; refusing to reissue identity')
            issue_client(self.pki, identity, password)
        if _certificate_status(self.pki / 'index.txt', identity) != 'V':
            raise ValueError('reserved identity is not active')
        client = self.fleet / 'clients' / identity
        _directory(self.fleet / 'clients')
        _directory(client)
        for name, source in (('ca.crt', self.pki / 'ca.crt'), ('client.pem', certificate), ('crl.pem', self.pki / 'crl.pem')):
            _atomic_write(client / name, source.read_bytes())
        verify_credentials(client, identity)
        _openssl(client, 'verify', '-CAfile', 'ca.crt', '-CRLfile', 'crl.pem', '-crl_check', '-purpose', 'sslclient', 'client.pem')
        return client

    def _bundle(self, state, manifest, client):
        output = self.bundles / state['operation_id']
        if output.is_symlink():
            raise ValueError('bundle cannot be a symbolic link')
        if output.exists():
            settings = self._read_json(output / 'settings.json')
            for key in ('instance_id', 'account', 'reserve_cpu_percent'):
                if settings.get(key) != state[key]:
                    raise ValueError('cached bundle does not match operation')
            for name in ('ca.crt', 'client.pem'):
                if (output / name).read_bytes() != (client / name).read_bytes():
                    raise ValueError('cached bundle credentials differ from PKI')
            if (settings.get('relay_ip'), settings.get('relay_port')) != (manifest['relay_ip'], manifest['relay_port']):
                raise ValueError('cached bundle relay address changed')
            return output
        with tempfile.TemporaryDirectory(prefix='.bundle-input-', dir=self.automation) as temporary:
            stage = Path(temporary)
            stage.chmod(0o700)
            _atomic_write(stage / 'manifest.json', _json_bytes(manifest))
            staged_client = stage / 'clients' / state['instance_id']
            _directory(stage / 'clients')
            _directory(staged_client)
            for name in ('ca.crt', 'client.pem'):
                _atomic_write(staged_client / name, (client / name).read_bytes())
            generate_dual(stage, state['instance_id'], state['account'], output,
                          reserve_cpu_percent=state['reserve_cpu_percent'])
        return output

    def _activate(self, changes):
        if self.service_path in changes:
            self._command(['systemctl', 'daemon-reload'])
        if self.config_path in changes or self.config_dir / 'crl.pem' in changes or self.service_path in changes:
            self._command(['systemctl', 'restart', 'prl-fleet.service'])
            self._command(['systemctl', 'is-active', '--quiet', 'prl-fleet.service'])
        if self.registry_path in changes:
            self._command(['systemctl', 'restart', 'prl-monitor.service'])
            self._command(['systemctl', 'is-active', '--quiet', 'prl-monitor.service'])

    def _rollback(self, journal):
        allowed = {self.manifest_path, self.config_path, self.registry_path, self.service_path, self.config_dir / 'crl.pem'}
        entries = journal['files']
        changes = {Path(entry['path']) for entry in entries}
        if not changes <= allowed:
            raise ValueError('invalid recovery journal paths')
        for entry in entries:
            path = Path(entry['path'])
            if path.read_bytes() not in (base64.b64decode(entry['old']), base64.b64decode(entry['new'])):
                raise ValueError('external drift prevents automatic transaction recovery')
        for entry in reversed(entries):
            _atomic_write(Path(entry['path']), base64.b64decode(entry['old']), preserve=True)
        self._activate(changes)
        self.journal.unlink()
        _sync_dir(self.automation)

    def _apply(self, desired):
        changes = {path: content for path, content in desired.items() if path.read_bytes() != content}
        if not changes:
            return
        # Validate as the service account, in / (root's cwd is not traversable).
        if self.config_path in changes or self.service_path in changes or self.config_dir / 'crl.pem' in changes:
            descriptor, name = tempfile.mkstemp(prefix='.provision-candidate-', dir=self.config_dir)
            os.close(descriptor)
            candidate = Path(name)
            try:
                _atomic_write(candidate, desired[self.config_path], mode=0o640)
                if os.name == 'posix':
                    metadata = self.config_path.stat()
                    os.chown(candidate, metadata.st_uid, metadata.st_gid)
                self._command(['runuser', '-u', 'prl-fleet', '--', '/usr/sbin/haproxy', '-c', '-f', str(candidate)])
            finally:
                candidate.unlink(missing_ok=True)
        journal = {'files': [
            {'path': str(path), 'old': base64.b64encode(path.read_bytes()).decode('ascii'),
             'new': base64.b64encode(content).decode('ascii')} for path, content in changes.items()]}
        _atomic_write(self.journal, _json_bytes(journal))
        try:
            for path, content in changes.items():
                _atomic_write(path, content, preserve=True)
            self._activate(set(changes))
        except Exception:
            self._rollback(journal)
            raise
        self.journal.unlink()
        _sync_dir(self.automation)

    def _prepare_directories(self):
        for path in (self.base, self.automation, self.operations, self.bundles):
            _directory(path)

    def maintain(self):
        """Renew and deploy the CRL; intended for the root-owned daily timer."""
        self._prepare_directories()
        with _lock(self.automation / 'allocation.lock'):
            if self.journal.exists():
                self._rollback(self._read_json(self.journal))
            manifest = validate_manifest(self._read_json(self.manifest_path))
            self._preflight(manifest)
            refreshed = self._refresh_crl(self._password())
            self._apply({self.config_path: self.config_path.read_bytes(),
                         self.service_path: MANAGED_UNIT.encode('utf-8'),
                         self.config_dir / 'crl.pem': (self.pki / 'crl.pem').read_bytes()})
            return {'status': 'ready', 'crl_refreshed': refreshed}

    def handle(self, request):
        self._request(request)
        self._prepare_directories()
        operation = request['operation_id']
        with _lock(self.automation / 'allocation.lock'):
            path = self.operations / (operation + '.json')
            state = self._read_json(path) if path.exists() else None
            if request['action'] == 'status':
                return ({'operation_id': operation, 'instance_id': state['instance_id'], 'status': state['status']}
                        if state else {'operation_id': operation, 'status': 'unknown'})
            if state and any(state[key] != request[key] for key in ('spec_hash', 'account', 'reserve_cpu_percent')):
                raise ValueError('operation already reserved with a different specification')
            if self.journal.exists():
                self._rollback(self._read_json(self.journal))
            manifest = validate_manifest(self._read_json(self.manifest_path))
            self._preflight(manifest)
            if state is None:
                state = self._allocate(manifest, request)
            identity = state['instance_id']
            if not re.fullmatch(r'gpu[0-9]{4,}', identity):
                raise ValueError('invalid reserved identity')
            state['status'] = 'allocated'
            _atomic_write(path, _json_bytes(state))
            client = self._credentials(state)
            if identity not in {row['id'] for row in manifest['instances']}:
                manifest['instances'].append({'id': identity, 'label': identity, 'allowed_ip': None})
            manifest.update(xmr_pool_host='xmr.kryptex.network', xmr_pool_port=8029)
            manifest = validate_manifest(manifest)
            bundle = self._bundle(state, manifest, client)
            registry = {'instances': [{'id': row['id'], 'label': row['label']} for row in manifest['instances']]}
            self._apply({self.manifest_path: _json_bytes(manifest),
                         self.config_path: render_haproxy(expanded_manifest(manifest), config_dir=str(self.config_dir)).encode('utf-8'),
                         self.registry_path: _json_bytes(registry),
                         self.service_path: MANAGED_UNIT.encode('utf-8'),
                         self.config_dir / 'crl.pem': (self.pki / 'crl.pem').read_bytes()})
            state['status'] = 'ready'
            _atomic_write(path, _json_bytes(state))
            return {'operation_id': operation, 'instance_id': identity,
                    'cloud_init_b64': base64.b64encode((bundle / 'cloud-init.yaml').read_bytes()).decode('ascii')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir', required=True, type=Path)
    parser.add_argument('--maintain', action='store_true', help='renew CRL when needed; root timer use only')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if os.name != 'posix' or os.geteuid() != 0:
            raise ValueError('provisioning requires root on the relay')
        provisioner = Provisioner(args.base_dir)
        if args.maintain:
            result = provisioner.maintain()
        else:
            raw = sys.stdin.buffer.read(16385)
            if len(raw) > 16384:
                raise ValueError('request too large')
            result = provisioner.handle(json.loads(raw))
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, KeyError, TypeError):
        # Avoid printing raw exceptions: filesystem paths and third-party error
        # output may contain private material. Detailed diagnostics stay local.
        print(json.dumps({'error': 'relay provisioning failed; check relay configuration and operation state'}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
