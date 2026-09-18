#!/usr/bin/env python3
"""Unattended, per-machine mining enrollment over a restricted SSH command."""
import argparse
import base64
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

BOOTSTRAP = '/var/lib/xna-dual-bootstrap'
FILES = ('install.py', 'settings.json', 'ca.crt', 'client.pem')


def operation_id(claim):
    if not isinstance(claim, str) or not re.fullmatch('[a-f0-9]{64}', claim):
        raise ValueError('invalid enrollment claim')
    return hashlib.sha256(('xna-mining-enrollment-v1:' + claim).encode()).hexdigest()


def regular(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('symlinks are not allowed in enrollment paths')
    return path


def write_private(path, data):
    path = regular(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def get_claim(state_dir, machine):
    state_dir = regular(state_dir)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = regular(state_dir / 'claim.json')
    if path.exists():
        data = json.loads(path.read_text())
        if data.get('machine') != machine:
            raise ValueError('enrollment belongs to another VM; use an image captured before mining enrollment')
        operation_id(data.get('claim'))
        return data['claim']
    claim = secrets.token_hex(32)
    write_private(path, json.dumps({'machine': machine, 'claim': claim}).encode())
    return claim


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != {'version', 'relay_host', 'relay_port', 'installer_sha256'}:
        raise ValueError('invalid enrollment settings')
    if type(settings['version']) is not int or settings['version'] != 1:
        raise ValueError('unsupported enrollment settings')
    ipaddress.IPv4Address(settings['relay_host'])
    if type(settings['relay_port']) is not int or not 1 <= settings['relay_port'] <= 65535:
        raise ValueError('invalid SSH port')
    if not re.fullmatch('[a-f0-9]{64}', settings['installer_sha256']):
        raise ValueError('invalid pinned installer checksum')
    return settings


def ssh_command(directory, settings):
    validate_settings(settings)
    return ['ssh', '-F', '/dev/null', '-T', '-p', str(settings['relay_port']),
            '-i', str(directory / 'enrollment.key'), '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(directory / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=20',
            '-o', 'ConnectionAttempts=1', '-o', 'LogLevel=ERROR',
            'root@' + settings['relay_host'], 'xna-mining-enroll']


def unpack(response, claim, settings):
    if not isinstance(response, dict) or response.get('operation_id') != operation_id(claim):
        raise ValueError('enrollment response does not match this VM')
    identity = response.get('instance_id')
    if not isinstance(identity, str) or not re.fullmatch('[a-z][a-z0-9_-]{0,31}', identity):
        raise ValueError('invalid assigned identity')
    encoded = response.get('cloud_init_b64')
    if not isinstance(encoded, str) or len(encoded) > 90000:
        raise ValueError('invalid enrollment bundle size')
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > 65535 or not raw.startswith(b'#cloud-config\n'):
        raise ValueError('invalid enrollment cloud-config')
    document = json.loads(raw.split(b'\n', 1)[1])
    entries = document.get('write_files', [])
    expected = {BOOTSTRAP + '/' + name for name in FILES}
    expected.add('/etc/systemd/system/xna-dual-bootstrap.service')
    if len(entries) != len(expected) or {row.get('path') for row in entries} != expected:
        raise ValueError('unexpected enrollment file destinations')
    files = {}
    for entry in entries:
        if entry.get('encoding') != 'gz+b64' or entry.get('permissions') != '0600' or entry.get('owner') != 'root:root':
            raise ValueError('unexpected enrollment file attributes')
        compressed = base64.b64decode(entry['content'], validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
            content = source.read(512 * 1024 + 1)
        if len(content) > 512 * 1024:
            raise ValueError('enrollment file exceeds size limit')
        if entry['path'].startswith(BOOTSTRAP + '/'):
            files[Path(entry['path']).name] = content
    if hashlib.sha256(files['install.py']).hexdigest() != settings['installer_sha256']:
        raise ValueError('installer differs from the version pinned in this bootstrap')
    miner_settings = json.loads(files['settings.json'])
    if miner_settings.get('instance_id') != identity or miner_settings.get('relay_ip') != settings['relay_host']:
        raise ValueError('assigned identity/relay does not match the bundle')
    return files


def enroll(directory, state_dir, bundle_dir, machine):
    directory, state_dir, bundle_dir = map(regular, (directory, state_dir, bundle_dir))
    settings = validate_settings(json.loads((directory / 'settings.json').read_text()))
    claim = get_claim(state_dir, machine)
    if not shutil.which('ssh'):
        raise ValueError('the Ubuntu image must include openssh-client')
    for name in ('enrollment.key', 'known_hosts'):
        path = regular(directory / name)
        if not path.is_file():
            raise ValueError('missing enrollment authentication files')
    # This response carries private client credentials; never echo it or log it.
    result = subprocess.run(ssh_command(directory, settings), input=json.dumps({'claim': claim}).encode(),
                            capture_output=True, timeout=360)
    if result.returncode:
        raise ValueError('relay enrollment failed: ' + result.stderr.decode(errors='replace')[-800:])
    if len(result.stdout) > 100000:
        raise ValueError('relay response exceeds size limit')
    files = unpack(json.loads(result.stdout), claim, settings)
    bundle_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in files.items():
        destination = regular(bundle_dir / name)
        if destination.exists() and destination.read_bytes() != content:
            raise ValueError('existing bundle differs; refusing to replace this VM identity')
    for name, content in files.items():
        write_private(bundle_dir / name, content)
    identity = json.loads(files['settings.json'])['instance_id']
    print('Mining identity assigned: ' + identity, flush=True)
    return identity


def hostname_hosts(original, previous, identity):
    if not re.fullmatch('[a-z][a-z0-9-]{0,31}', identity):
        raise ValueError('invalid mining hostname')
    lines, found = [], False
    for line in original.splitlines():
        body, sep, comment = line.partition('#')
        parts = body.split()
        if len(parts) > 1 and parts[0] == '127.0.1.1' and (previous in parts[1:] or identity in parts[1:]):
            aliases = [name for name in parts[1:] if name not in (previous, identity)]
            line = ' '.join(['127.0.1.1', identity, *aliases]) + (' #' + comment if sep else '')
            found = True
        lines.append(line)
    if not found:
        lines.append('127.0.1.1 ' + identity)
    return '\n'.join(lines) + '\n'


def configure_hostname(identity):
    hosts = Path('/etc/hosts')
    content = hostname_hosts(hosts.read_text(), socket.gethostname(), identity)
    policy = Path('/etc/cloud/cloud.cfg.d/99-xna-miner-hostname.cfg')
    policy.parent.mkdir(parents=True, exist_ok=True)
    data = b'# Managed by XNA mining bootstrap\npreserve_hostname: true\n'
    if policy.exists() and policy.read_bytes() != data:
        raise ValueError('existing hostname policy is unmanaged')
    write_private(policy, data)
    write_private(hosts, content.encode())
    hosts.chmod(0o644)
    subprocess.run(['hostnamectl', 'set-hostname', identity], check=True)


def mining_status(metrics, xmr):
    accepted = 0
    for line in metrics.splitlines():
        if line.startswith('krig_miner_blocks_submitted_total{') and 'result="accepted"' in line:
            accepted += int(float(line.rsplit(None, 1)[-1]))
    cpu = int(xmr.get('results', {}).get('shares_good', 0))
    return {'prl_accepted': accepted, 'xmr_accepted': cpu, 'ready': accepted > 0 and cpu > 0}


def wait_for_mining(timeout=900):
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    services = ('xna-dual-tunnel', 'xna-dual-prl', 'xna-dual-xmr')
    print('Waiting for accepted PRL GPU and XMR CPU shares...', flush=True)
    while time.monotonic() < deadline:
        try:
            with opener.open('http://127.0.0.1:12000/metrics', timeout=5) as response:
                metrics = response.read(1024 * 1024).decode()
            with opener.open('http://127.0.0.1:18089/2/summary', timeout=5) as response:
                xmr = json.load(response)
            status = mining_status(metrics, xmr)
            active = all(subprocess.run(['systemctl', 'is-active', '--quiet', service],
                                       capture_output=True).returncode == 0 for service in services)
            if status['ready'] and active:
                return status
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(15)
    raise ValueError('both miners have not accepted shares yet; bootstrap will retry automatically')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('/var/lib/xna-dual-enroll'))
    parser.add_argument('--enroll-only', action='store_true', help='prepare credentials without installing miners')
    args = parser.parse_args(argv)
    try:
        import fcntl
        if os.geteuid() != 0:
            raise ValueError('run the mining installer as root')
        os.umask(0o077)
        directory = regular(args.directory)
        directory.chmod(0o700)
        machine = Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
        if not re.fullmatch('[0-9a-f-]{36}', machine) or set(machine) <= {'0', '-'}:
            raise ValueError('unique VM hardware identity is unavailable')
        with open(regular(directory / 'enroll.lock'), 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            target = Path(BOOTSTRAP)
            identity = enroll(directory, directory, target, machine)
            if not args.enroll_only:
                configure_hostname(identity)
                complete = Path('/var/lib/xna-dual-miner/complete')
                if complete.exists():
                    if complete.read_text().strip() != identity:
                        raise ValueError('installed miner belongs to another identity')
                    subprocess.run(['systemctl', 'start', 'xna-dual-tunnel', 'xna-dual-prl', 'xna-dual-xmr'], check=True)
                else:
                    subprocess.run([sys.executable, str(target / 'install.py'), '--bundle-dir', str(target)], check=True)
                status = wait_for_mining()
                write_private(directory / 'ready', json.dumps(dict(instance_id=identity, **status)).encode())
                print('PRL GPU and XMR CPU mining confirmed: ' + json.dumps(status), flush=True)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
