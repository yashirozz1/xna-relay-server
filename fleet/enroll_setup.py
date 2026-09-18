#!/usr/bin/env python3
"""Create a private reusable mining installer and its restricted SSH credential."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dual.enroll import regular, write_private
from dual_bundle import cloud_config

ENROLL = '/var/lib/xna-dual-enroll'
KEY_COMMENT = 'xna-mining-enrollment'
SOURCES = ('dual/install.py', 'dual/enroll.py', 'dual_bundle.py', 'fleet_bundle.py',
           'relay_bundle.py', 'fleet/__init__.py', 'fleet/pki.py',
           'fleet/enroll_gateway.py', 'fleet/azure_provision.py', 'fleet/templates/prl-fleet.service')
UNIT = '''[Unit]
Description=XNA automatic enrollment and PRL GPU + XMR CPU mining setup
Wants=network-online.target
After=network-online.target cloud-final.service
StartLimitIntervalSec=0
ConditionPathExists=!/var/lib/xna-dual-enroll/ready

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /var/lib/xna-dual-enroll/enroll.py
RemainAfterExit=yes
Restart=on-failure
RestartSec=60
TimeoutStartSec=2400
UMask=0077

[Install]
WantedBy=multi-user.target
'''


def authorized_keys(original, public, command):
    key_type, blob, *_ = public.strip().split()
    if key_type != 'ssh-ed25519' or not re.fullmatch('[A-Za-z0-9+/=]+', blob):
        raise ValueError('invalid enrollment public key')
    if '\n' in command or '\r' in command:
        raise ValueError('invalid forced command')
    escaped = command.replace('\\', '\\\\').replace('"', '\\"')
    new = f'restrict,command="{escaped}" {key_type} {blob} {KEY_COMMENT}'
    rows = []
    for line in original.splitlines():
        if re.search(r'(?:^|\s)' + re.escape(key_type + ' ' + blob) + r'(?:\s|$)', line):
            if not line.endswith(' ' + KEY_COMMENT):
                raise ValueError('enrollment key already has an unmanaged authorization')
            continue
        rows.append(line)
    rows.append(new)
    return '\n'.join(rows) + '\n'


def shell_installer(files):
    payload = base64.b64encode(json.dumps({path: base64.b64encode(data).decode()
                                         for path, data in files.items()}).encode()).decode()
    return '''#!/bin/bash
# PRIVATE: contains a restricted enrollment credential. Do not publish.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "Execute com sudo bash install-miners.sh" >&2; exit 1; fi
command -v python3 >/dev/null
command -v ssh >/dev/null
python3 - <<'XNA_PRIVATE_BOOTSTRAP'
import base64,json,os,tempfile
from pathlib import Path
os.umask(0o077)
files=json.loads(base64.b64decode(''' + repr(payload) + '''))
for name,data in files.items():
    path=Path(name)
    for item in (path,*path.parents):
        if item.is_symlink(): raise SystemExit('Unsafe bootstrap path')
    content=base64.b64decode(data,validate=True)
    if path.exists() and path.read_bytes()!=content:
        raise SystemExit('An existing mining bootstrap differs; refusing overwrite')
for name,data in files.items():
    path=Path(name)
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.xna-bootstrap-')
    with os.fdopen(fd,'wb') as stream:
        stream.write(base64.b64decode(data,validate=True));stream.flush();os.fsync(stream.fileno())
    os.chmod(tmp,0o600);os.replace(tmp,path)
XNA_PRIVATE_BOOTSTRAP
systemctl daemon-reload
systemctl enable xna-dual-bootstrap.service
cloud_state="$(systemctl show --property=ActiveState --value cloud-final.service)"
if [[ "$cloud_state" = activating || "$cloud_state" = active || "$cloud_state" = reloading ]]; then
  systemctl start --no-block xna-dual-bootstrap.service
  echo "Instalacao automatica agendada para depois do cloud-init."
else
  systemctl start xna-dual-bootstrap.service
  echo "Instalacao concluida. Hostname: $(hostname). Servicos: xna-dual-prl e xna-dual-xmr."
fi
'''


def snapshot(base):
    contents = {name: (ROOT / name).read_bytes() for name in SOURCES}
    digest = hashlib.sha256()
    for name, data in contents.items():
        digest.update(name.encode() + b'\0' + data)
    version = digest.hexdigest()[:20]
    releases = regular(base / 'enrollment/releases')
    releases.mkdir(parents=True, mode=0o700, exist_ok=True)
    destination = regular(releases / version)
    if destination.exists():
        if any(regular(destination / name).read_bytes() != data for name, data in contents.items()):
            raise ValueError('immutable enrollment release was modified')
        return destination
    temporary = Path(tempfile.mkdtemp(prefix='.release-', dir=releases))
    try:
        for name, data in contents.items():
            path = temporary / name
            path.parent.mkdir(parents=True, exist_ok=True)
            write_private(path, data)
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return destination


def maintenance_units(base, release):
    service = f'''# Managed by XNA mining enrollment
[Unit]
Description=XNA relay certificate revocation list renewal
After=network-online.target prl-fleet.service

[Service]
Type=oneshot
User=root
WorkingDirectory={str(release).replace('%', '%%')}
ExecStart=/usr/bin/python3 -m fleet.azure_provision --base-dir {json.dumps(str(base))} --maintain
UMask=0077
'''
    timer = '''# Managed by XNA mining enrollment
[Unit]
Description=Daily XNA relay certificate maintenance

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
'''
    return {'xna-relay-maintenance.service': service, 'xna-relay-maintenance.timer': timer}


def install_maintenance(base, release):
    for name, content in maintenance_units(base, release).items():
        path = regular('/etc/systemd/system/' + name)
        if path.exists() and not path.read_text().startswith('# Managed by XNA mining enrollment\n'):
            raise ValueError('unmanaged maintenance unit already exists')
        write_private(path, content.encode())
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'xna-relay-maintenance.timer'], check=True)
    subprocess.run(['systemctl', 'is-active', '--quiet', 'xna-relay-maintenance.timer'], check=True)


def setup(base, output, account, reserve=10, relay_port=22, authorized=None, host_public=None):
    if not re.fullmatch('krx[A-Za-z0-9]{3,64}', account) or type(reserve) is not int or not 1 <= reserve <= 50:
        raise ValueError('invalid account/CPU reservation')
    if type(relay_port) is not int or not 1 <= relay_port <= 65535:
        raise ValueError('invalid relay SSH port')
    base, output = regular(base), regular(output)
    manifest = json.loads((base / 'fleet/manifest.json').read_text())
    relay = str(ipaddress.IPv4Address(manifest['relay_ip']))
    installer = (ROOT / 'dual/install.py').read_bytes()
    enrolled = (ROOT / 'dual/enroll.py').read_bytes()
    release = snapshot(base)
    version = hashlib.sha256((release.name + account + str(reserve) + relay + str(relay_port)).encode()).hexdigest()[:16]
    secrets_dir = regular(base / 'enrollment')
    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = regular(secrets_dir / ('bootstrap-' + version))
    if not key.exists():
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', KEY_COMMENT,
                        '-f', str(key)], check=True)
    key.chmod(0o600)
    public = subprocess.run(['ssh-keygen', '-y', '-f', str(key)], check=True,
                            capture_output=True, text=True).stdout.strip()
    host_key = Path(host_public or '/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
    if len(host_key) < 2 or host_key[0] != 'ssh-ed25519':
        raise ValueError('expected an Ed25519 SSH host key')
    host = relay if relay_port == 22 else f'[{relay}]:{relay_port}'
    settings = dict(version=1, relay_host=relay, relay_port=relay_port,
                    installer_sha256=hashlib.sha256(installer).hexdigest())
    files = {ENROLL + '/enroll.py': enrolled, ENROLL + '/enrollment.key': key.read_bytes(),
             ENROLL + '/known_hosts': f'{host} {host_key[0]} {host_key[1]}\n'.encode(),
             ENROLL + '/settings.json': json.dumps(settings).encode(),
             '/etc/systemd/system/xna-dual-bootstrap.service': UNIT.encode()}
    artifacts = {'cloud-init.yaml': cloud_config(files).encode(),
                 'install-miners.sh': shell_installer(files).encode()}
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, data in artifacts.items():
        path = regular(output / name)
        if path.exists() and path.read_bytes() != data:
            raise ValueError('output exists from another version; use a new output directory')
    target = regular(authorized or Path('/root/.ssh/authorized_keys'))
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = shlex.join(['/usr/bin/python3', str(release / 'fleet/enroll_gateway.py'),
                         '--base-dir', str(base), '--account', account, '--reserve-cpu-percent', str(reserve)])
    content = authorized_keys(target.read_text() if target.exists() else '', public, command)
    write_private(target, content.encode())
    for name, data in artifacts.items():
        write_private(output / name, data)
    print('Private reusable installer: ' + str(output / 'install-miners.sh'))
    print('Private reusable cloud-init: ' + str(output / 'cloud-init.yaml'))
    print('Credential is restricted to enrollment; no shell or forwarding is authorized.')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--reserve-cpu-percent', type=int, default=10)
    parser.add_argument('--ssh-port', type=int, default=22)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError('setup must run as root on the relay')
        os.umask(0o077)
        setup(args.base_dir, args.output, args.account, args.reserve_cpu_percent, args.ssh_port)
        install_maintenance(args.base_dir, snapshot(args.base_dir))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
