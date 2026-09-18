#!/usr/bin/env python3
"""Pinned Ubuntu 24.04 dual-miner bootstrap. --check is entirely read-only.

State claims the managed namespace before any installation changes. Repeating an
interrupted installation is permitted only with the identical settings and PEMs.
Nothing in this program changes NVIDIA driver, firmware, or security settings.
"""
import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

STATE = Path('/var/lib/xna-dual-miner')
OPT = Path('/opt/xna-dual-miner')
ETC = Path('/etc/xna-dual-miner')
UNITS = Path('/etc/systemd/system')
SERVICES = ('xna-dual-tunnel', 'xna-dual-prl', 'xna-dual-xmr')
PORTS = (8048, 17029, 17429, 12000, 18089)
ARTIFACTS = {
    'krig': ('https://github.com/kryptex/krig-miner/releases/download/v1.5.1/krig-miner-1.5.1-linux-x64.tar.gz',
             'dbd6c69488e33777d839394b8f59b785b03fd44748d57f45da431e5d46f48663', 'krig-miner'),
    'alfa': ('https://github.com/yashirozz1/xna.alfa-miner-zero-fee/releases/download/v6.26.0-zero-fee-linux/alfa-miner-cpu-6.26.0-zero-fee-linux-x64.tar.gz',
             'd613201496cebc4eea4e83038a6334dc58b82f654064552cdfdcd4d581a78c2e',
             'alfa-miner-cpu-6.26.0-zero-fee-linux-x64/alfa-miner-cpu'),
}


def run(*args, input=None, check=True, env=None):
    """No shell and no credential contents in diagnostics."""
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, env=env)
    if check and result.returncode:
        raise ValueError(f'{args[0]} failed ({result.returncode}): '
                         + result.stderr.decode(errors='replace')[-1600:])
    return result


def validate_settings(data):
    keys = {'version', 'instance_id', 'relay_ip', 'relay_port', 'account', 'reserve_cpu_percent'}
    if not isinstance(data, dict) or set(data) != keys:
        raise ValueError('settings.json must contain exactly the documented settings')
    for key, lo, hi in [('version', 1, 1), ('relay_port', 1, 65535), ('reserve_cpu_percent', 1, 50)]:
        if type(data[key]) is not int or not lo <= data[key] <= hi:
            raise ValueError(f'invalid {key}')
    for key, pattern in [('instance_id', r'[a-z][a-z0-9_-]{0,31}'),
                         ('account', r'krx[A-Za-z0-9]{3,64}')]:
        if not isinstance(data[key], str) or not re.fullmatch(pattern, data[key]):
            raise ValueError(f'invalid {key}')
    if data['instance_id'] == 'monitor-panel':
        raise ValueError('monitor-panel is not a mining identity')
    if not isinstance(data['relay_ip'], str):
        raise ValueError('relay_ip must be an IPv4 address')
    address = ipaddress.ip_address(data['relay_ip'])
    if address.version != 4 or address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError('relay_ip must be a unicast, non-loopback IPv4 address')
    return data


def no_symlinks(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError(f'symlink is not allowed: {item}')
    return path


def read_regular(path, limit=1024 * 1024):
    path = no_symlinks(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f'expected a small regular file: {path}')
    return path.read_bytes()


def load_bundle(path):
    path = no_symlinks(path)
    settings = validate_settings(json.loads(read_regular(path / 'settings.json')))
    ca = read_regular(path / 'ca.crt')
    client = read_regular(path / 'client.pem')
    # openssl reads the first certificate and private key from the combined PEM.
    run('openssl', 'verify', '-purpose', 'sslclient', '-CAfile', str(path / 'ca.crt'),
        str(path / 'client.pem'))
    subject = run('openssl', 'x509', '-in', str(path / 'client.pem'), '-noout',
                  '-subject', '-nameopt', 'RFC2253').stdout.decode().strip()
    common_names = re.findall(r'(?:^subject=|,)CN=([^,]+)', subject)
    if common_names != [settings['instance_id']]:
        raise ValueError('client certificate CN does not match instance_id')
    cert_key = run('openssl', 'x509', '-in', str(path / 'client.pem'), '-pubkey', '-noout').stdout
    private_key = run('openssl', 'pkey', '-in', str(path / 'client.pem'), '-passin', 'pass:', '-pubout').stdout
    if cert_key != private_key:
        raise ValueError('client certificate and private key do not match')
    return settings, ca, client


def validate_driver(version):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version.strip()):
        raise ValueError('unrecognized NVIDIA driver version')
    if tuple(map(int, version.strip().split('.'))) < (580, 65, 6):
        raise ValueError('NVIDIA driver 580.65.06 or newer is required; install it separately')


def cpu_plan(rows, reserve):
    nodes = {}
    seen = set()
    for row in sorted(rows, key=lambda row: int(row['cpu'])):
        if row.get('online') not in (True, 'yes', 'Y', 1):
            continue
        node, core, cpu = int(row['node']), (int(row['socket']), int(row['core'])), int(row['cpu'])
        if node < 0 or cpu < 0:
            raise ValueError('NUMA topology is unavailable')
        if core not in seen:
            seen.add(core)
            nodes.setdefault(node, []).append(cpu)
    plan = {node: cpus[math.ceil(len(cpus) * reserve / 100):] for node, cpus in nodes.items()}
    if not plan or any(not cpus for cpus in plan.values()):
        raise ValueError('not enough physical CPU cores to honor the per-NUMA reservation')
    return plan


def hardware(settings):
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                   if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise ValueError('only Ubuntu 24.04 is supported')
    if platform.machine() != 'x86_64':
        raise ValueError('only x86_64 is supported')
    gpus = run('nvidia-smi', '--query-gpu=index,name,driver_version', '--format=csv,noheader').stdout.decode().splitlines()
    if not gpus:
        raise ValueError('nvidia-smi reported no working GPUs')
    for gpu in gpus:
        validate_driver(gpu.rsplit(',', 1)[-1].strip())
    rows = json.loads(run('lscpu', '--json', '--extended=CPU,NODE,SOCKET,CORE,ONLINE').stdout)['cpus']
    return gpus, cpu_plan(rows, settings['reserve_cpu_percent'])


def state_identity(settings, ca, client):
    return dict(settings=settings, ca_sha256=hashlib.sha256(ca).hexdigest(),
                client_sha256=hashlib.sha256(client).hexdigest())


def validate_resume(state, identity):
    if not isinstance(state, dict) or state.get('identity') != identity:
        raise ValueError('existing installation identity/settings/credentials differ; refusing overwrite')


def verify_checksum(path, expected):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError(f'SHA256 mismatch: {Path(path).name}; no miner will be started')


def extract_artifact(archive, binary, target):
    """Validate the entire archive, then copy selected bytes, never tar.extract."""
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        seen = set()
        selected = []
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or '\\' in member.name:
                raise ValueError('unsafe archive path')
            if not member.isfile() and not member.isdir():
                raise ValueError('archive contains a link or special file')
            normalized = str(path)
            if normalized in seen:
                raise ValueError('duplicate archive path')
            seen.add(normalized)
            if member.isfile() and (normalized == binary or re.match(r'^(LICENSE|COPYING|NOTICE)([.-].*)?$', path.name, re.I)):
                if member.size > 512 * 1024 * 1024:
                    raise ValueError('archive member is unexpectedly large')
                selected.append(member)
        if sum(str(PurePosixPath(m.name)) == binary for m in selected) != 1:
            raise ValueError('archive does not contain the expected regular binary')
        target = no_symlinks(target)
        target.mkdir(parents=True, exist_ok=True)
        # cloud-init bootstrap uses UMask=0077; miners still need directory traversal.
        target.chmod(0o755)
        for member in selected:
            name = PurePosixPath(member.name).name
            destination = no_symlinks(target / name)
            with source.extractfile(member) as stream:
                atomic_write(destination, stream.read(), 0o755 if str(PurePosixPath(member.name)) == binary else 0o644)


def hugepage_plan(existing, current_group, xmrgid, owned, foreign=False):
    if not owned and (any(existing.values()) or current_group != 0 or foreign):
        if any(value < 1280 for value in existing.values()) or current_group == 0:
            raise ValueError('foreign huge-page reservations/group exist; configure >=1280 2MiB pages per mining NUMA node and a non-root hugetlb_shm_group, or use a fresh image')
        return dict(existing), current_group
    return {node: max(value, 1280) for node, value in existing.items()}, xmrgid


def atomic_write(path, content, mode=0o600, gid=None):
    path = no_symlinks(path)
    raw = content.encode() if isinstance(content, str) else content
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        if gid is not None:
            os.chown(temporary, 0, gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configs(settings, plan, prluid, supplemental_gid=None):
    peer = f"{settings['relay_ip']}:{settings['relay_port']}"
    ident = settings['account'] + '/' + settings['instance_id']
    mtls = f'''client = yes
verifyChain = yes
CAfile = {ETC}/ca.crt
cert = {ETC}/client.pem
checkHost = relay.prl.internal
connect = {peer}
'''
    stunnel = f'''foreground = yes
pid =
debug = notice
syslog = no

[prl]
accept = 127.0.0.1:8048
{mtls}sni = relay.prl.internal

[xmr-pool-tls]
client = yes
accept = 127.0.0.1:17029
connect = 127.0.0.1:17429
verifyChain = yes
CAfile = /etc/ssl/certs/ca-certificates.crt
checkHost = xmr.kryptex.network
sni = xmr.kryptex.network

[xmr-relay-mtls]
accept = 127.0.0.1:17429
{mtls}sni = xmr.relay.prl.internal
'''
    xmr = {'autosave': False, 'background': False, 'donate-level': 0,
           'log-file': None, 'print-time': 60,
           'http': {'enabled': True, 'host': '127.0.0.1', 'port': 18089, 'restricted': True},
           'randomx': {'init': 16, 'mode': 'auto', '1gb-pages': False,
                       'rdmsr': False, 'wrmsr': False, 'numa': True},
           'cpu': {'enabled': True, 'huge-pages': True, 'yield': True,
                   'rx': [cpu for cpus in plan.values() for cpu in cpus]},
           'opencl': False, 'cuda': False,
           'pools': [{'algo': 'rx/0', 'coin': 'monero', 'url': '127.0.0.1:17029',
                      'user': ident + '-cpu', 'pass': 'x', 'keepalive': True, 'tls': False}]}
    # Executed privileged only by this service's root-owned pre/post commands.
    redirect = f'''#!/bin/sh
set -eu
action="$1"
set -- OUTPUT -p tcp --dport 8048 -m owner --uid-owner {prluid} -m comment --comment xna-dual-prl -j REDIRECT --to-ports 8048
case "$action" in
start)
  /usr/sbin/iptables -w 30 -t nat -C "$@" 2>/dev/null || /usr/sbin/iptables -w 30 -t nat -A "$@"
  ;;
stop)
  while /usr/sbin/iptables -w 30 -t nat -C "$@" 2>/dev/null; do /usr/sbin/iptables -w 30 -t nat -D "$@"; done
  ;;
*) exit 2 ;;
esac
'''
    result = {'stunnel.conf': stunnel, 'xmr.json': json.dumps(xmr, indent=2) + '\n', 'redirect': redirect}
    commands = {
        'xna-dual-tunnel': f'/usr/bin/stunnel4 {ETC}/stunnel.conf',
        'xna-dual-prl': f'{OPT}/krig/krig-miner --coin pearl --url stratum+ssl://prl.kryptex.network:8048 --user {ident}-gpu --devices all --no-rocm --no-tui --gpu-no-reset-oc --api-host 127.0.0.1 --api-port 12000',
        'xna-dual-xmr': f'{OPT}/alfa/alfa-miner-cpu --config={ETC}/xmr.json',
    }
    for name, command in commands.items():
        description = {'xna-dual-tunnel': 'XNA mining authenticated relay tunnels',
                       'xna-dual-prl': 'XNA PRL GPU mining (KRig)',
                       'xna-dual-xmr': 'XNA XMR CPU mining (Alfa)'}[name]
        extra = ''
        dependencies = 'Wants=network-online.target\nAfter=network-online.target\n'
        if name != 'xna-dual-tunnel':
            # Miners retry their local sockets even when a tunnel start fails.
            # Requires would skip starting them and not re-enqueue them later.
            dependencies += 'Wants=xna-dual-tunnel.service\nAfter=xna-dual-tunnel.service\n'
        if name == 'xna-dual-prl':
            extra = f'ExecStartPre=+{OPT}/redirect start\nExecStopPost=+{OPT}/redirect stop\n'
        if name == 'xna-dual-xmr':
            extra += 'LimitMEMLOCK=infinity\n'
            if supplemental_gid:
                extra += f'SupplementaryGroups={supplemental_gid}\n'
        result[name + '.service'] = f'''# Managed by xna-dual-miner; identity {settings['instance_id']}
[Unit]
Description={description}
{dependencies}StartLimitIntervalSec=0

[Service]
Type=simple
User={name}
Group={name}
{extra}ExecStart={command}
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
'''
    return result


def installed_state(identity):
    no_symlinks(STATE)
    if not STATE.exists():
        return None
    if STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o022:
        raise ValueError('state directory must be root owned and not writable by other users')
    state = json.loads(read_regular(STATE / 'state.json'))
    validate_resume(state, identity)
    return state


def owned_directory(path, identity_id):
    path = no_symlinks(path)
    if not path.exists():
        temporary = Path(tempfile.mkdtemp(prefix='.' + path.name + '.', dir=path.parent))
        try:
            atomic_write(temporary / '.xna-dual-owner', identity_id + '\n', 0o644)
            temporary.chmod(0o755)
            os.rename(temporary, path)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    if read_regular(path / '.xna-dual-owner').decode().strip() != identity_id:
        raise ValueError(f'unmanaged directory or different identity: {path}')


def guard_unit(path, identity_id):
    no_symlinks(path)
    if path.exists():
        lines = read_regular(path).decode().splitlines()
        if not lines or lines[0] != f'# Managed by xna-dual-miner; identity {identity_id}':
            raise ValueError(f'unmanaged service unit: {path}')


def validate_listeners(proc_net, expected_uids):
    for line in proc_net.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[3] != '0A':
            continue
        port = int(fields[1].rsplit(':', 1)[1], 16)
        if port in PORTS and (port not in expected_uids or int(fields[7]) != expected_uids[port]):
            raise ValueError(f'port {port} has an unmanaged listener')


def preflight_resume(settings):
    import pwd
    for path in (OPT, ETC):
        if path.exists() or path.is_symlink():
            owned_directory(path, settings['instance_id'])
    for name in SERVICES:
        guard_unit(UNITS / (name + '.service'), settings['instance_id'])
        override = UNITS / (name + '.service.d')
        if override.exists() or override.is_symlink():
            raise ValueError(f'unmanaged service overrides: {override}')
    expected_uids = {}
    for name, ports in [('xna-dual-tunnel', (8048, 17029, 17429)),
                        ('xna-dual-prl', (12000,)), ('xna-dual-xmr', (18089,))]:
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            continue
        if account.pw_gecos != 'xna-dual-miner/' + settings['instance_id']:
            raise ValueError(f'unmanaged existing user: {name}')
        expected_uids.update({port: account.pw_uid for port in ports})
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        if Path(path).exists():
            validate_listeners(Path(path).read_text(), expected_uids)


def preflight_fresh():
    import pwd
    import grp
    for path in (OPT, ETC, *(UNITS / (name + '.service') for name in SERVICES)):
        no_symlinks(path)
        if path.exists():
            raise ValueError(f'unmanaged target already exists: {path}')
    for name in SERVICES:
        if (UNITS / (name + '.service.d')).exists():
            raise ValueError(f'unmanaged service overrides for {name}')
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise ValueError(f'unmanaged group already exists: {name}')
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise ValueError(f'unmanaged user already exists: {name}')
    for name in (*SERVICES, 'xna-prl-miner', 'xna-xmr-miner', 'prl-fleet-client'):
        loaded = run('systemctl', 'show', name + '.service', '--property=LoadState', '--value').stdout.decode().strip()
        if loaded != 'not-found':
            raise ValueError(f'existing mining service {name}; installation requires a fresh image')
    for port in PORTS:
        with socket.socket() as listener:
            try:
                listener.bind(('0.0.0.0', port))
            except OSError as error:
                raise ValueError(f'local port {port} is already in use') from error


def save_state(state):
    atomic_write(STATE / 'state.json', json.dumps(state, indent=2) + '\n')


def claim_state(identity):
    # Atomic directory rename leaves either no claim, or a complete identity.
    temporary = Path(tempfile.mkdtemp(prefix='.xna-dual-', dir=STATE.parent))
    try:
        atomic_write(temporary / 'state.json', json.dumps({'identity': identity, 'complete': False}) + '\n')
        os.rename(temporary, STATE)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return {'identity': identity, 'complete': False}


def ensure_user(name, identity_id):
    import pwd
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        run('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
            '--shell', '/usr/sbin/nologin', '--comment', 'xna-dual-miner/' + identity_id, name)
        account = pwd.getpwnam(name)
    if (account.pw_uid == 0 or account.pw_dir != '/nonexistent' or account.pw_shell != '/usr/sbin/nologin'
            or account.pw_gecos != 'xna-dual-miner/' + identity_id):
        raise ValueError(f'unexpected existing account attributes for {name}')
    return account


def download_artifact(name, spec):
    url, digest, member = spec
    archive = STATE / (name + '.tar.gz')
    no_symlinks(archive)
    if archive.exists():
        try:
            verify_checksum(archive, digest)
        except ValueError:
            archive.unlink()
    if not archive.exists():
        temporary = STATE / (name + '.download')
        no_symlinks(temporary)
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'xna-dual-bootstrap/1'})
            with urllib.request.urlopen(request, timeout=120) as response, open(temporary, 'wb') as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 512 * 1024 * 1024:
                        raise ValueError('download exceeds 512 MiB')
                    output.write(chunk)
            verify_checksum(temporary, digest)
            os.replace(temporary, archive)
        finally:
            if temporary.exists():
                temporary.unlink()
    verify_checksum(archive, digest)
    return archive


def hugepage_status(plan):
    return {node: int(Path(f'/sys/devices/system/node/node{node}/hugepages/hugepages-2048kB/nr_hugepages').read_text())
            for node in plan}


def configure_hugepages(plan, gid, state):
    existing = hugepage_status(plan)
    oldgroup = int(Path('/proc/sys/vm/hugetlb_shm_group').read_text())
    managed_paths = {Path(f'/sys/devices/system/node/node{node}/hugepages/hugepages-2048kB/nr_hugepages') for node in plan}
    foreign = any(int(path.read_text()) for path in Path('/sys/devices/system/node').glob(
        'node*/hugepages/hugepages-*/nr_hugepages') if path not in managed_paths)
    owned = (state.get('hugepages_owned', False) and oldgroup in (0, gid)) or (
        not any(existing.values()) and oldgroup == 0 and not foreign)
    target, group = hugepage_plan(existing, oldgroup, gid, owned, foreign)
    # Claim ownership before changing anything, so an interruption is resumable.
    state['hugepages_owned'] = owned
    save_state(state)
    if owned:
        Path('/proc/sys/vm/hugetlb_shm_group').write_text(str(group))
        for node, pages in target.items():
            Path(f'/sys/devices/system/node/node{node}/hugepages/hugepages-2048kB/nr_hugepages').write_text(str(pages))
        observed = hugepage_status(plan)
        if any(observed[n] < target[n] for n in target):
            raise ValueError('not enough free RAM for the required 2MiB huge pages; no miner was started')
    else:
        print(f'Respecting existing huge-page reservations and hugetlb group {group}.')
    return group


def install_packages():
    """Recover interrupted dpkg transactions without deleting or bypassing locks."""
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    apt = ('apt-get', '-o', 'DPkg::Lock::Timeout=300', '-o', 'Acquire::Retries=3')
    run(*apt, 'update', env=env)
    dpkg = ('dpkg', '--force-confdef', '--force-confold', '--configure', '-a')
    for attempt in range(61):
        result = run(*dpkg, env=env, check=False)
        diagnostic = result.stderr.decode(errors='replace').lower()
        if result.returncode and 'lock' in diagnostic and attempt < 60:
            time.sleep(5)
            continue
        break
    if result.returncode:
        # Interrupted unpack can leave dependencies incomplete. apt fixes them
        # using its own locks; --no-remove refuses unrelated package removal.
        run(*apt, '-f', 'install', '-y', '--no-remove', env=env)
        run(*dpkg, env=env)
    run(*apt, 'install', '-y', '--no-remove', '--no-install-recommends',
        'stunnel4', 'ca-certificates', 'openssl', 'curl', 'iptables', env=env)


def wait_services():
    stable, previous = 0, None
    for attempt in range(30):
        result = run('systemctl', 'show', *(name + '.service' for name in SERVICES),
                     '--property=ActiveState,NRestarts', check=False)
        lines = result.stdout.decode().splitlines()
        states = [line for line in lines if line.startswith('ActiveState=')]
        restarts = tuple(line for line in lines if line.startswith('NRestarts='))
        active = result.returncode == 0 and states == ['ActiveState=active'] * len(SERVICES)
        stable = stable + 1 if active and restarts == previous else (1 if active else 0)
        previous = restarts
        if stable >= 3:
            return
        time.sleep(2)
    raise ValueError('services did not stay active; inspect journalctl and rerun the same bundle')


def install(settings, ca, client, plan, identity):
    import fcntl
    if os.geteuid() != 0:
        raise ValueError('installation requires root; --check does not')
    no_symlinks('/run/xna-dual-miner.lock')
    with open('/run/xna-dual-miner.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = installed_state(identity)
        if state is None:
            preflight_fresh()
            state = claim_state(identity)
        else:
            preflight_resume(settings)
        # Download and verify BOTH archives before changing configs or starting services.
        archives = {name: download_artifact(name, spec) for name, spec in ARTIFACTS.items()}
        install_packages()
        accounts = {name: ensure_user(name, settings['instance_id']) for name in SERVICES}
        for path in (OPT, ETC):
            owned_directory(path, settings['instance_id'])
            if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                raise ValueError(f'managed path is not root-owned and protected: {path}')
        for name, archive in archives.items():
            extract_artifact(archive, ARTIFACTS[name][2], OPT / name)
        group = configure_hugepages(plan, accounts['xna-dual-xmr'].pw_gid, state)
        tunnel_gid = accounts['xna-dual-tunnel'].pw_gid
        atomic_write(ETC / 'ca.crt', ca, 0o644)
        atomic_write(ETC / 'client.pem', client, 0o640, tunnel_gid)
        generated = configs(settings, plan, accounts['xna-dual-prl'].pw_uid,
                            group if group != accounts['xna-dual-xmr'].pw_gid else None)
        for name, content in generated.items():
            if name.endswith('.service'):
                atomic_write(UNITS / name, content, 0o644)
            elif name == 'redirect':
                atomic_write(OPT / name, content, 0o755)
            else:
                atomic_write(ETC / name, content, 0o644)
        # Huge pages must also be restored at each boot before XMR starts.
        atomic_write(OPT / 'install.py', Path(__file__).read_bytes(), 0o755)
        atomic_write(ETC / 'settings.json', json.dumps(settings), 0o644)
        boot_unit = generated['xna-dual-xmr.service'].replace('ExecStart=',
            f'ExecStartPre=+/usr/bin/python3 {OPT}/install.py --restore-hugepages\nExecStart=')
        atomic_write(UNITS / 'xna-dual-xmr.service', boot_unit, 0o644)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', *(name + '.service' for name in SERVICES))
        run('systemctl', 'restart', 'xna-dual-tunnel.service')
        run('systemctl', 'restart', 'xna-dual-prl.service', 'xna-dual-xmr.service')
        wait_services()
        state['complete'] = True
        state['cpu_plan'] = plan
        save_state(state)
        atomic_write(STATE / 'complete', settings['instance_id'] + '\n')
        print('Bootstrap complete: all three services active. Accepted pool shares are not yet verified.')


def restore_hugepages():
    import pwd
    settings = validate_settings(json.loads(read_regular(ETC / 'settings.json')))
    state = json.loads(read_regular(STATE / 'state.json'))
    if state.get('identity', {}).get('settings') != settings:
        raise ValueError('installed settings do not match ownership state')
    _, plan = hardware(settings)
    configure_hugepages(plan, pwd.getpwnam('xna-dual-xmr').pw_gid, state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle-dir', type=Path)
    parser.add_argument('--check', action='store_true', help='read-only credentials, platform and hardware check')
    parser.add_argument('--restore-hugepages', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.restore_hugepages:
            if args.bundle_dir or args.check or os.geteuid() != 0:
                raise ValueError('invalid huge-page restoration invocation')
            restore_hugepages()
            return 0
        if not args.bundle_dir:
            parser.error('--bundle-dir is required')
        settings, ca, client = load_bundle(args.bundle_dir)
        gpus, plan = hardware(settings)
        identity = state_identity(settings, ca, client)
        installed_state(identity)
        print(json.dumps({'instance_id': settings['instance_id'], 'gpus': gpus,
                          'cpu_threads': sum(map(len, plan.values())), 'cpu_plan': plan,
                          'reserve_cpu_percent': settings['reserve_cpu_percent'],
                          'relay': f"{settings['relay_ip']}:{settings['relay_port']}",
                          'check_only': args.check}, indent=2))
        if not args.check:
            install(settings, ca, client, plan, identity)
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
