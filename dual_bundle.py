#!/usr/bin/env python3
"""Generate a private Azure cloud-init/package for one authenticated mining VM."""
import argparse
import base64
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from fleet.pki import _openssl_command
from fleet_bundle import ID_PATTERN, validate_manifest

ROOT = Path(__file__).resolve().parent
BOOTSTRAP = '/var/lib/xna-dual-bootstrap'
UNIT = '''[Unit]
Description=XNA dual mining first-boot installer
Wants=network-online.target
After=network-online.target cloud-final.service
StartLimitIntervalSec=0
ConditionPathExists=!/var/lib/xna-dual-miner/complete

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /var/lib/xna-dual-bootstrap/install.py --bundle-dir /var/lib/xna-dual-bootstrap
RemainAfterExit=yes
Restart=on-failure
RestartSec=60
TimeoutStartSec=1800
UMask=0077

[Install]
WantedBy=multi-user.target
'''


def _openssl(directory, *arguments):
    command, cwd = _openssl_command(directory, arguments)
    result = subprocess.run(command, cwd=cwd, input=b'', capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('Certificado/chave invalidos: ' + result.stderr.decode(errors='replace')[-500:])
    return result.stdout


def verify_credentials(directory, identity):
    """Validate trust, identity, expiry and possession without printing private keys."""
    _openssl(directory, 'verify', '-CAfile', 'ca.crt', '-purpose', 'sslclient', 'client.pem')
    _openssl(directory, 'x509', '-in', 'client.pem', '-noout', '-checkend', '86400')
    subject = _openssl(directory, 'x509', '-in', 'client.pem', '-noout', '-subject',
                       '-nameopt', 'RFC2253').decode().strip().removeprefix('subject=')
    if not re.search(r'(?:^|,)CN=' + re.escape(identity) + r'(?:,|$)', subject):
        raise ValueError('CN do certificado nao corresponde ao ID da VM')
    public_key = _openssl(directory, 'pkey', '-in', 'client.pem', '-pubout').strip()
    certificate_key = _openssl(directory, 'x509', '-in', 'client.pem', '-pubkey', '-noout').strip()
    if public_key != certificate_key:
        raise ValueError('Chave privada nao corresponde ao certificado')


def cloud_config(files):
    entries = []
    for path, content in files.items():
        entries.append({'path': path, 'owner': 'root:root', 'permissions': '0600',
                        'encoding': 'gz+b64',
                        'content': base64.b64encode(gzip.compress(content, mtime=0)).decode('ascii')})
    document = {'write_files': entries,
                'runcmd': [['systemctl', 'daemon-reload'],
                           ['systemctl', 'enable', '--now', '--no-block', 'xna-dual-bootstrap.service']]}
    content = '#cloud-config\n' + json.dumps(document, indent=2) + '\n'
    if len(content.encode('utf-8')) > 65535:
        raise ValueError('cloud-init excede o limite de 64 KiB do Azure')
    return content


def generate_dual(fleet_dir, instance_id, account, output, *, reserve_cpu_percent=10, installer=None):
    fleet_dir, output = Path(fleet_dir).absolute(), Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError('Pasta de saida ja existe: ' + str(output))
    if not isinstance(instance_id, str) or not ID_PATTERN.fullmatch(instance_id) or instance_id == 'monitor-panel':
        raise ValueError('ID de cliente invalido')
    if not isinstance(account, str) or not re.fullmatch(r'krx[A-Za-z0-9]{3,64}', account):
        raise ValueError('Use o ID da conta Kryptex, no formato krx..., sem worker')
    if type(reserve_cpu_percent) is not int or not 1 <= reserve_cpu_percent <= 50:
        raise ValueError('reserve_cpu_percent deve estar entre 1 e 50')
    manifest = validate_manifest(json.loads((fleet_dir / 'manifest.json').read_text(encoding='utf-8')))
    if instance_id not in {item['id'] for item in manifest['instances']}:
        raise ValueError('ID nao cadastrado no manifesto do relay')
    if manifest['pool_host'] != 'prl.kryptex.network' or manifest['pool_port'] != 8048:
        raise ValueError('Este instalador requer a pool PRL Kryptex na porta TLS 8048')
    if manifest.get('xmr_pool_host') != 'xmr.kryptex.network' or manifest.get('xmr_pool_port') != 8029:
        raise ValueError('Habilite a rota XMR Kryptex (xmr_pool_host/xmr_pool_port) no relay antes de gerar os clientes')
    client = fleet_dir / 'clients' / instance_id
    files = {}
    for name in ('ca.crt', 'client.pem'):
        source = client / name
        if source.is_symlink() or not source.is_file():
            raise FileNotFoundError('Arquivo ausente ou link: ' + str(source))
        files[name] = source.read_bytes()
    verify_credentials(client, instance_id)
    files['settings.json'] = (json.dumps({'version': 1, 'instance_id': instance_id,
        'relay_ip': manifest['relay_ip'], 'relay_port': manifest['relay_port'],
        'account': account, 'reserve_cpu_percent': reserve_cpu_percent}, indent=2) + '\n').encode()
    files['install.py'] = Path(installer or ROOT / 'dual/install.py').read_bytes()
    cloud_files = {BOOTSTRAP + '/' + name: content for name, content in files.items()}
    cloud_files['/etc/systemd/system/xna-dual-bootstrap.service'] = UNIT.encode()
    files['cloud-init.yaml'] = cloud_config(cloud_files).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.dual-', dir=output.parent))
    try:
        stage.chmod(0o700)
        for name, content in files.items():
            target = stage / name
            target.write_bytes(content)
            target.chmod(0o600)
        stage.rename(output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fleet-dir', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--instance-id')
    selection.add_argument('--all', action='store_true', help='gerar uma pasta por ID cadastrado')
    parser.add_argument('--account', required=True)
    parser.add_argument('--reserve-cpu-percent', type=int, default=10)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.all:
            if args.output.exists() or args.output.is_symlink():
                raise FileExistsError('Use uma nova pasta de saida')
            manifest = validate_manifest(json.loads((args.fleet_dir / 'manifest.json').read_text()))
            for row in manifest['instances']:
                path = generate_dual(args.fleet_dir, row['id'], args.account, args.output / row['id'],
                                     reserve_cpu_percent=args.reserve_cpu_percent)
                print(path / 'cloud-init.yaml')
        else:
            path = generate_dual(args.fleet_dir, args.instance_id, args.account, args.output,
                                 reserve_cpu_percent=args.reserve_cpu_percent)
            print(path / 'cloud-init.yaml')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print('Arquivos PRIVADOS: uma identidade por VM; nao publicar em Git, logs ou URLs publicas.')


if __name__ == '__main__':
    main()
