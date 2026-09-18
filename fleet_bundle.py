#!/usr/bin/env python3
"""Build per-instance mTLS bundles and a read-only monitoring service."""
import argparse
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from relay_bundle import hostname, ipv4

ROOT = Path(__file__).resolve().parent
ID_PATTERN = re.compile(r'[a-z][a-z0-9_-]{0,31}')


def integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'{name}: esperado inteiro de {minimum} a {maximum}')
    return value


def validate_manifest(data):
    defaults = dict(relay_port=18443, api_port=18444, pool_host='prl.kryptex.network',
                    pool_port=8048, max_connections=2048, max_connections_per_instance=8)
    allowed = set(defaults) | {'relay_ip', 'instances'}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError('manifesto invalido ou campos desconhecidos')
    result = defaults | data
    try:
        result['relay_ip'] = ipv4(result['relay_ip'])
        result['pool_host'] = hostname(result['pool_host'])
    except (KeyError, TypeError, argparse.ArgumentTypeError) as exc:
        raise ValueError(f'IP/hostname invalido: {exc}') from exc
    for key in ('relay_port', 'api_port'):
        integer(result[key], key, 1024, 65535)
    if result['relay_port'] == result['api_port'] or 18080 in (result['relay_port'], result['api_port']):
        raise ValueError('portas relay/API precisam ser distintas e nao podem usar 18080')
    integer(result['pool_port'], 'pool_port', 1, 65535)
    integer(result['max_connections'], 'max_connections', 16, 65536)
    integer(result['max_connections_per_instance'], 'max_connections_per_instance', 1, 128)
    instances = result.get('instances')
    if not isinstance(instances, list) or not 1 <= len(instances) <= 1024:
        raise ValueError('informe de 1 a 1024 instancias')
    seen, normalized = set(), []
    for instance in instances:
        if not isinstance(instance, dict) or set(instance) - {'id', 'label', 'allowed_ip'}:
            raise ValueError('instancia invalida ou campos desconhecidos')
        identity = instance.get('id')
        if (not isinstance(identity, str) or not ID_PATTERN.fullmatch(identity)
                or identity == 'monitor-panel' or identity in seen):
            raise ValueError('ID invalido, reservado ou duplicado')
        label = instance.get('label', identity)
        if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in label):
            raise ValueError('label deve ter 1..80 caracteres, sem caracteres de controle')
        address = instance.get('allowed_ip')
        if address is not None:
            try:
                address = ipv4(address)
            except (TypeError, argparse.ArgumentTypeError) as exc:
                raise ValueError('allowed_ip invalido') from exc
        seen.add(identity)
        normalized.append(dict(id=identity, label=label, allowed_ip=address))
    result['instances'] = normalized
    return result


def render_haproxy(manifest, config_dir='/etc/prl-fleet', runtime_dir='/run/prl-fleet',
                   socket_group='prl-metrics'):
    m = validate_manifest(manifest)
    group = f' group {socket_group}' if socket_group else ''
    lines = [
        'global', '    log stdout format raw local0', '    nbthread 2',
        f'    maxconn {m["max_connections"]}',
        f'    stats socket {runtime_dir}/stats.sock mode 660{group} level user',
        '    stats timeout 2s', '    ssl-default-bind-options ssl-min-ver TLSv1.2',
        '', 'defaults', '    mode tcp', '    log global', '    option tcplog',
        '    option contstats', '    timeout connect 5s', '    timeout client 10m',
        '    timeout server 10m', '', 'resolvers system_dns', '    parse-resolv-conf',
        '    timeout resolve 2s', '    timeout retry 1s', '    hold valid 30s', '',
        'frontend fleet_ingress',
        f'    bind 0.0.0.0:{m["relay_port"]} ssl crt {config_dir}/server.pem ca-file {config_dir}/ca.crt crl-file {config_dir}/crl.pem verify required',
        '    stick-table type string len 32 size 10k expire 1m store conn_cur,conn_rate(10s)',
    ]
    # HAProxy limits words per configuration line. Repeated declarations of
    # the same ACL are ORed, keeping large fleets within that parser limit.
    for offset in range(0, len(m['instances']), 32):
        lines.append('    acl known_client ssl_c_s_dn(CN) -m str ' +
                     ' '.join(i['id'] for i in m['instances'][offset:offset + 32]))
    lines += [
        '    tcp-request session reject unless known_client',
        '    tcp-request session track-sc0 ssl_c_s_dn(CN)',
        f'    tcp-request session reject if {{ sc0_conn_cur gt {m["max_connections_per_instance"]} }}',
        '    tcp-request session reject if { sc0_conn_rate gt 30 }',
    ]
    for i in m['instances']:
        if i['allowed_ip']:
            lines.append(f'    tcp-request session reject if {{ ssl_c_s_dn(CN) -m str {i["id"]} }} !{{ src {i["allowed_ip"]}/32 }}')
    for i in m['instances']:
        lines.append(f'    use_backend pool_{i["id"]} if {{ ssl_c_s_dn(CN) -m str {i["id"]} }}')
    for i in m['instances']:
        lines += ['', f'backend pool_{i["id"]}',
                  f'    server pool {m["pool_host"]}:{m["pool_port"]} resolvers system_dns resolve-prefer ipv4 init-addr last,libc,none']
    lines += [
        '', 'frontend monitor_https', '    mode http', '    maxconn 32',
        f'    bind 0.0.0.0:{m["api_port"]} ssl crt {config_dir}/server.pem ca-file {config_dir}/ca.crt crl-file {config_dir}/crl.pem verify required',
        '    timeout http-request 5s', '    timeout http-keep-alive 5s',
        '    log-format "monitor status=%ST bytes=%B"',
        '    stick-table type ip size 1k expire 1m store http_req_rate(10s)',
        '    http-request deny unless { ssl_c_s_dn(CN) -m str monitor-panel }',
        '    http-request deny unless { method GET }',
        '    http-request track-sc0 src',
        '    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 180 }',
        '    default_backend monitor_local', '', 'backend monitor_local', '    mode http',
        '    timeout server 10s', '    server api 127.0.0.1:18080', '',
    ]
    return '\n'.join(lines)


def render_client(manifest, client_dir='/etc/prl-fleet-client', local_port=17048, bridge_port=17443):
    m = validate_manifest(manifest)
    return f'''# Two independent TLS layers. Only local sockets carry plaintext.
foreground = yes
pid =
debug = notice

[pool_tls]
client = yes
accept = 127.0.0.1:{local_port}
connect = 127.0.0.1:{bridge_port}
CAfile = /etc/ssl/certs/ca-certificates.crt
verifyChain = yes
checkHost = {m['pool_host']}
sni = {m['pool_host']}
sslVersionMin = TLSv1.2
TIMEOUTconnect = 5
TIMEOUTbusy = 10
TIMEOUTidle = 600

[relay_mtls]
client = yes
accept = 127.0.0.1:{bridge_port}
connect = {m['relay_ip']}:{m['relay_port']}
CAfile = {client_dir}/ca.crt
cert = {client_dir}/client.pem
verifyChain = yes
checkHost = relay.prl.internal
sni = relay.prl.internal
sslVersionMin = TLSv1.2
TIMEOUTconnect = 5
TIMEOUTbusy = 10
TIMEOUTidle = 600
'''


def write(path, content, secret=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8', newline='\n')
    path.chmod(0o600 if secret else 0o644)


def copy(source, destination, secret=False):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o600 if secret else 0o644)


def generate(manifest, pki_dir, output):
    m = validate_manifest(manifest)
    pki, output = Path(pki_dir), Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('saida existente; gere outro diretorio')
    required = ['ca.crt', 'server.pem', 'crl.pem', 'clients/monitor-panel.pem']
    required += [f'clients/{i["id"]}.pem' for i in m['instances']]
    for relative in required:
        if not (pki / relative).is_file():
            raise ValueError(f'PKI incompleta: falta {relative}')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.fleet-', dir=output.parent))
    try:
        relay = stage / 'relay'
        write(relay / 'haproxy.cfg', render_haproxy(m))
        for name in ('ca.crt', 'crl.pem', 'server.pem'):
            copy(pki / name, relay / name, name == 'server.pem')
        registry = {'instances': [dict(id=i['id'], label=i['label']) for i in m['instances']]}
        write(relay / 'registry.json', json.dumps(registry, indent=2, ensure_ascii=False))
        token = secrets.token_urlsafe(48)
        write(relay / 'api-token', token + '\n', secret=True)
        for name in ('prl-fleet.service', 'prl-monitor.service'):
            copy(ROOT / 'fleet/templates' / name, relay / name)
        copy(ROOT / 'fleet/install-relay.sh', relay / 'install.sh')
        copy(ROOT / 'fleet/install-common.sh', relay / 'install-common.sh')
        copy(ROOT / 'fleet/menu.py', relay / 'menu.py')
        copy(ROOT / 'requirements-monitor.txt', relay / 'requirements-monitor.txt')
        for source in sorted((ROOT / 'monitor').glob('*.py')):
            copy(source, relay / 'monitor' / source.name)
        panel = stage / 'panel'
        copy(pki / 'ca.crt', panel / 'ca.crt')
        copy(pki / 'clients/monitor-panel.pem', panel / 'client.pem', secret=True)
        write(panel / 'api-token', token + '\n', secret=True)
        for i in m['instances']:
            client = stage / 'clients' / i['id']
            write(client / 'stunnel.conf', render_client(m))
            copy(pki / 'ca.crt', client / 'ca.crt')
            copy(pki / 'clients' / (i['id'] + '.pem'), client / 'client.pem', secret=True)
            copy(ROOT / 'fleet/templates/prl-fleet-client.service', client / 'prl-fleet-client.service')
            copy(ROOT / 'fleet/install-client.sh', client / 'install.sh')
            copy(ROOT / 'fleet/install-common.sh', client / 'install-common.sh')
            copy(ROOT / 'fleet/menu.py', client / 'menu.py')
        write(stage / 'manifest.json', json.dumps(m, indent=2, ensure_ascii=False))
        copy(ROOT / 'docs/FLEET.md', stage / 'README.md')
        stage.rename(output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--pki-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        path = generate(json.loads(args.manifest.read_text(encoding='utf-8')), args.pki_dir, args.output)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f'Pacote criado: {path}. Contem chaves privadas e token; distribua por pasta, via SSH.')


if __name__ == '__main__':
    main()
