#!/usr/bin/env python3
"""Render a TCP relay + authenticated TLS client bundle. No remote changes."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import shutil
from string import Template
import tempfile

ROOT = Path(__file__).resolve().parent


def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError('use um IPv4 individual, sem CIDR') from exc
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise argparse.ArgumentTypeError('IPv4 precisa identificar uma maquina')
    return str(address)


def hostname(value):
    labels = value.split('.')
    if (len(value) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',
                                 label) for label in labels)):
        raise argparse.ArgumentTypeError('hostname DNS ASCII invalido')
    return value.lower()


def port(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('porta precisa ser um inteiro') from exc
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError('porta precisa estar entre 1 e 65535')
    return number


def unprivileged_port(value):
    number = port(value)
    if number < 1024:
        raise argparse.ArgumentTypeError('use porta entre 1024 e 65535; preserve o SSH')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--relay-ip', required=True, type=ipv4)
    parser.add_argument('--client-ip', required=True, type=ipv4,
                        help='IPv4 de SAIDA da VM, visto pelo relay')
    parser.add_argument('--pool-host', default='prl.kryptex.network', type=hostname)
    parser.add_argument('--pool-port', default=8048, type=port)
    parser.add_argument('--relay-port', default=18443, type=unprivileged_port)
    parser.add_argument('--local-port', default=17048, type=unprivileged_port)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('diretorio de saida ja existe; escolha um novo')
    values = vars(args).copy()
    values.pop('output')
    output.parent.mkdir(parents=True, exist_ok=True)
    # Build in a sibling temporary directory; expose the result only when complete.
    stage = Path(tempfile.mkdtemp(prefix='.prl-bundle-', dir=output.parent))
    try:
        for role, config, service in (
            ('relay', 'haproxy.cfg', 'prl-relay'),
            ('client', 'stunnel.conf', 'prl-client'),
        ):
            target = stage / role
            target.mkdir()
            rendered = Template((ROOT / 'templates' / (config + '.in')).read_text(
                encoding='utf-8')).substitute(values)
            (target / config).write_text(rendered, encoding='utf-8', newline='\n')
            for source, name in ((ROOT / 'templates' / (service + '.service'),
                                  service + '.service'),
                                 (ROOT / 'scripts' / 'install.sh', 'install.sh')):
                (target / name).write_text(source.read_text(encoding='utf-8'),
                                          encoding='utf-8', newline='\n')
            (target / 'install.sh').chmod(0o755)
        (stage / 'settings.json').write_text(
            json.dumps(values, indent=2) + '\n', encoding='utf-8', newline='\n')
        shutil.copyfile(ROOT / 'docs/LEGACY.md', stage / 'README.md')
        shutil.copyfile(ROOT / 'scripts' / 'check_tls.py', stage / 'check_tls.py')
        stage.rename(output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print(f'Pacote gerado: {output}')
    print('Nenhuma VM, conexao de mineracao ou instalacao foi iniciada.')


if __name__ == '__main__':
    main()
