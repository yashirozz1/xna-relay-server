#!/usr/bin/env python3
"""Read-only TLS handshake; sends no mining credentials or shares."""
import argparse
import socket
import ssl
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--connect', required=True, help='IP/hostname para conectar')
    parser.add_argument('--port', type=int, default=18443)
    parser.add_argument('--identity', default='prl.kryptex.network')
    args = parser.parse_args()
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((args.connect, args.port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=args.identity) as tls:
                print(f'OK: cadeia e identidade {args.identity} verificadas; {tls.version()}')
                print('Apenas handshake TLS; nenhuma credencial ou share enviada.')
    except (OSError, ssl.SSLError) as exc:
        print(f'FALHOU: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
