#!/usr/bin/env python3
"""Real HAProxy + stunnel tests. All application traffic stays on loopback."""
import contextlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXTRACTED = ROOT / '.tools' / 'root'
ENV = os.environ.copy()
if EXTRACTED.exists():
    ENV['LD_LIBRARY_PATH'] = str(EXTRACTED / 'usr/lib/x86_64-linux-gnu') + ':' + str(
        EXTRACTED / 'lib/x86_64-linux-gnu')


def binary(name, relative):
    path = shutil.which(name)
    if not path and (EXTRACTED / relative).exists():
        path = str(EXTRACTED / relative)
    if not path:
        raise RuntimeError(f'Missing {name}: install the Ubuntu package to run integration tests')
    return path


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, env=ENV)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class TLSEcho:
    def __init__(self, cert, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.port = self.socket.getsockname()[1]
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.payloads = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2)
                try:
                    with self.context.wrap_socket(conn, server_side=True) as tls:
                        while not self.stopped.is_set():
                            data = tls.recv(65536)
                            if not data:
                                break
                            self.payloads.append(data)
                            tls.sendall(data)
                except (OSError, ssl.SSLError):
                    pass

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(timeout=3)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.haproxy = binary('haproxy', 'usr/sbin/haproxy')
        cls.stunnel = binary('stunnel4', 'usr/bin/stunnel4')
        cls.temp = tempfile.TemporaryDirectory(prefix='prl-integration-')
        cls.directory = Path(cls.temp.name)
        cls.ca = cls.directory / 'ca.crt'
        cls.cert = cls.directory / 'pool.crt'
        cls.key = cls.directory / 'pool.key'
        cls.other_ca = cls.directory / 'other.crt'
        for prefix in ('ca', 'other'):
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(cls.directory / (prefix + '.key')),
                '-out', str(cls.directory / (prefix + '.crt')), '-days', '1',
                '-subj', '/CN=Local test CA ' + prefix,
                '-addext', 'basicConstraints=critical,CA:TRUE')
        csr = cls.directory / 'pool.csr'
        run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(cls.key), '-out', str(csr), '-subj', '/CN=localhost.test')
        ext = cls.directory / 'pool.ext'
        ext.write_text('subjectAltName=DNS:localhost.test\nextendedKeyUsage=serverAuth\n')
        run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(cls.ca),
            '-CAkey', str(cls.directory / 'ca.key'), '-CAcreateserial',
            '-out', str(cls.cert), '-days', '1', '-extfile', str(ext))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def stack(self, *, allowed='127.0.0.1', trusted=True,
              identity='localhost.test', unavailable=False):
        processes = []
        logs = []
        echo = TLSEcho(self.cert, self.key)
        try:
            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                path = Path(temporary)
                relay_port, local_port = free_port(), free_port()
                while local_port == relay_port:
                    local_port = free_port()
                upstream_port = echo.port
                if unavailable:
                    echo.close()
                bundle = path / 'bundle'
                run(sys.executable, str(ROOT / 'relay_bundle.py'),
                    '--relay-ip', '127.0.0.1', '--client-ip', allowed,
                    '--relay-port', str(relay_port), '--local-port', str(local_port),
                    '--pool-host', identity, '--pool-port', str(upstream_port),
                    '--output', str(bundle))
                haproxy_config = bundle / 'relay' / 'haproxy.cfg'
                # Local fixture has no DNS record: preserve the generated pool
                # identity at the client, replace only backend routing for the lab.
                text = haproxy_config.read_text().replace(
                    f'{identity}:{upstream_port}', f'127.0.0.1:{upstream_port}')
                text = text.replace(f'0.0.0.0:{relay_port}', f'127.0.0.1:{relay_port}')
                haproxy_config.write_text(text)
                stunnel_config = bundle / 'client' / 'stunnel.conf'
                stunnel_config.write_text(stunnel_config.read_text().replace(
                    '/etc/ssl/certs/ca-certificates.crt',
                    str(self.ca if trusted else self.other_ca)))
                run(self.haproxy, '-c', '-f', str(haproxy_config))
                commands = [
                    [self.haproxy, '-db', '-f', str(haproxy_config)],
                    [self.stunnel, str(stunnel_config)],
                ]
                for index, command in enumerate(commands):
                    log = open(path / f'process-{index}.log', 'w+')
                    logs.append(log)
                    processes.append(subprocess.Popen(command, env=ENV,
                                                       stdout=log, stderr=log))
                deadline = time.monotonic() + 5
                while True:
                    if any(proc.poll() is not None for proc in processes):
                        for log in logs:
                            log.seek(0)
                            print(log.read(), file=sys.stderr)
                        self.fail('A real network component failed to start')
                    try:
                        with socket.create_connection(('127.0.0.1', local_port), timeout=.1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail('Timed out starting local client')
                        time.sleep(.05)
                # Confirm HAProxy binds even in the deny-ACL case.
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', relay_port), timeout=.1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail('Timed out starting relay')
                        time.sleep(.05)
                try:
                    yield local_port, echo
                finally:
                    for proc in reversed(processes):
                        proc.terminate()
                    for proc in reversed(processes):
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
        finally:
            for proc in processes:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            for log in logs:
                log.close()
            echo.close()

    def test_binary_payload_is_preserved_end_to_end(self):
        payload = b'{"wallet":"test-only","worker":"gpu0"}\n' + bytes(range(256)) * 1024
        with self.stack() as (port, echo):
            with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
                conn.settimeout(5)
                conn.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    part = conn.recv(65536)
                    self.assertTrue(part, 'connection closed before full payload')
                    received.extend(part)
                self.assertEqual(bytes(received), payload)
            self.assertEqual(b''.join(echo.payloads), payload)

    def assert_rejected(self, **settings):
        with self.stack(**settings) as (port, echo):
            with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
                conn.settimeout(5)
                try:
                    conn.sendall(b'NEVER DELIVER THIS PAYLOAD')
                    data = conn.recv(1024)
                except (ConnectionResetError, BrokenPipeError):
                    data = b''
                self.assertEqual(data, b'')
            self.assertEqual(echo.payloads, [], 'unauthenticated payload reached pool')

    def test_untrusted_ca_is_rejected_before_payload(self):
        self.assert_rejected(trusted=False)

    def test_wrong_pool_identity_is_rejected_before_payload(self):
        self.assert_rejected(identity='wrong.test')

    def test_source_outside_acl_is_rejected(self):
        self.assert_rejected(allowed='127.0.0.2')

    def test_pool_outage_does_not_fall_back(self):
        self.assert_rejected(unavailable=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
