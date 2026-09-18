#!/usr/bin/env python3
"""Real fleet transport + HTTPS API; ephemeral processes, loopback only."""
import concurrent.futures
import contextlib
import http.client
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import integration as transport
from integration import ROOT, ENV, free_port, run

sys.path.insert(0, str(ROOT))
from fleet.pki import init_pki, issue_client, revoke_client
from fleet_bundle import generate, render_client, render_haproxy
from dual_bundle import generate_dual, verify_credentials
from monitor.haproxy import HAProxyStatsClient


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, cert, key):
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(cert, key)
        self.payloads = []
        super().__init__(('127.0.0.1', 0), EchoHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=3)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            with self.server.tls.wrap_socket(self.request, server_side=True) as tls:
                while data := tls.recv(65536):
                    self.server.payloads.append(data)
                    tls.sendall(data)
        except OSError:
            pass


class FleetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the V1 independent pool certificate fixture, not its test cases.
        transport.TransportTests.setUpClass.__func__(cls)
        cls.pki = cls.directory / 'pki'
        password = 'local integration test passphrase'
        init_pki(cls.pki, password, relay_ip='127.0.0.1')
        for identity in ('gpu01', 'gpu02', 'unknown', 'revoked', 'monitor-panel'):
            issue_client(cls.pki, identity, password)
        revoke_client(cls.pki, 'revoked', password)
        cls.foreign = cls.directory / 'foreign'
        init_pki(cls.foreign, password)
        issue_client(cls.foreign, 'gpu01', password)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def stack(self, *, client_cert=None, pool_identity='localhost.test',
              trusted_pool=True, allowed_ip=None, pool_down=False, dual=False, xmr_disabled=False):
        processes, logs = [], []
        echo = EchoServer(self.cert, self.key)
        xmr = EchoServer(self.cert, self.key) if dual else None
        try:
            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                path = Path(temporary)
                ports = set()
                while len(ports) < 7:
                    ports.add(free_port())
                relay_port, api_port, monitor_port, local1, bridge1, local2, bridge2 = ports
                manifest = {'relay_ip': '127.0.0.1', 'relay_port': relay_port,
                            'api_port': api_port, 'pool_host': 'localhost.test',
                            'pool_port': echo.server_address[1],
                            'instances': [{'id': 'gpu01', 'allowed_ip': allowed_ip}, {'id': 'gpu02'}]}
                if dual:
                    manifest.update(xmr_pool_host='localhost.test', xmr_pool_port=xmr.server_address[1])
                bundle = generate(manifest, self.pki, path / 'bundle')
                cfg = bundle / 'relay/haproxy.cfg'
                cfg.write_text(render_haproxy(manifest, bundle / 'relay', path, socket_group='')
                               .replace('0.0.0.0:', '127.0.0.1:')
                               .replace(f'localhost.test:{manifest["pool_port"]}', f'127.0.0.1:{manifest["pool_port"]}')
                               .replace('127.0.0.1:18080', f'127.0.0.1:{monitor_port}'))
                if dual:
                    cfg.write_text(cfg.read_text().replace(f'localhost.test:{xmr.server_address[1]}',
                                                          f'127.0.0.1:{xmr.server_address[1]}'))
                if xmr_disabled:
                    cfg.write_text(cfg.read_text().replace(' weight 0 resolvers', ' weight 0 disabled resolvers'))
                commands = [[self.haproxy, '-db', '-f', str(cfg)]]
                for identity, local, bridge in (('gpu01', local1, bridge1), ('gpu02', local2, bridge2)):
                    client = bundle / 'clients' / identity
                    text = render_client(manifest | {'pool_host': pool_identity}, client, local, bridge)
                    text = text.replace('/etc/ssl/certs/ca-certificates.crt',
                                        str(self.ca if trusted_pool else self.other_ca))
                    if dual and identity == 'gpu02':
                        text = text.replace('sni = relay.prl.internal', 'sni = xmr.relay.prl.internal')
                    (client / 'stunnel.conf').write_text(text)
                    if identity == 'gpu01' and client_cert:
                        (client / 'client.pem').write_bytes(Path(client_cert).read_bytes())
                    commands.append([self.stunnel, str(client / 'stunnel.conf')])
                monitor_env = ENV | {
                    'PRL_REGISTRY': str(bundle / 'relay/registry.json'),
                    'PRL_STATS_SOCKET': str(path / 'stats.sock'),
                    'PRL_DB': str(path / 'metrics.sqlite3'),
                    'PRL_TOKEN_FILE': str(bundle / 'relay/api-token'),
                    'PRL_SAMPLE_SECONDS': '5',
                }
                commands.append([sys.executable, '-m', 'uvicorn', '--factory', 'monitor.app:create_app',
                                 '--host', '127.0.0.1', '--port', str(monitor_port), '--workers', '1',
                                 '--no-access-log', '--no-proxy-headers'])
                run(self.haproxy, '-c', '-f', str(cfg))
                for index, command in enumerate(commands):
                    log = open(path / f'process-{index}.log', 'w+')
                    logs.append(log)
                    processes.append(subprocess.Popen(command, cwd=ROOT, env=monitor_env,
                                                       stdout=log, stderr=log))
                for port in (relay_port, api_port, monitor_port, local1, local2):
                    deadline = time.monotonic() + 10
                    while True:
                        if any(proc.poll() is not None for proc in processes):
                            self.fail('Component exited during startup')
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                self.fail('Component did not listen')
                            time.sleep(.05)
                if pool_down:
                    echo.close()
                yield {'locals': (local1, local2), 'relay': relay_port, 'api': api_port,
                       'bundle': bundle, 'echo': echo, 'xmr': xmr, 'socket': path / 'stats.sock',
                       'relay_process': processes[0],
                       'token': (bundle / 'panel/api-token').read_text().strip()}
        except Exception:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
            raise
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
            for proc in reversed(processes):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            for log in logs:
                log.close()
            echo.close()
            if xmr:
                xmr.close()

    def context(self, cert=None):
        tls = ssl.create_default_context(cafile=str(self.pki / 'ca.crt'))
        if cert:
            tls.load_cert_chain(str(cert))
        return tls

    def request(self, stack, path='/v1/instances', *, identity='monitor-panel', token=True, method='GET'):
        cert = self.pki / 'clients' / f'{identity}.pem' if identity else None
        conn = http.client.HTTPSConnection('127.0.0.1', stack['api'], timeout=5,
                                           context=self.context(cert))
        try:
            conn.request(method, path, headers={'Authorization': 'Bearer ' + stack['token']} if token else {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    @staticmethod
    def exchange(port, payload):
        with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
            conn.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                part = conn.recv(65536)
                if not part:
                    raise AssertionError('Connection closed before payload was echoed')
                received.extend(part)
        if bytes(received) != payload:
            raise AssertionError('Relay changed payload')

    def test_concurrent_clients_and_panel_observe_separate_real_traffic(self):
        with self.stack() as stack:
            started = time.monotonic()
            payloads = [bytes(range(256)) * (1024 if index % 2 == 0 else 2048) for index in range(8)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                jobs = [pool.submit(self.exchange, stack['locals'][index % 2], payload)
                        for index, payload in enumerate(payloads)]
                for job in jobs:
                    job.result(timeout=15)
            elapsed = time.monotonic() - started
            deadline = time.monotonic() + 12
            while True:
                status, body = self.request(stack)
                self.assertEqual(status, 200)
                data = json.loads(body)
                samples = {i['id']: i['sample'] for i in data['instances']}
                if all(samples[i] and samples[i]['inner_tls_bytes_in'] >= size for i, size in
                       (('gpu01', 1048576), ('gpu02', 2097152))):
                    break
                if time.monotonic() >= deadline:
                    self.fail('API did not publish real per-client traffic')
                time.sleep(.2)
            self.assertFalse(data['collection']['stale'])
            self.assertGreater(samples['gpu02']['inner_tls_bytes_in'], samples['gpu01']['inner_tls_bytes_in'])
            for sample in samples.values():
                self.assertGreaterEqual(sample['total_connections'], 4)
                self.assertGreater(sample['inner_tls_bytes_out'], 0)
                self.assertTrue(sample['observed'])
            status, body = self.request(stack, '/v1/health')
            self.assertEqual(status, 200, body)
            now = time.time()
            status, body = self.request(stack, f'/v1/traffic?instance_id=gpu01&since={now-60}&until={now}')
            self.assertEqual(status, 200, body)
            self.assertGreater(len(json.loads(body)['samples']), 0)
            print(f'\nFleet lab: 8 concurrent sessions, 3145728 bytes each direction, {elapsed:.3f}s.', flush=True)

    def test_panel_requires_its_certificate_and_bearer(self):
        with self.stack() as stack:
            self.assertEqual(self.request(stack, token=False)[0], 401)
            self.assertEqual(self.request(stack, identity='gpu01')[0], 403)
            self.assertEqual(self.request(stack, method='POST')[0], 403)
            self.assertEqual(self.request(stack, '/openapi.json')[0], 200)
            with self.assertRaises((OSError, http.client.HTTPException)):
                self.request(stack, identity=None)

    def test_dual_sni_routes_to_distinct_tls_pools(self):
        with self.stack(dual=True) as stack:
            for _ in range(3):
                self.exchange(stack['locals'][0], b'PRL payload')
                self.exchange(stack['locals'][1], b'XMR payload')
            self.assertEqual(b''.join(stack['echo'].payloads), b'PRL payload' * 3)
            self.assertEqual(b''.join(stack['xmr'].payloads), b'XMR payload' * 3)
            counters = HAProxyStatsClient(stack['socket']).collect({'gpu01', 'gpu02'}).counters
            self.assertEqual(set(counters), {'gpu01', 'gpu02'})

    def test_dual_bundle_real_certificate_and_wrong_identity_rejection(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            path = Path(temporary)
            manifest = {'relay_ip': '127.0.0.1', 'instances': [{'id': 'gpu01'}, {'id': 'gpu02'}],
                        'xmr_pool_host': 'xmr.kryptex.network', 'xmr_pool_port': 8029}
            fleet = generate(manifest, self.pki, path / 'fleet')
            output = generate_dual(fleet, 'gpu01', 'krxYZDM8VP', path / 'dual')
            self.assertLess((output / 'cloud-init.yaml').stat().st_size, 65536)
            verify_credentials(output, 'gpu01')
            with self.assertRaisesRegex(ValueError, 'CN'):
                verify_credentials(output, 'gpu02')
            (output / 'client.pem').write_bytes((self.foreign / 'clients/gpu01.pem').read_bytes())
            with self.assertRaises(ValueError):
                verify_credentials(output, 'gpu01')

    def test_xmr_unavailable_never_falls_back_to_prl(self):
        with self.stack(dual=True, xmr_disabled=True) as stack:
            self.exchange(stack['locals'][0], b'PRL still works')
            with self.assertRaises((OSError, AssertionError)):
                self.exchange(stack['locals'][1], b'XMR must not reach PRL')
            self.assertEqual(b''.join(stack['echo'].payloads), b'PRL still works')
            self.assertEqual(stack['xmr'].payloads, [])

    def test_relay_rejects_missing_certificate(self):
        with self.stack() as stack:
            with self.assertRaises(OSError):
                with socket.create_connection(('127.0.0.1', stack['relay']), timeout=3) as raw:
                    with self.context().wrap_socket(raw, server_hostname='relay.prl.internal') as tls:
                        tls.sendall(b'not authenticated')
                        if tls.recv(1) == b'':
                            raise ConnectionError('TLS closed')
            self.assertEqual(stack['echo'].payloads, [])

    def assert_client_rejected(self, **kwargs):
        with self.stack(**kwargs) as stack:
            with socket.create_connection(('127.0.0.1', stack['locals'][0]), timeout=5) as conn:
                try:
                    conn.sendall(b'must not arrive')
                    data = conn.recv(1024)
                except (ConnectionResetError, BrokenPipeError):
                    data = b''
                self.assertEqual(data, b'')
            self.assertEqual(stack['echo'].payloads, [])

    def test_unknown_client_rejected(self):
        self.assert_client_rejected(client_cert=self.pki / 'clients/unknown.pem')

    def test_revoked_client_rejected(self):
        self.assert_client_rejected(client_cert=self.pki / 'clients/revoked.pem')

    def test_foreign_ca_rejected(self):
        self.assert_client_rejected(client_cert=self.foreign / 'clients/gpu01.pem')

    def test_wrong_pool_identity_rejected(self):
        self.assert_client_rejected(pool_identity='wrong.test')

    def test_untrusted_pool_rejected(self):
        self.assert_client_rejected(trusted_pool=False)

    def test_source_outside_acl_rejected(self):
        self.assert_client_rejected(allowed_ip='127.0.0.2')

    def test_pool_unavailable_fails_closed(self):
        self.assert_client_rejected(pool_down=True)

    def test_relay_outage_does_not_connect_directly_to_pool(self):
        with self.stack() as stack:
            self.exchange(stack['locals'][0], b'confirmed relay path')
            before = b''.join(stack['echo'].payloads)
            stack['relay_process'].terminate()
            stack['relay_process'].wait(timeout=5)
            with socket.create_connection(('127.0.0.1', stack['locals'][0]), timeout=10) as conn:
                try:
                    conn.sendall(b'must not bypass the relay')
                    received = conn.recv(1024)
                except (ConnectionResetError, BrokenPipeError):
                    received = b''
                self.assertEqual(received, b'')
            self.assertEqual(b''.join(stack['echo'].payloads), before)

    def test_stats_socket_has_no_admin_privilege(self):
        with self.stack() as stack:
            reader = HAProxyStatsClient(stack['socket'])
            self.assertEqual(set(reader.collect({'gpu01', 'gpu02'}).counters), {'gpu01', 'gpu02'})
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(stack['socket']))
                client.sendall(b'disable server pool_gpu01/pool\n')
                client.shutdown(socket.SHUT_WR)
                reply = client.recv(4096)
            self.assertIn(b'Permission denied', reply)
            self.exchange(stack['locals'][0], b'still forwarding')

    def test_configuration_accepts_1024_named_instances(self):
        manifest = {'relay_ip': '127.0.0.1', 'pool_host': '127.0.0.1',
                    'instances': [{'id': f'gpu{i:04}'} for i in range(1024)]}
        config = self.directory / 'large-fleet.cfg'
        config.write_text(render_haproxy(manifest, self.pki, self.directory, socket_group=''))
        result = subprocess.run([self.haproxy, '-c', '-f', str(config)], env=ENV,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
