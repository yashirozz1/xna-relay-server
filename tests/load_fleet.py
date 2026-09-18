#!/usr/bin/env python3
"""Optional local capacity probe: real double TLS, per-client identities and API.

This is not a Contabo benchmark. All clients and the fake pool share the host
with the relay. No miner, remote pool, system service or firewall is used.
"""
import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import resource
import socket
import ssl
import subprocess
import sys
import threading
import time

from integration import ROOT, ENV, free_port, run, TransportTests
from integration_fleet import EchoServer

from fleet.pki import init_pki, issue_client
from fleet_bundle import generate, render_client, render_haproxy
from monitor.haproxy import HAProxyStatsClient


def process_usage(pid):
    status = Path(f'/proc/{pid}/status').read_text()
    rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith('VmRSS:'))
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    cpu = (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
    return {'rss_mib': round(rss / 1024, 2), 'cpu_seconds': cpu}


def percentile(values, fraction):
    return round(sorted(values)[min(len(values) - 1, int(len(values) * fraction))] * 1000, 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clients', type=int, default=300)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--cycles', type=int, default=2)
    parser.add_argument('--cpus', type=int, default=4)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.clients <= 1024 or not 5 <= args.seconds <= 300 or not 1 <= args.cycles <= 5:
        parser.error('clients: 1..1024; seconds: 5..300; cycles: 1..5')
    available = sorted(os.sched_getaffinity(0))
    if not 1 <= args.cpus <= len(available):
        parser.error('cpus exceeds available CPU affinity')
    os.sched_setaffinity(0, available[:args.cpus])
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(soft, args.clients * 12 + 1024), hard), hard))
    TransportTests.setUpClass()
    fixtures = TransportTests
    path = fixtures.directory
    processes, logs = {}, []
    echo = None
    try:
        print(f'Preparing {args.clients} distinct certificates on {args.cpus} logical CPUs...', flush=True)
        pki = path / 'pki'
        password = 'load test only temporary authority'
        init_pki(pki, password, relay_ip='127.0.0.1')
        identities = [f'gpu{i:04}' for i in range(args.clients)]
        for index, identity in enumerate([*identities, 'monitor-panel']):
            issue_client(pki, identity, password)
            if (index + 1) % 100 == 0:
                print(f'  {index + 1} certificates issued', flush=True)
        # A generous fixture backlog prevents measuring the echo server's tiny
        # default accept queue instead of relay reconnection behavior.
        EchoServer.request_queue_size = 2048
        echo = EchoServer(fixtures.cert, fixtures.key)
        ports = set()
        while len(ports) < args.clients * 2 + 3:
            ports.add(free_port())
        ports = iter(ports)
        relay_port, api_port, monitor_port = next(ports), next(ports), next(ports)
        manifest = {'relay_ip': '127.0.0.1', 'relay_port': relay_port, 'api_port': api_port,
                    'pool_host': 'localhost.test', 'pool_port': echo.server_address[1],
                    'instances': [{'id': identity} for identity in identities]}
        bundle = generate(manifest, pki, path / 'bundle')
        cfg = bundle / 'relay/haproxy.cfg'
        cfg.write_text(render_haproxy(manifest, bundle / 'relay', path, socket_group='')
                       .replace('0.0.0.0:', '127.0.0.1:')
                       .replace(f'localhost.test:{manifest["pool_port"]}', f'127.0.0.1:{manifest["pool_port"]}')
                       .replace('127.0.0.1:18080', f'127.0.0.1:{monitor_port}'))
        local_ports = []
        sections = ['foreground = yes\npid =\ndebug = err\n']
        for identity in identities:
            local, bridge = next(ports), next(ports)
            local_ports.append(local)
            text = render_client(manifest, bundle / 'clients' / identity, local, bridge)
            text = '[pool_tls]' + text.split('[pool_tls]', 1)[1]
            text = text.replace('[pool_tls]', f'[pool_{identity}]').replace('[relay_mtls]', f'[relay_{identity}]')
            sections.append(text.replace('/etc/ssl/certs/ca-certificates.crt', str(fixtures.ca)))
        stunnel_cfg = path / 'clients.conf'
        stunnel_cfg.write_text('\n'.join(sections))
        env = ENV | {'PRL_REGISTRY': str(bundle / 'relay/registry.json'),
                     'PRL_STATS_SOCKET': str(path / 'stats.sock'),
                     'PRL_DB': str(path / 'metrics.sqlite3'),
                     'PRL_TOKEN_FILE': str(bundle / 'relay/api-token'), 'PRL_SAMPLE_SECONDS': '5'}
        commands = {
            'haproxy': [fixtures.haproxy, '-db', '-f', str(cfg)],
            'stunnel_clients': [fixtures.stunnel, str(stunnel_cfg)],
            'monitor': [sys.executable, '-m', 'uvicorn', '--factory', 'monitor.app:create_app',
                        '--host', '127.0.0.1', '--port', str(monitor_port), '--no-access-log', '--no-proxy-headers'],
        }
        run(fixtures.haproxy, '-c', '-f', str(cfg))
        for name, command in commands.items():
            log = open(path / f'{name}.log', 'w+')
            logs.append(log)
            processes[name] = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=log)
        for port in (relay_port, api_port, monitor_port, local_ports[-1]):
            deadline = time.monotonic() + 15
            while True:
                if any(proc.poll() is not None for proc in processes.values()):
                    raise RuntimeError('component exited at startup')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('component startup timed out')
                    time.sleep(.05)
        tls = ssl.create_default_context(cafile=str(pki / 'ca.crt'))
        tls.load_cert_chain(str(bundle / 'panel/client.pem'))
        token = (bundle / 'panel/api-token').read_text().strip()
        api_latencies, max_rss = [], {name: 0 for name in processes}

        def panel():
            start = time.monotonic()
            conn = http.client.HTTPSConnection('127.0.0.1', api_port, context=tls, timeout=10)
            try:
                conn.request('GET', '/v1/instances', headers={'Authorization': 'Bearer ' + token})
                response = conn.getresponse()
                if response.status != 200:
                    raise RuntimeError(f'panel returned HTTP {response.status}')
                data = json.loads(response.read())
                if len(data['instances']) != args.clients:
                    raise AssertionError('panel lost registered clients')
                api_latencies.append(time.monotonic() - start)
                return data
            finally:
                conn.close()

        rounds = []
        for cycle in range(args.cycles):
            print(f'Cycle {cycle + 1}: opening {args.clients} sessions together...', flush=True)
            stop = threading.Event()
            ready = threading.Barrier(args.clients + 1, timeout=30)
            cpu_before = {name: process_usage(proc.pid)['cpu_seconds'] for name, proc in processes.items()}
            start = time.monotonic()

            def client(index):
                connection_started = time.monotonic()
                latencies, exchanges = [], 0
                try:
                    with socket.create_connection(('127.0.0.1', local_ports[index]), timeout=20) as conn:
                        payload = index.to_bytes(4, 'big') + bytes(range(256)) * 4
                        first = None
                        while not stop.is_set():
                            sent = time.monotonic()
                            conn.sendall(payload)
                            received = bytearray()
                            while len(received) < len(payload):
                                data = conn.recv(len(payload) - len(received))
                                if not data:
                                    raise RuntimeError('session closed before full payload')
                                received.extend(data)
                            if bytes(received) != payload:
                                raise AssertionError('payload changed')
                            latencies.append(time.monotonic() - sent)
                            exchanges += 1
                            if first is None:
                                first = time.monotonic() - connection_started
                                ready.wait()
                            stop.wait(1)
                    return first, latencies, exchanges
                except BaseException:
                    ready.abort()
                    stop.set()
                    raise

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as pool:
                futures = [pool.submit(client, i) for i in range(args.clients)]
                try:
                    ready.wait()
                    connected_seconds = time.monotonic() - start
                    snapshot = HAProxyStatsClient(path / 'stats.sock').collect(identities)
                    active = sum(c.current_connections for c in snapshot.counters.values())
                    if active < args.clients:
                        raise AssertionError(f'only {active} active connections')
                    print(f'  {active} active; holding for {args.seconds}s and polling HTTPS API...', flush=True)
                    deadline = time.monotonic() + args.seconds
                    while time.monotonic() < deadline:
                        if stop.is_set():
                            raise RuntimeError('a load client failed')
                        panel()
                        for name, proc in processes.items():
                            max_rss[name] = max(max_rss[name], process_usage(proc.pid)['rss_mib'])
                        stop.wait(2)
                    data = panel()
                    if data['collection']['stale'] or any(
                        not i['sample'] or not i['sample']['observed'] or i['sample']['current_connections'] < 1
                        for i in data['instances']
                    ):
                        raise AssertionError('API did not report a fresh active sample for every client')
                finally:
                    stop.set()
                results = [future.result() for future in futures]
            elapsed = time.monotonic() - start
            latencies = [v for _, values, _ in results for v in values]
            rounds.append({'cycle': cycle + 1, 'active_connections': active,
                           'all_connected_seconds': round(connected_seconds, 3),
                           'handshake_and_first_echo_p95_ms': percentile([r[0] for r in results], .95),
                           'echo_p95_ms_including_handshake': percentile(latencies, .95),
                           'verified_exchanges': sum(r[2] for r in results),
                           'duration_seconds': round(elapsed, 3),
                           'cpu_percent_one_core': {name: round(100 * (process_usage(proc.pid)['cpu_seconds'] - cpu_before[name]) / elapsed, 2)
                                                    for name, proc in processes.items()}})
            # Wait until old sessions are removed before opening the next wave.
            deadline = time.monotonic() + 10
            while sum(c.current_connections for c in HAProxyStatsClient(path / 'stats.sock').collect(identities).counters.values()):
                if time.monotonic() > deadline:
                    raise RuntimeError('old sessions did not drain')
                time.sleep(.1)
        result = {'clients': args.clients, 'cpu_affinity': sorted(os.sched_getaffinity(0)),
                  'host': os.uname().release, 'cycles': rounds, 'max_rss_mib': max_rss,
                  'panel_https_p95_ms': percentile(api_latencies, .95),
                  'limitation': 'Local synthetic TLS echo traffic; clients and pool share CPU with relay. Fresh metrics DB. Not Contabo or real mining traffic.'}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2), flush=True)
    except BaseException as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stdout or '', file=sys.stderr)
            print(exc.stderr or '', file=sys.stderr)
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read()[-10000:], file=sys.stderr)
        raise
    finally:
        for proc in reversed(list(processes.values())):
            if proc.poll() is None:
                proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for log in logs:
            log.close()
        if echo:
            echo.close()
        TransportTests.tearDownClass()


if __name__ == '__main__':
    main()
