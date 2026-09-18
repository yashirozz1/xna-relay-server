#!/usr/bin/env python3
"""Optional retention-size benchmark using synthetic SQLite history, no network."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.storage import MetricsStore
from monitor.haproxy import Counters, HAProxySnapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clients', type=int, default=300)
    parser.add_argument('--hours', type=int, default=72)
    parser.add_argument('--sample-seconds', type=int, default=15)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.clients <= 1024 or not 1 <= args.hours <= 168 or not 5 <= args.sample_seconds <= 300:
        parser.error('invalid clients, hours or sample-seconds')
    if hasattr(os, 'sched_setaffinity'):
        os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:4])
    ticks = args.hours * 3600 // args.sample_seconds
    base_time = 1700000000.125
    epoch = 'HAProxy|2.8.16-0ubuntu0.24.04.3|1|123456|1700000000|'
    with tempfile.TemporaryDirectory(prefix='prl-storage-load-') as temporary:
        path = Path(temporary) / 'metrics.sqlite3'
        store = MetricsStore(path, args.hours)
        print(f'Seeding {args.clients * ticks:,} samples in a temporary database...', flush=True)
        start = time.perf_counter()
        with sqlite3.connect(path) as conn:
            conn.execute('''
                WITH RECURSIVE
                  tick(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM tick WHERE n+1 < ?),
                  client(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM client WHERE n+1 < ?)
                INSERT INTO samples SELECT
                    ? + tick.n * ?, printf('gpu%04d', client.n),
                    1, 1, tick.n, tick.n*1024, tick.n*1024, 0,
                    0.1, 68.267, 68.267, 0.0, 0, ?
                FROM tick CROSS JOIN client
            ''', (ticks, args.clients, base_time, args.sample_seconds, epoch))
        seed_peak_mib = sum(p.stat().st_size for p in Path(temporary).glob('metrics.sqlite3*')) / 1024**2
        conn.close()
        seed_seconds = time.perf_counter() - start
        print(f'Seed complete in {seed_seconds:.2f}s; measuring reads and collection...', flush=True)
        reads = []
        for _ in range(3):
            start = time.perf_counter()
            samples = store.latest_samples()
            reads.append(round((time.perf_counter() - start) * 1000, 2))
            assert len(samples) == args.clients
            assert all(s['timestamp'] == base_time + (ticks - 1) * args.sample_seconds for s in samples.values())
        counters = {f'gpu{i:04}': Counters(1, ticks+1, (ticks+1)*1024, (ticks+1)*1024, 0) for i in range(args.clients)}
        start = time.perf_counter()
        store.record_success(base_time + (ticks+1) * args.sample_seconds, HAProxySnapshot(epoch, counters), counters)
        collect_ms = (time.perf_counter() - start) * 1000
        with store._connect() as conn:
            row_count, oldest = conn.execute('SELECT COUNT(*), MIN(timestamp) FROM samples').fetchone()
        assert row_count == args.clients * ticks
        assert oldest == base_time + args.sample_seconds
        size = sum(p.stat().st_size for p in Path(temporary).glob('metrics.sqlite3*'))
        result = {'clients': args.clients, 'history_hours': args.hours, 'sample_seconds': args.sample_seconds,
                  'seeded_rows': args.clients * ticks, 'seed_seconds': round(seed_seconds, 2),
                  'latest_samples_ms': reads, 'record_success_ms': round(collect_ms, 2),
                  'database_mib': round(size / 1024**2, 2),
                  'seed_database_and_wal_mib': round(seed_peak_mib, 2),
                  'expired_rows_removed': args.clients,
                  'synthetic_epoch': epoch,
                  'limitation': 'Synthetic counters in temporary local SQLite; not Contabo disk performance.'}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
