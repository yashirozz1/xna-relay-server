from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .haproxy import HAProxySnapshot


COUNTER_FIELDS = (
    "total_connections",
    "inner_tls_bytes_in",
    "inner_tls_bytes_out",
    "errors",
)


class MetricsStore:
    def __init__(self, path: Path, retention_hours: int):
        self.path = Path(path)
        self.retention_seconds = retention_hours * 3600
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=2.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 2000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS samples (
                    timestamp REAL NOT NULL,
                    instance_id TEXT NOT NULL,
                    observed INTEGER NOT NULL,
                    current_connections INTEGER,
                    total_connections INTEGER,
                    inner_tls_bytes_in INTEGER,
                    inner_tls_bytes_out INTEGER,
                    errors INTEGER,
                    connections_per_second REAL,
                    inner_tls_bytes_in_per_second REAL,
                    inner_tls_bytes_out_per_second REAL,
                    errors_per_second REAL,
                    discontinuity INTEGER NOT NULL,
                    collector_epoch TEXT NOT NULL,
                    PRIMARY KEY (timestamp, instance_id)
                );
                CREATE INDEX IF NOT EXISTS samples_instance_time
                    ON samples(instance_id, timestamp DESC);
                CREATE TABLE IF NOT EXISTS collection_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    last_attempt_at REAL,
                    last_success_at REAL,
                    status TEXT NOT NULL,
                    error TEXT
                );
                """
            )

    def record_success(
        self,
        timestamp: float,
        snapshot: HAProxySnapshot,
        instance_ids: Iterable[str],
    ) -> None:
        instance_ids = list(instance_ids)
        with self._write_lock, self._connect() as connection:
            latest = self._latest_by_instance(connection)
            rows = []
            for instance_id in instance_ids:
                current = snapshot.counters.get(instance_id)
                previous = latest.get(instance_id)
                if current is None:
                    rows.append(
                        (
                            timestamp,
                            instance_id,
                            0,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            1,
                            snapshot.epoch,
                        )
                    )
                    continue

                discontinuity = self._is_discontinuity(previous, current, snapshot.epoch)
                rates: dict[str, float | None] = {field: None for field in COUNTER_FIELDS}
                if not discontinuity and previous is not None:
                    elapsed = timestamp - previous["timestamp"]
                    if elapsed > 0:
                        for field in COUNTER_FIELDS:
                            rates[field] = (getattr(current, field) - previous[field]) / elapsed
                    else:
                        discontinuity = True
                rows.append(
                    (
                        timestamp,
                        instance_id,
                        1,
                        current.current_connections,
                        current.total_connections,
                        current.inner_tls_bytes_in,
                        current.inner_tls_bytes_out,
                        current.errors,
                        rates["total_connections"] if not discontinuity else None,
                        rates["inner_tls_bytes_in"] if not discontinuity else None,
                        rates["inner_tls_bytes_out"] if not discontinuity else None,
                        rates["errors"] if not discontinuity else None,
                        int(discontinuity),
                        snapshot.epoch,
                    )
                )

            connection.executemany(
                """
                INSERT INTO samples (
                    timestamp, instance_id, observed, current_connections,
                    total_connections, inner_tls_bytes_in, inner_tls_bytes_out,
                    errors, connections_per_second,
                    inner_tls_bytes_in_per_second,
                    inner_tls_bytes_out_per_second, errors_per_second,
                    discontinuity, collector_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            connection.execute(
                "DELETE FROM samples WHERE timestamp < ?", (timestamp - self.retention_seconds,)
            )
            connection.execute(
                """
                INSERT INTO collection_state
                    (singleton, last_attempt_at, last_success_at, status, error)
                VALUES (1, ?, ?, 'ok', NULL)
                ON CONFLICT(singleton) DO UPDATE SET
                    last_attempt_at=excluded.last_attempt_at,
                    last_success_at=excluded.last_success_at,
                    status='ok', error=NULL
                """,
                (timestamp, timestamp),
            )

    @staticmethod
    def _latest_by_instance(connection: sqlite3.Connection) -> dict[str, sqlite3.Row]:
        rows = connection.execute(
            """
            SELECT s.* FROM samples AS s
            INNER JOIN (
                SELECT instance_id, MAX(timestamp) AS timestamp
                FROM samples GROUP BY instance_id
            ) AS latest
            ON latest.instance_id = s.instance_id AND latest.timestamp = s.timestamp
            """
        ).fetchall()
        return {row["instance_id"]: row for row in rows}

    @staticmethod
    def _is_discontinuity(previous: sqlite3.Row | None, current: Any, epoch: str) -> bool:
        if previous is None or not previous["observed"] or previous["collector_epoch"] != epoch:
            return True
        return any(getattr(current, field) < previous[field] for field in COUNTER_FIELDS)

    def record_failure(self, timestamp: float) -> None:
        with self._write_lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO collection_state
                    (singleton, last_attempt_at, last_success_at, status, error)
                VALUES (1, ?, NULL, 'error', 'collection failed')
                ON CONFLICT(singleton) DO UPDATE SET
                    last_attempt_at=excluded.last_attempt_at,
                    status='error', error='collection failed'
                """,
                (timestamp,),
            )

    def collection_state(self) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT last_attempt_at, last_success_at, status, error FROM collection_state WHERE singleton=1"
            ).fetchone()
        if row is None:
            return {
                "last_attempt_at": None,
                "last_success_at": None,
                "status": "never",
                "error": None,
            }
        return dict(row)

    def latest_sample(self, instance_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM samples WHERE instance_id=? ORDER BY timestamp DESC LIMIT 1",
                (instance_id,),
            ).fetchone()
        return self._public_row(row) if row else None

    def latest_samples(self) -> dict[str, dict[str, Any]]:
        with self._connect() as connection:
            rows = self._latest_by_instance(connection).values()
            return {row["instance_id"]: self._public_row(row) for row in rows}

    def query(self, instance_id: str, since: float, until: float, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM samples
                WHERE instance_id=? AND timestamp>=? AND timestamp<=?
                ORDER BY timestamp ASC LIMIT ?
                """,
                (instance_id, since, until, limit),
            ).fetchall()
        return [self._public_row(row) for row in rows]

    @staticmethod
    def _public_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result.pop("collector_epoch", None)
        result["observed"] = bool(result["observed"])
        result["discontinuity"] = bool(result["discontinuity"])
        return result
