from __future__ import annotations

import csv
import io
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Counters:
    current_connections: int
    total_connections: int
    inner_tls_bytes_in: int
    inner_tls_bytes_out: int
    errors: int


@dataclass(frozen=True)
class HAProxySnapshot:
    epoch: str
    counters: dict[str, Counters]


def _nonnegative_int(value: str | None) -> int:
    if value in (None, ""):
        return 0
    number = int(value)
    if number < 0:
        raise ValueError("HAProxy counter is negative")
    return number


def parse_stat_csv(payload: str, registry_ids: Iterable[str]) -> dict[str, Counters]:
    allowed = set(registry_ids)
    reader = csv.DictReader(io.StringIO(payload))
    if not reader.fieldnames or "# pxname" not in reader.fieldnames or "svname" not in reader.fieldnames:
        raise ValueError("invalid HAProxy stat header")
    parsed: dict[str, Counters] = {}
    for row in reader:
        pxname = row.get("# pxname", "")
        if row.get("svname") != "BACKEND" or not pxname.startswith("pool_"):
            continue
        instance_id = pxname[5:]
        if instance_id not in allowed:
            continue
        if instance_id in parsed:
            raise ValueError("duplicate HAProxy backend aggregate")
        try:
            parsed[instance_id] = Counters(
                current_connections=_nonnegative_int(row.get("scur")),
                total_connections=_nonnegative_int(row.get("stot")),
                inner_tls_bytes_in=_nonnegative_int(row.get("bin")),
                inner_tls_bytes_out=_nonnegative_int(row.get("bout")),
                errors=sum(
                    _nonnegative_int(row.get(field))
                    for field in ("ereq", "econ", "eresp")
                ),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid HAProxy stat counter") from exc
    return parsed


def parse_info(payload: str) -> str:
    values: dict[str, str] = {}
    for line in payload.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    identity_parts = [
        values.get("Name", ""),
        values.get("Version", ""),
        values.get("Process_num", ""),
        values.get("Pid", ""),
        values.get("Start_time_sec", ""),
        values.get("Reloads", ""),
    ]
    if not values.get("Pid"):
        raise ValueError("invalid HAProxy info response")
    return "|".join(identity_parts)


class HAProxyStatsClient:
    """Reads only the two user-level HAProxy commands needed by the monitor."""

    def __init__(self, path: Path, timeout_seconds: float = 2.0, max_bytes: int = 4 * 1024 * 1024):
        self._path = str(path)
        self._timeout_seconds = timeout_seconds
        self._max_bytes = max_bytes

    def collect(self, instance_ids: Iterable[str]) -> HAProxySnapshot:
        stats = self._read_fixed(b"show stat\n")
        info = self._read_fixed(b"show info\n")
        return HAProxySnapshot(
            epoch=parse_info(info),
            counters=parse_stat_csv(stats, instance_ids),
        )

    def _read_fixed(self, command: bytes) -> str:
        chunks: list[bytes] = []
        received = 0
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self._timeout_seconds)
            client.connect(self._path)
            client.sendall(command)
            client.shutdown(socket.SHUT_WR)
            while True:
                chunk = client.recv(min(65_536, self._max_bytes + 1 - received))
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
                if received > self._max_bytes:
                    raise ValueError("HAProxy response exceeds configured limit")
        return b"".join(chunks).decode("utf-8", errors="strict")
