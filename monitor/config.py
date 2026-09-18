from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


INSTANCE_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
MAX_INSTANCES = 1024
MAX_REGISTRY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Instance:
    id: str
    label: str


@dataclass(frozen=True)
class Settings:
    registry_path: Path
    stats_socket: Path
    db_path: Path
    token_file: Path
    sample_seconds: int = 15
    retention_hours: int = 72
    socket_timeout_seconds: float = 2.0
    max_socket_bytes: int = 4 * 1024 * 1024
    requests_per_minute: int = 120

    def __post_init__(self) -> None:
        for field_name in ("registry_path", "stats_socket", "db_path", "token_file"):
            object.__setattr__(self, field_name, Path(getattr(self, field_name)))
        if not 5 <= self.sample_seconds <= 300:
            raise ValueError("PRL_SAMPLE_SECONDS must be between 5 and 300")
        if not 1 <= self.retention_hours <= 168:
            raise ValueError("PRL_RETENTION_HOURS must be between 1 and 168")
        if not 1 <= self.requests_per_minute <= 10_000:
            raise ValueError("requests_per_minute is out of range")

    @property
    def stale_after_seconds(self) -> int:
        return self.sample_seconds * 2

    @classmethod
    def from_env(cls) -> "Settings":
        required = {
            "registry_path": "PRL_REGISTRY",
            "stats_socket": "PRL_STATS_SOCKET",
            "db_path": "PRL_DB",
            "token_file": "PRL_TOKEN_FILE",
        }
        missing = [env for env in required.values() if not os.environ.get(env)]
        if missing:
            raise RuntimeError("missing monitor environment: " + ", ".join(missing))
        return cls(
            **{name: Path(os.environ[env]) for name, env in required.items()},
            sample_seconds=_env_int("PRL_SAMPLE_SECONDS", 15),
            retention_hours=_env_int("PRL_RETENTION_HOURS", 72),
        )


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def load_registry(path: Path) -> list[Instance]:
    path = Path(path)
    if path.stat().st_size > MAX_REGISTRY_BYTES:
        raise ValueError("registry exceeds 1 MiB")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("registry is unreadable or invalid JSON") from exc
    if not isinstance(document, dict) or set(document) != {"instances"}:
        raise ValueError("registry must contain only an instances array")
    rows = document["instances"]
    if not isinstance(rows, list) or len(rows) > MAX_INSTANCES:
        raise ValueError(f"registry supports at most {MAX_INSTANCES} instances")

    instances: list[Instance] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "label"}:
            raise ValueError("each registry instance requires only id and label")
        instance_id = row["id"]
        label = row["label"]
        if not isinstance(instance_id, str) or not INSTANCE_ID.fullmatch(instance_id):
            raise ValueError("invalid registry instance id")
        if instance_id in seen:
            raise ValueError("duplicate registry instance id")
        if (
            not isinstance(label, str)
            or not 1 <= len(label) <= 80
            or any(ord(character) < 32 or ord(character) == 127 for character in label)
        ):
            raise ValueError("invalid registry instance label")
        seen.add(instance_id)
        instances.append(Instance(instance_id, label))
    return instances
