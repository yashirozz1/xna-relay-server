from __future__ import annotations

import asyncio
import hmac
import math
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, load_registry
from .haproxy import HAProxyStatsClient
from .service import Collector, MonitorService
from .storage import MetricsStore


METRICS_SCOPE = (
    "HAProxy forwarded inner-TLS transport bytes and connection/error counters; "
    "not physical-link or billing measurements and no mining content is inspected."
)
MAX_TRAFFIC_ROWS = 2000
MAX_TOKEN_BYTES = 4096


class SlidingWindowRateLimiter:
    def __init__(self, requests_per_minute: int, clock: Callable[[], float]):
        self.limit = requests_per_minute
        self.clock = clock
        self.requests: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock()
        bucket = self.requests[key]
        cutoff = now - 60
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        if len(self.requests) > 4096:
            empty_or_old = [
                item_key
                for item_key, values in self.requests.items()
                if not values or values[-1] <= cutoff
            ]
            for item_key in empty_or_old[:1024]:
                self.requests.pop(item_key, None)
        return True


def _read_token(path: Path) -> str:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_TOKEN_BYTES + 1)
    except OSError as exc:
        raise RuntimeError("authentication unavailable") from exc
    if len(raw) > MAX_TOKEN_BYTES:
        raise RuntimeError("authentication unavailable")
    try:
        token = raw.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise RuntimeError("authentication unavailable") from exc
    if (
        len(token) < 32
        or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)
        or raw not in (token.encode("ascii"), token.encode("ascii") + b"\n", token.encode("ascii") + b"\r\n")
    ):
        raise RuntimeError("authentication unavailable")
    return token


def create_app(
    settings: Settings | None = None,
    collector: Collector | None = None,
    clock: Callable[[], float] = time.time,
    start_sampler: bool = True,
) -> FastAPI:
    settings = settings or Settings.from_env()
    instances = load_registry(settings.registry_path)
    store = MetricsStore(settings.db_path, settings.retention_hours)
    collector = collector or HAProxyStatsClient(
        settings.stats_socket,
        settings.socket_timeout_seconds,
        settings.max_socket_bytes,
    )
    monitor = MonitorService(settings, instances, collector, store, clock)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(monitor.sample_forever()) if start_sampler else None
        try:
            yield
        finally:
            if task is not None:
                monitor.stop()
                await task

    bearer = HTTPBearer(auto_error=False)
    limiter = SlidingWindowRateLimiter(settings.requests_per_minute, clock)

    async def authorize(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> None:
        try:
            expected = _read_token(settings.token_file)
        except RuntimeError:
            raise HTTPException(status_code=503, detail="authentication unavailable")
        if (
            credentials is None
            or credentials.scheme.lower() != "bearer"
            or not hmac.compare_digest(credentials.credentials, expected)
        ):
            raise HTTPException(
                status_code=401,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        client_key = request.client.host if request.client else "local"
        if not limiter.allow(client_key):
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    app = FastAPI(
        title="PRL Fleet Monitor",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        dependencies=[Depends(authorize)],
        lifespan=lifespan,
    )
    app.state.monitor = monitor

    @app.get("/openapi.json", include_in_schema=False)
    def openapi():
        return JSONResponse(app.openapi())

    @app.get("/v1/health")
    def health():
        status = monitor.health_status()
        body = {"status": status, "collection": monitor.collection_view()}
        return JSONResponse(body, status_code=200 if status == "ok" else 503)

    @app.get("/v1/instances")
    def list_instances():
        samples = store.latest_samples()
        return {
            "instances": [
                {
                    "id": instance.id,
                    "label": instance.label,
                    "sample": samples.get(instance.id),
                }
                for instance in instances
            ],
            "collection": monitor.collection_view(),
            "metrics_scope": METRICS_SCOPE,
        }

    @app.get("/v1/instances/{instance_id}")
    def get_instance(instance_id: str):
        instance = monitor.instances_by_id.get(instance_id)
        if instance is None:
            raise HTTPException(status_code=404, detail="instance not found")
        return {
            "instance": {"id": instance.id, "label": instance.label},
            "sample": store.latest_sample(instance_id),
            "collection": monitor.collection_view(),
            "metrics_scope": METRICS_SCOPE,
        }

    @app.get("/v1/traffic")
    def traffic(
        instance_id: str,
        since: float,
        until: float,
        limit: int = Query(default=500, ge=1, le=MAX_TRAFFIC_ROWS),
    ):
        if instance_id not in monitor.instances_by_id:
            raise HTTPException(status_code=404, detail="instance not found")
        if not math.isfinite(since) or not math.isfinite(until):
            raise HTTPException(status_code=422, detail="timestamps must be finite")
        if since > until:
            raise HTTPException(status_code=422, detail="since must not exceed until")
        if until - since > settings.retention_hours * 3600:
            raise HTTPException(status_code=422, detail="query range exceeds retention")
        rows = store.query(instance_id, since, until, limit + 1)
        return {
            "instance_id": instance_id,
            "since": since,
            "until": until,
            "samples": rows[:limit],
            "truncated": len(rows) > limit,
            "collection": monitor.collection_view(),
            "metrics_scope": METRICS_SCOPE,
        }

    return app
