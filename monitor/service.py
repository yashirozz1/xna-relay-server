from __future__ import annotations

import asyncio
from typing import Callable, Protocol

from .config import Instance, Settings
from .haproxy import HAProxySnapshot
from .storage import MetricsStore


class Collector(Protocol):
    def collect(self, instance_ids: set[str]) -> HAProxySnapshot: ...


class MonitorService:
    def __init__(
        self,
        settings: Settings,
        instances: list[Instance],
        collector: Collector,
        store: MetricsStore,
        clock: Callable[[], float],
    ):
        self.settings = settings
        self.instances = instances
        self.instances_by_id = {instance.id: instance for instance in instances}
        self.collector = collector
        self.store = store
        self.clock = clock
        self._stop = asyncio.Event()

    def collect_once(self) -> bool:
        now = self.clock()
        try:
            snapshot = self.collector.collect(set(self.instances_by_id))
            self.store.record_success(now, snapshot, self.instances_by_id)
            return True
        except Exception:
            self.store.record_failure(now)
            return False

    async def sample_forever(self) -> None:
        while not self._stop.is_set():
            await asyncio.to_thread(self.collect_once)
            try:
                await asyncio.wait_for(self._stop.wait(), self.settings.sample_seconds)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()

    def collection_view(self) -> dict:
        state = self.store.collection_state()
        last_success = state["last_success_at"]
        age = None if last_success is None else max(0.0, self.clock() - last_success)
        stale = state["status"] != "ok" or age is None or age > self.settings.stale_after_seconds
        return {
            **state,
            "sample_age_seconds": age,
            "stale_after_seconds": self.settings.stale_after_seconds,
            "stale": stale,
        }

    def health_status(self) -> str:
        view = self.collection_view()
        if view["status"] == "error":
            return "collector_error"
        if view["stale"]:
            return "stale"
        return "ok"
