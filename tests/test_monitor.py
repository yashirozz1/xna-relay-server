import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from monitor.app import create_app
from monitor.config import Settings, load_registry
from monitor.haproxy import Counters, HAProxySnapshot, parse_info, parse_stat_csv
from monitor.storage import MetricsStore


TOKEN = "a" * 48


def haproxy_csv(*rows):
    columns = [
        "# pxname",
        "svname",
        "scur",
        "stot",
        "bin",
        "bout",
        "ereq",
        "econ",
        "eresp",
        "status",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


class FakeClock:
    def __init__(self, value=1_700_000_000.0):
        self.value = value

    def __call__(self):
        return self.value


class QueueCollector:
    def __init__(self, *results):
        self.results = list(results)

    def collect(self, _instance_ids):
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class MonitorTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.registry = root / "registry.json"
        self.registry.write_text(
            json.dumps(
                {
                    "instances": [
                        {"id": "gpu01", "label": "GPU 01"},
                        {"id": "gpu02", "label": "GPU 02"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.token_file = root / "api-token"
        self.token_file.write_text(TOKEN + "\n", encoding="ascii")
        self.settings = Settings(
            registry_path=self.registry,
            stats_socket=root / "stats.sock",
            db_path=root / "metrics.sqlite3",
            token_file=self.token_file,
            sample_seconds=15,
            retention_hours=72,
        )
        self.clock = FakeClock()

    def tearDown(self):
        self.tempdir.cleanup()

    def app_client(self, collector):
        app = create_app(
            settings=self.settings,
            collector=collector,
            clock=self.clock,
            start_sampler=False,
        )
        return app, TestClient(app)

    @staticmethod
    def auth(token=TOKEN):
        return {"Authorization": f"Bearer {token}"}

    def test_nonfinite_timestamps_are_rejected_as_bad_queries(self):
        _app, client = self.app_client(QueueCollector())
        for field in ('since', 'until'):
            for value in ('nan', 'inf', '-inf'):
                with self.subTest(field=field, value=value):
                    params = {'instance_id': 'gpu01', 'since': 0, 'until': 10, field: value}
                    response = client.get('/v1/traffic', params=params, headers=self.auth())
                    self.assertEqual(response.status_code, 422)

    def test_parser_maps_only_registered_backend_aggregate_rows(self):
        payload = haproxy_csv(
            {
                "# pxname": "pool_gpu01",
                "svname": "BACKEND",
                "scur": "3",
                "stot": "12",
                "bin": "1000",
                "bout": "2000",
                "ereq": "1",
                "econ": "2",
                "eresp": "3",
                "status": "UP",
            },
            {
                "# pxname": "pool_gpu01",
                "svname": "pool",
                "scur": "99",
                "stot": "99",
                "bin": "99",
                "bout": "99",
                "ereq": "99",
                "econ": "99",
                "eresp": "99",
                "status": "UP",
            },
            {
                "# pxname": "pool_unknown",
                "svname": "BACKEND",
                "scur": "7",
                "stot": "8",
                "bin": "9",
                "bout": "10",
                "ereq": "0",
                "econ": "0",
                "eresp": "0",
                "status": "UP",
            },
        )

        parsed = parse_stat_csv(payload, {"gpu01", "gpu02"})

        self.assertEqual(
            parsed,
            {
                "gpu01": Counters(
                    current_connections=3,
                    total_connections=12,
                    inner_tls_bytes_in=1000,
                    inner_tls_bytes_out=2000,
                    errors=6,
                )
            },
        )

    def test_haproxy_epoch_is_stable_as_uptime_advances(self):
        first = "Name: HAProxy\nVersion: 2.8.5\nProcess_num: 1\nPid: 123\nUptime_sec: 15\n"
        second = "Name: HAProxy\nVersion: 2.8.5\nProcess_num: 1\nPid: 123\nUptime_sec: 30\n"

        self.assertEqual(parse_info(first), parse_info(second))

    def test_registry_accepts_1024_valid_unique_instances_but_not_more(self):
        root = Path(self.tempdir.name)
        self.registry.write_text(
            json.dumps(
                {
                    "instances": [
                        {"id": f"g{i:04d}", "label": f"GPU {i}"}
                        for i in range(1024)
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(len(load_registry(self.registry)), 1024)

        data = json.loads(self.registry.read_text(encoding="utf-8"))
        data["instances"].append({"id": "overflow", "label": "Overflow"})
        self.registry.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "1024"):
            load_registry(self.registry)

    def test_all_routes_including_openapi_require_strong_file_token(self):
        snapshot = HAProxySnapshot(epoch="pid:1:start:10", counters={})
        _, client = self.app_client(QueueCollector(snapshot))

        for path in ("/v1/health", "/v1/instances", "/openapi.json"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 401)
                self.assertEqual(
                    client.get(path, headers=self.auth("wrong" * 10)).status_code,
                    401,
                )

        self.assertEqual(client.get("/docs", headers=self.auth()).status_code, 404)
        self.assertEqual(client.get("/redoc", headers=self.auth()).status_code, 404)
        response = client.get("/openapi.json", headers=self.auth())
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("/docs", response.json()["paths"])
        self.assertIsNone(response.headers.get("access-control-allow-origin"))

    def test_weak_token_file_fails_closed(self):
        self.token_file.write_text("short-token\n", encoding="ascii")
        _, client = self.app_client(QueueCollector())

        response = client.get("/v1/health", headers=self.auth("short-token"))

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "authentication unavailable")

    def test_collection_exposes_current_metrics_and_rates(self):
        first = HAProxySnapshot(
            epoch="pid:1:start:10",
            counters={
                "gpu01": Counters(2, 10, 1000, 2000, 1),
            },
        )
        second = HAProxySnapshot(
            epoch="pid:1:start:10",
            counters={
                "gpu01": Counters(3, 16, 1600, 3200, 4),
            },
        )
        app, client = self.app_client(QueueCollector(first, second))

        app.state.monitor.collect_once()
        self.clock.value += 15
        app.state.monitor.collect_once()
        response = client.get("/v1/instances/gpu01", headers=self.auth())

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["instance"]["id"], "gpu01")
        self.assertEqual(body["sample"]["current_connections"], 3)
        self.assertEqual(body["sample"]["inner_tls_bytes_in"], 1600)
        self.assertEqual(body["sample"]["inner_tls_bytes_in_per_second"], 40.0)
        self.assertEqual(body["sample"]["connections_per_second"], 0.4)
        self.assertFalse(body["sample"]["discontinuity"])
        self.assertIn("not physical-link or billing", body["metrics_scope"])

    def test_counter_reset_marks_discontinuity_without_negative_rates(self):
        store = MetricsStore(self.settings.db_path, retention_hours=72)
        store.record_success(
            100.0,
            HAProxySnapshot(
                epoch="pid:1:start:10",
                counters={"gpu01": Counters(2, 20, 2000, 4000, 8)},
            ),
            ["gpu01"],
        )
        store.record_success(
            115.0,
            HAProxySnapshot(
                epoch="pid:2:start:20",
                counters={"gpu01": Counters(1, 1, 100, 200, 0)},
            ),
            ["gpu01"],
        )

        sample = store.latest_sample("gpu01")

        self.assertTrue(sample["discontinuity"])
        self.assertIsNone(sample["inner_tls_bytes_in_per_second"])
        self.assertIsNone(sample["connections_per_second"])
        self.assertFalse(
            any(isinstance(value, float) and value < 0 for value in sample.values())
        )

    def test_missing_backend_is_unobserved_not_offline(self):
        app, client = self.app_client(
            QueueCollector(HAProxySnapshot(epoch="pid:1:start:10", counters={}))
        )
        app.state.monitor.collect_once()

        response = client.get("/v1/instances/gpu02", headers=self.auth())

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["sample"]["observed"])
        self.assertNotIn("offline", json.dumps(response.json()).lower())

    def test_failed_collection_makes_health_503_but_preserves_stale_data(self):
        app, client = self.app_client(
            QueueCollector(
                HAProxySnapshot(
                    epoch="pid:1:start:10",
                    counters={"gpu01": Counters(1, 2, 300, 400, 0)},
                ),
                OSError("secret socket pathname and internal detail"),
            )
        )
        app.state.monitor.collect_once()
        self.clock.value += 15
        app.state.monitor.collect_once()

        health = client.get("/v1/health", headers=self.auth())
        instance = client.get("/v1/instances/gpu01", headers=self.auth())

        self.assertEqual(health.status_code, 503)
        self.assertEqual(health.json()["status"], "collector_error")
        self.assertEqual(health.json()["collection"]["error"], "collection failed")
        self.assertEqual(instance.status_code, 200)
        self.assertTrue(instance.json()["collection"]["stale"])
        self.assertEqual(instance.json()["sample"]["inner_tls_bytes_in"], 300)
        self.assertNotIn("secret", json.dumps(health.json()))

    def test_sample_age_makes_health_stale_without_erasing_last_sample(self):
        app, client = self.app_client(
            QueueCollector(
                HAProxySnapshot(
                    epoch="pid:1:start:10",
                    counters={"gpu01": Counters(0, 0, 0, 0, 0)},
                )
            )
        )
        app.state.monitor.collect_once()
        self.clock.value += 31

        health = client.get("/v1/health", headers=self.auth())
        instances = client.get("/v1/instances", headers=self.auth())

        self.assertEqual(health.status_code, 503)
        self.assertEqual(health.json()["status"], "stale")
        self.assertTrue(instances.json()["collection"]["stale"])
        self.assertEqual(len(instances.json()["instances"]), 2)

    def test_retention_and_traffic_query_use_real_sqlite_and_enforce_bounds(self):
        store = MetricsStore(self.settings.db_path, retention_hours=1)
        snapshot = HAProxySnapshot(
            epoch="pid:1:start:10",
            counters={"gpu01": Counters(1, 1, 100, 200, 0)},
        )
        store.record_success(100.0, snapshot, ["gpu01"])
        store.record_success(3_800.0, snapshot, ["gpu01"])
        self.assertEqual(
            [row["timestamp"] for row in store.query("gpu01", 0, 4_000, 2000)],
            [3800.0],
        )

        self.settings = Settings(
            registry_path=self.settings.registry_path,
            stats_socket=self.settings.stats_socket,
            db_path=self.settings.db_path,
            token_file=self.settings.token_file,
            sample_seconds=15,
            retention_hours=1,
        )
        _, client = self.app_client(QueueCollector())
        valid = client.get(
            "/v1/traffic?instance_id=gpu01&since=3700&until=3900&limit=1",
            headers=self.auth(),
        )
        too_many = client.get(
            "/v1/traffic?instance_id=gpu01&since=3700&until=3900&limit=2001",
            headers=self.auth(),
        )
        reversed_range = client.get(
            "/v1/traffic?instance_id=gpu01&since=3900&until=3700",
            headers=self.auth(),
        )

        self.assertEqual(valid.status_code, 200)
        self.assertEqual(len(valid.json()["samples"]), 1)
        self.assertEqual(too_many.status_code, 422)
        self.assertEqual(reversed_range.status_code, 422)


if __name__ == "__main__":
    unittest.main()
