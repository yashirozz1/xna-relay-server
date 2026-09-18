# PRL Fleet Monitor API

The monitor is a read-only FastAPI service for the HAProxy fleet relay. It reads
only HAProxy's fixed `show stat` and `show info` commands from the configured
user-level Unix socket. It does not accept HAProxy commands from HTTP callers
and has no write or administration endpoint.

## Install and start

For the complete Contabo deployment, use the generated fleet installer described
in [FLEET.md](FLEET.md). It runs this API on loopback and exposes a separate
HAProxy HTTPS listener (default 18444) requiring the `monitor-panel` mTLS
certificate **and** the Bearer token. The panel backend polls the relay; no
outbound webhook is configured. Remote clients validate the relay's private CA
and its `relay.prl.internal` DNS identity (or its IP SAN).

The commands below describe a manual local run.

Create a dedicated virtual environment from the relay bundle directory:

```sh
python3 -m venv .venv-monitor
.venv-monitor/bin/pip install --requirement requirements-monitor.txt
```

The installer must provide these environment variables:

| Variable | Meaning | Default / limit |
|---|---|---|
| `PRL_REGISTRY` | JSON registry path | required; at most 1,024 instances |
| `PRL_STATS_SOCKET` | HAProxy `level user` Unix socket | required |
| `PRL_DB` | persistent SQLite database path | required |
| `PRL_TOKEN_FILE` | Bearer token file | required; one printable ASCII token, at least 32 characters |
| `PRL_SAMPLE_SECONDS` | collection interval | `15`; 5–300 seconds |
| `PRL_RETENTION_HOURS` | history retention | `72`; 1–168 hours |

Run exactly one Uvicorn worker on loopback:

```sh
.venv-monitor/bin/uvicorn --factory monitor.app:create_app \
  --host 127.0.0.1 --port 18080 --workers 1 --no-access-log
```

The import interface for an installer or service check is:

```python
from monitor.app import create_app

app = create_app()  # reads the PRL_* environment variables
```

The token file should be generated with a cryptographically secure random
generator and readable only by the monitor service account. The file is read on
every request, so an atomic file replacement rotates the token without restarting
the process. Missing, malformed, weak, or unreadable token files fail closed.

## HTTP contract

Every endpoint, including `/openapi.json`, requires
`Authorization: Bearer <token>`. Interactive Swagger and ReDoc routes are
disabled. The app installs no browser CORS policy. Requests are limited per
source address; traffic responses contain at most 2,000 samples and cannot span
more than the configured retention window.

The installed service disables forwarded-header trust. Behind the local HAProxy
gateway, the application limit is therefore shared by panel requests (120/minute).
Poll `/v1/instances` every 15–30 seconds for the complete fleet; avoid one request
per instance. Non-finite timestamps (`NaN`, infinity) return 422. API credentials
belong in the panel backend, never in browser JavaScript.

| Endpoint | Result |
|---|---|
| `GET /v1/health` | `200` only for a fresh successful collection; `503` before the first sample, after a collection error, or when the last success is older than two sample intervals |
| `GET /v1/instances` | Registry entries with their latest persisted sample |
| `GET /v1/instances/{id}` | One registered instance and its latest persisted sample |
| `GET /v1/traffic?instance_id=ID&since=UNIX&until=UNIX&limit=500` | Oldest-to-newest persisted samples in the requested inclusive time range |
| `GET /openapi.json` | Authenticated OpenAPI document |

Data endpoints remain available when collection is stale or failing. Their
`collection.stale` field is then `true`, and the payload remains the last known
successful data. A registered backend missing from a successful HAProxy response
is stored as `observed: false`; this is intentionally not reported as confirmed
offline.

Each sample contains current and cumulative connection counts, cumulative byte
and error counters, derived per-second rates, and `discontinuity`. The first
sample, a missing/reappearing backend, a HAProxy process change, a counter reset,
or a non-increasing sample timestamp sets `discontinuity: true` and leaves rate
fields null. Negative rates are never emitted.

`inner_tls_bytes_in` and `inner_tls_bytes_out` are bytes forwarded by HAProxy for
the inner TLS transport. They are not physical-interface or billable-transfer
measurements. The monitor does not inspect mining messages, wallet identifiers,
shares, or hashrate.

## Registry and HAProxy mapping

The registry format is:

```json
{
  "instances": [
    {"id": "gpu01", "label": "GPU 01"}
  ]
}
```

IDs must match `[a-z][a-z0-9_-]{0,31}` and labels are 1–80 characters without
control characters. For each registered ID, the monitor uses only the HAProxy CSV
aggregate row whose proxy name is `pool_ID` and server name is `BACKEND`. Server
rows and unregistered proxy rows are ignored.
