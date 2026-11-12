# Webalizer Threat Triage

[![CI](https://github.com/SneakySep/webalizer-threat-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/SneakySep/webalizer-threat-triage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Production-oriented asynchronous URL and domain threat triage backed by
**FastAPI**, **VirusTotal API v3**, **Celery**, **Redis**, and **PostgreSQL**.

## Architecture

```text
                        +------------------+
  POST /triage/scan --> | FastAPI          |
                        | validate + cache | ---- cache hit ----> 200 + result
                        +--------+---------+
                                 | miss / forced refresh
                                 v
                        +------------------+
                        | Redis            |
                        | lock + status    | <---- status polling
                        +--------+---------+
                                 | Celery broker
                                 v
                        +------------------+
                        | Celery worker    |
                        | global rate limiter
                        | VT client + poll |
                        +---+----------+---+
                            |          |
                 normalized |          | raw
                            v          v
                    +------------------+
                    | PostgreSQL       |
                    | triage_reports   |
                    +------------------+
```

A scan is never performed inside an HTTP request. FastAPI validates the target,
checks the 24-hour Redis result cache, deduplicates in-flight identical scans, and
enqueues a Celery task. The worker handles VirusTotal rate limits, the two-step
URL analysis flow, normalization, persistence, and cache population.

## Features

- URL and domain validation, canonicalization, IDNA support, and unsafe-IP blocking.
- VirusTotal-compatible URL base64 IDs and SHA-256 cache keys.
- 24-hour Redis result cache with cache-versioning and corruption handling.
- In-flight deduplication so identical targets do not consume duplicate VT quota.
- Configurable Celery rate limit plus a process-shared Redis token bucket.
- Two-step VirusTotal URL submission and exponential-backoff polling.
- Analysis-ID persistence across Celery retries to avoid duplicate submissions.
- Normalized, UI-ready reports: risk score, verdict, engine stats, detections,
  categories, DNS records, and scan timestamp.
- Historical reports in PostgreSQL with JSONB raw and normalized payloads.
- Consistent JSON error envelope, optional API-key auth, and health checks.
- Unit and contract tests with mocked VirusTotal, Redis, and database access.

## Project layout

```text
.github/
  workflows/ci.yml              CI: lint, tests, Compose, image, scripts
  dependabot.yml                dependency update automation
app/
  main.py                       FastAPI app, lifespan, health routes
  config.py                     Pydantic Settings
  database.py                   async + sync SQLAlchemy engines
  celery_app.py                 Celery configuration and worker signals
  errors.py                     error envelope and exception handlers
  api/
    deps.py                     DB/cache/auth dependencies
    v1/router.py
    v1/endpoints/triage.py      scan, status, report
  models/triage_report.py       triage_reports SQLAlchemy model
  schemas/triage.py             Pydantic v2 request/response schemas
  services/
    cache.py                    Redis cache, task state, locks
    dispatcher.py               Celery task publish abstraction
    normalizer.py               VirusTotal JSON -> TriageResult
    rate_limit.py               global Redis token bucket
    triage.py                   worker orchestration
    virustotal.py               VT v3 HTTP client and error mapping
  tasks/vt_worker.py            Celery task and retry handling
  utils/helpers.py              validation, hashing, cache keys
alembic/                        database migrations
scripts/
  verify_vt_key.py              VirusTotal key/connectivity preflight
  enable-live-scans.ps1         One-command live-scan setup (Windows)
tests/                          pytest suite
```

## Requirements

- Python 3.11 or newer for local development and tests.
- Docker Engine with Compose v2 for the full stack.
- A VirusTotal API key for live scans. The test suite does not require one.

## Quick start

1. Clone the repository:

   ```bash
   git clone https://github.com/SneakySep/webalizer-threat-triage.git
   cd webalizer-threat-triage
   ```

2. Create `.env` if it does not exist and set your VirusTotal key:

   ```powershell
   Copy-Item .env.example .env
   # edit .env and set: VT_API_KEY=...
   ```

   On Linux/macOS: `cp .env.example .env`. `.env` is gitignored and is excluded
   from the Docker image. Never commit it.

3. Enable live scans:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\enable-live-scans.ps1
   ```

   This verifies the key is present, rebuilds and recreates the API and worker,
   waits for readiness, and performs a single-request VirusTotal preflight. To
   do it manually:

   ```bash
   docker compose up -d --build
   docker compose exec -T worker python -m scripts.verify_vt_key
   ```

   `docker compose restart worker` does **not** reload `.env`; containers must be
   recreated for a new key to take effect.

4. Verify readiness and open the API docs:

   ```bash
   curl http://localhost:8000/health/ready
   # http://localhost:8000/docs
   ```

Without `VT_API_KEY`, the stack still starts, but scans fail safely with
`VT_AUTH_FAILED`. The worker logs a startup warning in that case.

The preflight performs one real domain lookup, so it consumes one request from
your VirusTotal quota. A `200` means the key and outbound connectivity are valid;
`401`/`403` means the key was rejected; `429` means the key was accepted but the
quota is exhausted.

## API

### Submit a scan

```bash
curl -X POST http://localhost:8000/api/v1/triage/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com/login", "force_refresh": false}'
```

On Windows PowerShell, use `Invoke-RestMethod`; native `curl.exe` argument
handling can strip the JSON quotes:

```powershell
$body = @{ target = 'https://example.com/login'; force_refresh = $false } |
  ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri 'http://localhost:8000/api/v1/triage/scan' `
  -ContentType 'application/json' `
  -Body $body
```

New scan (`202`):

```json
{
  "task_id": "0b685a75-c53b-4b45-91d2-3db4f5a8f3e6",
  "status": "queued",
  "cached": false,
  "deduplicated": false,
  "report_id": null,
  "result": null,
  "poll_url": "/api/v1/triage/status/0b685a75-c53b-4b45-91d2-3db4f5a8f3e6"
}
```

Cache hit (`200`) includes the original `task_id`, `report_id`, and the complete
normalized `result` inline. `force_refresh: true` bypasses the result cache but
still joins an already-running identical scan.

### Poll task status

```bash
curl http://localhost:8000/api/v1/triage/status/<task_id>
```

Statuses: `queued`, `processing`, `retrying`, `completed`, `failed`.

A completed response contains `report_id` and `report_url`. A failed response
contains a safe `error` object:

```json
{
  "task_id": "...",
  "status": "failed",
  "target": "example.com",
  "target_type": "domain",
  "attempt": 5,
  "report_id": null,
  "error": {
    "code": "VT_RATE_LIMITED",
    "message": "VirusTotal rate limit exceeded.",
    "retryable": true
  },
  "created_at": "...",
  "updated_at": "..."
}
```

### Retrieve a stored report

```bash
curl http://localhost:8000/api/v1/triage/report/<report_id>
curl "http://localhost:8000/api/v1/triage/report/<report_id>?include_raw=true"
```

The raw VirusTotal JSON is omitted by default to keep responses small and
UI-focused.

### Optional authentication

Set `TRIAGE_API_KEY` to require `X-API-Key` on all `/api/v1/triage/*` endpoints.
Leave it empty to disable authentication (local development).

## Normalized result

```json
{
  "target": "example.com",
  "target_type": "domain",
  "risk_score": 2.22,
  "detection_ratio": "2/90",
  "verdict": "malicious",
  "engine_stats": {
    "malicious": 2,
    "suspicious": 1,
    "undetected": 27,
    "harmless": 60,
    "timeout": 2,
    "total": 90
  },
  "detections": [
    {
      "engine_name": "EngineA",
      "category": "malicious",
      "result": "phishing",
      "method": "blacklist",
      "version": null
    }
  ],
  "categories": ["Malware", "Phishing"],
  "dns_records": [
    {"type": "A", "value": "93.184.216.34", "ttl": 300, "priority": null},
    {"type": "MX", "value": "mail.example.com", "ttl": null, "priority": 10}
  ],
  "scan_date": "2023-11-14T22:13:20Z"
}
```

- `risk_score` is `malicious / engines_with_verdict * 100` (0–100).
- Timeouts do not dilute the risk denominator.
- Verdict thresholds are configurable through `MALICIOUS_MIN_ENGINES` and
  `SUSPICIOUS_MIN_ENGINES`. With no usable engine verdicts, the verdict is
  `unknown`.
- `detections` contains only engines that returned `malicious` or `suspicious`.
- DNS parsing is limited to A, AAAA, MX, and NS records.

## Caching and rate limiting

Cache keys follow the required format:

```text
vt_cache:url:<sha256(normalized_url)>
vt_cache:domain:<normalized_domain>
```

The cache envelope includes the originating task ID, report ID, normalized
result, timestamp, and schema version. Entries are written only after a
successful scan and expire after `CACHE_TTL_SECONDS` (default 24 hours). Malformed
or version-mismatched entries are deleted and treated as misses.

VirusTotal's free tier allows roughly **4 requests per minute and 500 per day**.
Every HTTP request passes through a Redis token bucket shared by all worker
instances. Celery also applies a task rate limit, but the Redis limiter is the
authoritative quota guard because a single URL task may make several requests.
`429` responses are retried with backoff and `Retry-After` support.

In-flight locks use `triage:lock:<cache_key>`. They are held across Celery
retries and released on success or terminal failure. Task state is stored under
`triage:status:<task_id>` for seven days by default.

## Error handling

All API errors use one envelope:

```json
{
  "error": {
    "code": "INVALID_TARGET",
    "message": "only http:// and https:// URLs are supported"
  }
}
```

| Condition | Behavior |
|---|---|
| Invalid URL/domain | `422 INVALID_TARGET` |
| Request schema failure | `422 VALIDATION_ERROR` |
| Unknown task/report | `404 TASK_NOT_FOUND` / `REPORT_NOT_FOUND` |
| Redis unavailable | `503 CACHE_UNAVAILABLE` |
| Broker publish failure | `503 QUEUE_UNAVAILABLE` |
| PostgreSQL unavailable | `503 DATABASE_UNAVAILABLE` |
| VT invalid key (`401`) | task `failed` with `VT_AUTH_FAILED`, no retries |
| VT rate limit (`429`) | task `retrying`, exponential backoff, then `VT_RATE_LIMITED` |
| VT 5xx/timeout | retried with exponential backoff |
| Domain not found in VT | completed report with verdict `unknown` |

Upstream 401 errors are never returned as client 401s; they indicate a server
configuration problem and are surfaced through the asynchronous task status.

## Database migrations

```bash
docker compose run --rm migrate
# or locally, with DATABASE_URL set:
alembic upgrade head
```

The initial migration creates `triage_reports` with UUID primary keys, JSONB
payloads, verdict/target-type check constraints, and history indexes.

## Tests

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements-dev.txt
pytest -q
ruff check app tests alembic scripts
```

Tests use fakeredis, an in-memory fake dispatcher, mocked VirusTotal HTTP
responses, and fake database sessions, so no live VT key or infrastructure is
required. CI runs the suite on Python 3.11 and 3.12 with an 80% coverage floor,
validates the Compose file, builds the container image, and parses the
PowerShell setup helper.

## Production notes

- Put the API behind TLS and a reverse proxy; set `TRIAGE_API_KEY` for machine
  callers and configure `CORS_ORIGINS` explicitly.
- PostgreSQL and Redis are not published by the provided Compose file.
- Keep VirusTotal and database credentials in a secret manager rather than
  committing `.env`.
- The `worker` uses late acknowledgements and requeues tasks if a worker process
  is lost. Scan locks have a one-hour TTL to recover from crashed workers.
- Scale workers horizontally if needed; the Redis token bucket keeps the global
  VT request rate under the configured quota.
- Never commit `.env` or any API key. Rotate a credential immediately if it is
  exposed.

## Security

Report vulnerabilities privately through the repository's **Security** tab.
See [SECURITY.md](SECURITY.md) for details and secret-handling guidance.

## Contributing

Development setup, checks, and pull request expectations are documented in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the MIT License. Copyright © 2026 SneakySep. See
[LICENSE](LICENSE).
