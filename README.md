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
- Normalized, UI-ready reports: risk score, verdict, confidence, engine stats,
  detections, categories, DNS records, and scan timestamp.
- Historical reports in PostgreSQL with JSONB raw and normalized payloads.
- Task-scoped report idempotency and a configurable retention window.
- Per-client scan throttling and a force-refresh cooldown.
- Consistent JSON error envelope, optional API-key auth, and health checks.
- Dependency-free browser UI with plain-language verdicts, evidence drill-down,
  recent checks, and an access-key prompt for protected instances.
- Unit and contract tests with mocked VirusTotal, Redis, and database access,
  plus opt-in PostgreSQL/Redis integration and Playwright browser suites.

## Project layout

```text
.github/
  workflows/ci.yml              CI: lint, tests, Compose, image, scripts
  dependabot.yml                dependency update automation
app/
  main.py                       FastAPI app, lifespan, health and UI routes
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
  static/
    index.html                  Browser UI shell
    styles.css                  Responsive visual design
    app.js                      Scan flow, polling, verdict rendering, history
    favicon.svg                 Browser mark
  services/
    cache.py                    Redis cache, task state, locks
    dispatcher.py               Celery task publish abstraction
    normalizer.py               VirusTotal JSON -> TriageResult
    rate_limit.py               global Redis token bucket
    retention.py                batched report pruning
    triage.py                   worker orchestration
    virustotal.py               VT v3 HTTP client and error mapping
  tasks/vt_worker.py            Celery task and retry handling
  utils/helpers.py              validation, hashing, cache keys
alembic/                        database migrations
scripts/
  prune_reports.py              Delete reports past the retention window
  verify_vt_key.py              VirusTotal key/connectivity preflight
  enable-live-scans.ps1         One-command live-scan setup (Windows)
tests/
  integration/                  Real PostgreSQL and Redis tests
  e2e/                          Playwright browser flows
  ...                           Unit and API contract tests
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

4. Verify readiness and open the app:

   ```bash
   curl http://localhost:8000/health/ready
   # http://localhost:8000        web UI
   # http://localhost:8000/docs   API docs
   ```

Without `VT_API_KEY`, the stack still starts, but scans fail safely with
`VT_AUTH_FAILED`. The worker logs a startup warning in that case.

The preflight performs one real domain lookup, so it consumes one request from
your VirusTotal quota. A `200` means the key and outbound connectivity are valid;
`401`/`403` means the key was rejected; `429` means the key was accepted but the
quota is exhausted.

## Web UI

Open <http://localhost:8000> after the stack is healthy. The page is served directly
by FastAPI and calls the same public API as any other client.

- Paste a full URL or a bare domain and get a plain-language verdict with next steps.
- Vendor evidence—risk score, detection ratio, flagged engines, categories, and DNS
  records—stays available under “Show the technical evidence.”
- Recent checks are stored in the browser's `localStorage`; the server does not use
  them for anything else.
- If `TRIAGE_API_KEY` is set, the UI asks for the key on the first `401` and keeps it
  in `sessionStorage` for the current tab.

The frontend is plain HTML, CSS, and JavaScript with no Node build step. Its source
is in `app/static/` and is copied into the image by the existing `Dockerfile`. After
changing UI files locally, rebuild the API container:

```bash
docker compose up -d --build api
```

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
  "confidence": "medium",
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
- `confidence` (`low`, `medium`, `high`, or `null` for `unknown`) describes how
  much vendor evidence supports the verdict. It is optional so cached and stored
  results created before this field remain valid.
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

### Scan submission limits

Every `POST /api/v1/triage/scan` is throttled before any VirusTotal work starts.
Limits apply per API key when `TRIAGE_API_KEY` is configured, otherwise per
client IP:

- `SCAN_RATE_LIMIT_PER_MINUTE` (default `30`)
- `SCAN_RATE_LIMIT_PER_HOUR` (default `300`)
- `FORCE_REFRESH_COOLDOWN_SECONDS` (default `300`) per target

Exceeding a window returns `429 RATE_LIMITED`; forcing another refresh too soon
returns `429 FORCE_REFRESH_COOLDOWN`. Both include `Retry-After`. Locks, task
status, and cooldown markers are cleaned up if enqueueing fails, so a failed
submission does not block the next attempt.

### Report lifecycle

Reports are written once per Celery task. The nullable unique `task_id` column
makes retries and duplicate worker deliveries reuse the existing row instead of
creating a second report.

`REPORT_RETENTION_DAYS` defaults to `180`. Prune expired rows in batches:

```bash
# Preview the row count
docker compose run --rm api python -m scripts.prune_reports --dry-run

# Delete rows older than the configured/default window
docker compose run --rm api python -m scripts.prune_reports

# Override the window and batch size
docker compose run --rm api python -m scripts.prune_reports --days 90 --batch-size 500
```

Set `STORE_RAW_VT_RESPONSE=false` to persist only normalized report data. The
default is `true` for compatibility with existing report responses.

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
| Scan minute/hour limit exceeded | `429 RATE_LIMITED` with `Retry-After` |
| Forced refresh too soon | `429 FORCE_REFRESH_COOLDOWN` with `Retry-After` |
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
payloads, verdict/target-type check constraints, and history indexes. The second
migration adds the task idempotency key and the created-at retention index.

## Tests

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements-dev.txt
pytest -q
ruff check app tests alembic scripts
```

The default suite uses fakeredis, an in-memory fake dispatcher, mocked
VirusTotal HTTP responses, and fake database sessions, so no live VT key or
infrastructure is required. CI runs it on Python 3.11 and 3.12 with an 80%
coverage floor, validates the Compose file, builds the container image, and
parses the PowerShell setup helper.

Real-service and browser suites are opt-in:

```bash
# PostgreSQL + Redis integration tests
INTEGRATION_DATABASE_URL=postgresql+psycopg://triage:triage@localhost:5432/triage \
INTEGRATION_REDIS_URL=redis://localhost:6379/15 \
pytest -m integration -q

# Playwright browser flows (starts uvicorn automatically)
pip install -r requirements-dev.txt
playwright install chromium
RUN_E2E=1 pytest -m e2e -q
```

CI runs the integration suite against PostgreSQL 16 and Redis 7, and the
browser suite against Chromium.

## Production notes

- Put the API behind TLS and a reverse proxy; set `TRIAGE_API_KEY` for machine
  callers and configure `CORS_ORIGINS` explicitly.
- `--proxy-headers` only trusts `FORWARDED_ALLOW_IPS` (default `127.0.0.1`).
  Set it to your proxy address or network when the proxy is in another
  container, otherwise rate limits fall back to the proxy's address.
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
