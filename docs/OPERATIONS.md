# Operations runbook

Day-two guidance for running Webalizer Threat Triage. Configuration lives in
`.env`; see `.env.example` for every setting and `README.md` for the API.

## Health and readiness

- `GET /health/live` only proves the process is running.
- `GET /health/ready` checks PostgreSQL and Redis. Use it for load-balancer and
  container readiness probes.
- The Compose `worker` healthcheck runs `celery inspect ping`. The `beat`
  service has no healthcheck because a missed schedule is retried on the next
  interval.

## Metrics and request tracing

Prometheus metrics are served at `/metrics` when `METRICS_ENABLED=true`. If
`TRIAGE_API_KEY` or `TRIAGE_API_KEYS` is configured, scrapers must send the
same `X-API-Key` header. Check it with:

```bash
curl -H "X-API-Key: $TRIAGE_API_KEY" http://webalizer.internal:8000/metrics
```

Configure your scraper to send that header, or put the API behind a proxy that
injects it for the metrics path.

Useful series:

- `webalizer_http_requests_total` by method, path, and status.
- `webalizer_http_request_duration_seconds` by method and path.
- `webalizer_scan_outcomes_total` by outcome.

Every response carries `X-Request-ID`, and error envelopes include
`error.request_id`. Ask users for that value when investigating a failure, then
search API and worker logs for it. Path labels replace report UUIDs with
`{report_id}` to keep cardinality bounded.

## Retention and pruning

Reports older than `REPORT_RETENTION_DAYS` (default 180) are pruned by the
`beat` service daily at 03:15 UTC. Manual pruning is available from the API
image:

```bash
docker compose run --rm api python -m scripts.prune_reports --dry-run
docker compose run --rm api python -m scripts.prune_reports
```

Prune in batches for large tables. Take a backup before a manual run if the
reports are still needed for an investigation.

## Backups

PostgreSQL is the source of truth for stored reports. Back it up on a schedule
that matches the retention window:

```bash
docker compose exec -T postgres pg_dump -U triage -d triage -Fc \
  > triage-$(date +%Y%m%d).dump
```

Restore into an empty database with `pg_restore`. Redis holds only the result
cache, task status, rate-limit buckets, and locks; it can be rebuilt after a
loss, at the cost of repeated VirusTotal work. Do not treat the Celery broker
or result backend as durable storage.

## Key rotation

1. Add a new labelled entry to `TRIAGE_API_KEYS` alongside the old key.
2. Recreate the API, worker, and beat containers so they reload `.env`.
3. Move clients to the new key.
4. Remove the old entry and recreate the services again.

The legacy `TRIAGE_API_KEY` and labelled keys are accepted together. Each key
gets its own scan rate-limit bucket. Rotate `VT_API_KEY` the same way; the
worker reads it at startup, so `docker compose restart worker` is not enough.

## Proxy and network hardening

- Terminate TLS at a reverse proxy and forward only to the API port.
- Set `FORWARDED_ALLOW_IPS` to the proxy address or network. Leaving the
  default `127.0.0.1` prevents direct clients from spoofing `X-Forwarded-For`.
- Set `CORS_ORIGINS` explicitly if a separate frontend calls the API.
- Keep PostgreSQL and Redis on a private network. The provided Compose file
  does not publish them.
- Scrape `/metrics` over a private network or with an API key. Set
  `METRICS_ENABLED=false` where metrics are not needed.
- In production, responses include HSTS and a strict CSP for the app UI.
  `/docs`, `/redoc`, and `/openapi.json` skip CSP so Swagger and ReDoc can load
  their CDN assets; disable docs with `DOCS_ENABLED=false` if they are not
  needed.

## Branch protection

Protect `main` and require these CI checks before merging:

- `Lint and test (Python 3.11)` and `Lint and test (Python 3.12)`
- `Integration (PostgreSQL and Redis)`
- `Browser E2E`
- `Docker and scripts`
- CodeQL analysis

Also require a pull request, dismiss stale approvals, block force pushes, and
restrict who can push to `main`. Keep Dependabot updates flowing and review
runtime dependency changes before merging.

## Incident response

1. If a VirusTotal or API key leaked, remove it from `.env`, rotate it at the
   provider, and recreate the affected services.
2. Search logs for the exposed credential and for the `X-Request-ID` values in
   user reports.
3. If report data must be removed, use `DELETE /api/v1/triage/reports/{id}` or
   prune with a shorter window. Deletion invalidates that target's Redis cache.
4. Review `/metrics` for unusual scan volume, error rates, or latency before and
   after the change.
