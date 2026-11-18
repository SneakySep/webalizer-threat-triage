# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- Risk-score backfill (`scripts.backfill_risk_scores`) that recomputes both the
  `risk_score` column and the `normalized_data` blob after a scoring-rule change,
  with a dry-run mode, batched writes, and malformed rows skipped and counted.
- Verdict-change survey (`--with-verdicts`) that reports how many stored reports
  would change verdict under the current thresholds without rewriting them.
- `--force-verdicts` to apply a reviewed verdict rewrite, which the survey alone
  will not do. Every run now reports `verdicts_changed`, and the default
  risk-score path no longer rewrites stored verdicts as a side effect.
- Request body size limit (`MAX_REQUEST_BODY_BYTES`, default 64 KiB) rejecting
  oversized payloads with 413 before the endpoint parses them.
- Redis socket and connect timeouts so a stalled Redis cannot block every request
  handler, including `/health/ready`.
- Swagger UI Authorize support for the API key, with the key declared as a
  security scheme instead of a plain header.
- Bounded Prometheus path labels: unmatched paths collapse to `{unmatched}` so
  random scanner traffic cannot mint unbounded time series.

### Changed

- API key comparison now evaluates every configured key without short-circuiting,
  so response timing does not reveal which key matched.
- Missing `X-API-Key` returns the app's own 401 envelope with
  `WWW-Authenticate: ApiKey`.

### Documentation

- Operations runbook and README cover the risk-score backfill and its dry-run and
  verdict-survey behaviour.

## [1.1.0] - 2026-11-13

### Added

- Server-backed report history with pagination, verdict filtering, and permalinks.
- Report deletion endpoint with cache invalidation for data-removal requests.
- Optional verdict confidence and confidence-aware browser copy.
- Scan submission limits, force-refresh cooldown, and cleanup on enqueue failure.
- Task-scoped report idempotency and configurable report retention.
- Scheduled report pruning through Celery beat.
- Security headers, strict CSP for the app UI, request IDs, and Prometheus metrics.
- Labelled API keys with legacy single-key compatibility.
- PostgreSQL/Redis integration tests and Playwright browser tests in CI.
- CodeQL analysis and JavaScript syntax checks in CI.

### Changed

- Compose now trusts forwarded headers only from `FORWARDED_ALLOW_IPS`.
- The worker has a Celery ping healthcheck.
- Documentation covers retention, metrics, auth, and the new history endpoints.

## [1.0.0] - 2026-11-12

### Added

- Initial asynchronous URL and domain triage service.
- FastAPI API, Celery worker, Redis cache, PostgreSQL reports, and browser UI.
