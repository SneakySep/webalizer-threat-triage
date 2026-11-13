# Changelog

All notable changes to this project are documented here.

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
