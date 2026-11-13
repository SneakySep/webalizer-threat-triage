# Contributing

Thanks for considering a contribution. This project uses FastAPI, SQLAlchemy
2.0, Celery, Redis, PostgreSQL, and the VirusTotal API v3.

## Prerequisites

- Python 3.11 or newer
- Docker Engine with Compose v2
- A VirusTotal API key only if you intend to run live scans

## Development setup

```bash
git clone https://github.com/SneakySep/webalizer-threat-triage.git
cd webalizer-threat-triage

python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows PowerShell

pip install -r requirements-dev.txt
```

Create a local environment file:

```bash
cp .env.example .env
```

Leave `VT_API_KEY` empty for tests — the suite mocks VirusTotal and does not
need a key or live infrastructure. Never commit `.env`.

## Checks before opening a pull request

```bash
ruff check app tests alembic scripts
ruff format --check app tests alembic scripts
pytest -q
```

The default suite mocks VirusTotal, Redis, and PostgreSQL. Real-service and
browser suites are opt-in:

```bash
INTEGRATION_DATABASE_URL=postgresql+psycopg://triage:triage@localhost:5432/triage \
INTEGRATION_REDIS_URL=redis://localhost:6379/15 \
pytest -m integration -q

playwright install chromium
RUN_E2E=1 pytest -m e2e -q
```

To run the full stack:

```bash
docker compose up -d --build
docker compose exec -T worker python -m scripts.verify_vt_key
```

The preflight consumes one VirusTotal request and is only relevant when
`VT_API_KEY` is configured.

## Pull request expectations

- Keep changes focused and explain the behavior being changed.
- Add or update tests for bug fixes and new behavior.
- Update the README when configuration, endpoints, or setup steps change.
- Keep API errors inside the existing JSON error envelope.
- Do not weaken validation, rate limiting, secret handling, or retry safety.
- Confirm `ruff check`, `ruff format --check`, and `pytest` pass.

## Database changes

Schema changes require an Alembic migration:

```bash
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```

Review generated migrations before committing them.

## Security

Do not report security vulnerabilities in public issues. Follow
[SECURITY.md](SECURITY.md) for private reporting instructions.
