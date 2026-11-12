# Security Policy

## Supported versions

Security fixes are applied to the latest commit on the `main` branch. Older
commits and unofficial forks are not supported.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Describe the issue, affected endpoints or files, and reproduction steps.

Include as much detail as you can safely share:

- The affected version, commit, or container image.
- Whether the issue requires authentication.
- A minimal reproduction or proof of concept.
- Any suggested fix or mitigation.

You can expect an initial acknowledgement within a few days. This project does
not currently operate a paid bug bounty program.

## Secret handling

- Never commit `.env`, API keys, tokens, database passwords, or private keys.
- `.env` is ignored by Git and excluded from Docker build contexts. Only
  `.env.example` belongs in the repository.
- If a credential is exposed, revoke or rotate it with the provider
  immediately. Removing it from a later commit does not invalidate the exposed
  value.
- VirusTotal API keys should be restricted to the smallest scope available and
  stored in a secret manager for production deployments.

## Scope

This repository covers the API, Celery worker, container configuration, and
supporting scripts. Vulnerabilities in VirusTotal, PostgreSQL, Redis, Docker, or
Python dependencies should be reported to the relevant upstream project unless
this project's configuration makes the issue exploitable.
