# VMRay Analytics Platform

Production-oriented preservation and analytics for VMRay's short-lived analysis results. It retains immutable static repetitions, dynamic 60/120/180-second runs, raw source payloads, verdict support, VTI observations, and per-analysis IOC snapshots in PostgreSQL.

## Local operation

Copy `.env.example` to `.env`, set strong local values and VMRay credentials, then run `make up`. Open `http://localhost:8080`; `/health` and `/ready` are unauthenticated and contain no sensitive data. Use `make collect` for a one-shot read-only collection and `make logs` for logs.

## Commands

- `make migrate` — apply versioned migrations.
- `make test` — build and run focused tests.
- `make collect` — run one collection cycle.
- `make backup` — create a timestamped compressed PostgreSQL backup.
- `docker compose restart web collector` — restart application services.
- `docker compose exec db psql -U vmray -d vmray -c 'select * from collector_status'` — collector status.

See [architecture](ARCHITECTURE.md), [API findings](docs/VMRAY_API_FINDINGS.md), and the [operations guides](ops/DEPLOYMENT.md).
