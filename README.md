# VMRay Analytics Platform

Production-oriented analytics for VMRay's short-lived analysis results. It retains normalized immutable static repetitions, dynamic 60/120/180-second runs, verdict observations, and VTI observations in PostgreSQL. Raw API responses and full analysis archives are not downloaded or retained.

## Local operation

Copy `.env.example` to `.env`, set strong local values and VMRay credentials, then run `make up`. Open `http://localhost`; `/health` and `/ready` are unauthenticated and contain no sensitive data. Use `make collect` for a one-shot read-only collection and `make logs` for logs.

## Commands

- `make recompute` — rebuild persisted VTI counters from normalized observations using the current taxonomy.
- `make migrate` — apply versioned migrations.
- `make test` — build and run focused tests.
- `make collect` — run one collection cycle.
- `make backup` — create a timestamped compressed PostgreSQL backup.
- `docker compose restart web collector` — restart application services.
- `docker compose exec db psql -U vmray -d vmray -c 'select * from collector_status'` — collector status.

See [architecture](ARCHITECTURE.md), [API findings](docs/VMRAY_API_FINDINGS.md), and the [operations guides](ops/DEPLOYMENT.md).
