# Architecture

`Caddy -> FastAPI web -> PostgreSQL` serves the dashboard and exports. A separate collector process calls documented read-only VMRay endpoints, stores compressed raw payloads, normalizes samples/runs/verdicts/VTIs/IOCs in one transaction per run, and advances a durable overlap checkpoint. PostgreSQL is the system of record and uses a named Docker volume. The same image provides migrations, one-shot collection, raw reprocessing, demo seeding, and operational commands.

The six-run group retains three ordered static observations and dynamic 60/120/180 observations. Analytics query these observations without assigning truth status to any duration.
