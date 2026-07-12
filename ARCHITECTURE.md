# Architecture

`Caddy -> FastAPI web -> PostgreSQL` serves the dashboard and exports. A separate collector process calls documented read-only VMRay detail, VTI, and sample endpoints, normalizes samples/runs/verdicts/VTIs in one transaction per run, and advances a durable overlap checkpoint. It never downloads full analysis archives and does not retain raw API responses. PostgreSQL is the system of record and uses a named Docker volume. The same image provides migrations, one-shot collection, demo seeding, and operational commands.

The six-run group retains three ordered static observations and dynamic 60/120/180 observations. Analytics query these observations without assigning truth status to any duration.
