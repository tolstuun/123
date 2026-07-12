# Architecture

`Caddy -> FastAPI web -> PostgreSQL` serves the dashboard and exports. A separate collector process calls documented read-only VMRay detail, VTI, and sample endpoints, normalizes samples/runs/verdicts/VTIs in one transaction per run, and advances a durable overlap checkpoint. It never downloads full analysis archives and does not retain raw API responses. PostgreSQL is the system of record and uses a named Docker volume. The same image provides migrations, one-shot collection, demo seeding, and operational commands.

Samples are the sole analytical entity. Every immutable analysis run links directly to its SHA-256 sample; submission and job identifiers are provenance attributes only. Sample-level analytics combine matching static and requested-duration observations as consensus, mixed, or missing.
