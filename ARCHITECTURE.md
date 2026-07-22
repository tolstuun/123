# Architecture

`Caddy -> FastAPI web -> PostgreSQL` serves the dashboard and exports. A separate collector process calls documented read-only VMRay detail, VTI, sample, and submission endpoints, normalizes samples/runs/VTIs in one transaction per run, and advances a durable overlap checkpoint. It never downloads full analysis archives and does not retain raw API responses. PostgreSQL is the system of record and uses a named Docker volume. Submission provenance is retained on each run; deterministic rounds start whenever an interface name repeats for a sample. Metrics compare `(sample, round, arm)` and filter runs by their creation timestamp.

Samples are the sole analytical entity. Every immutable analysis run links directly to its SHA-256 sample; submission and job identifiers are provenance attributes only. Sample-level analytics combine matching static and requested-duration observations as consensus, mixed, or missing.
