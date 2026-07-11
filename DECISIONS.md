# Engineering Decisions

- Python 3.12, FastAPI, server-rendered Jinja templates, small vanilla JavaScript charts, psycopg 3, and PostgreSQL 16 provide a compact maintainable application without an SPA toolchain.
- SQL migrations are versioned files applied by a dedicated idempotent migrator. PostgreSQL advisory locking prevents concurrent migration.
- Web and collector share domain and persistence modules but run as separate containers.
- Caddy provides the preferred host port 80; Docker publishes it without requiring sudo. HTTP Basic authentication is enforced by the application; health endpoints intentionally remain unauthenticated and non-sensitive.
- Raw JSON and archive source material is compressed in PostgreSQL and linked to a run. This favors recoverability over minimum storage.
- Submission ID plus SHA-256 is the preferred six-run group identity. Deterministic time-window fallback is explicitly marked ambiguous.
