# Engineering Decisions

- Python 3.12, FastAPI, server-rendered Jinja templates, small vanilla JavaScript charts, psycopg 3, and PostgreSQL 16 provide a compact maintainable application without an SPA toolchain.
- SQL migrations are versioned files applied by a dedicated idempotent migrator. PostgreSQL advisory locking prevents concurrent migration.
- Web and collector share domain and persistence modules but run as separate containers.
- Caddy provides the preferred host port 80; Docker publishes it without requiring sudo. HTTP Basic authentication is enforced by the application; health endpoints intentionally remain unauthenticated and non-sensitive.
- Only normalized analytics data is retained. Raw API payloads and full analysis archives are deliberately excluded to keep storage bounded.
- SHA-256 sample identity is the only analytical key. Submission and job identifiers are retained only as run provenance.
