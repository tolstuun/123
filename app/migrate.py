from pathlib import Path
from .db import connection


def migrate() -> None:
    files = sorted(Path("migrations").glob("*.sql"))
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(81472931)")
        try:
            cur.execute("SELECT to_regclass('public.schema_migrations') AS table_name")
            exists = cur.fetchone()["table_name"] is not None
            applied = set()
            if exists:
                cur.execute("SELECT version FROM schema_migrations")
                applied = {row["version"] for row in cur.fetchall()}
            for file in files:
                version = file.stem
                if version in applied:
                    continue
                cur.execute(file.read_text(encoding="utf-8"))
                if version != "001_initial":
                    cur.execute("INSERT INTO schema_migrations(version) VALUES (%s)", (version,))
                else:
                    cur.execute("INSERT INTO schema_migrations(version) VALUES (%s)", (version,))
                conn.commit()
        finally:
            cur.execute("SELECT pg_advisory_unlock(81472931)")


if __name__ == "__main__":
    migrate()
