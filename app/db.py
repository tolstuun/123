from contextlib import contextmanager
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from .config import settings

pool = ConnectionPool(settings.database_url, min_size=1, max_size=10, kwargs={"row_factory": dict_row}, open=False)


def open_pool() -> None:
    if pool.closed:
        pool.open(wait=True)


@contextmanager
def connection():
    open_pool()
    with pool.connection() as conn:
        yield conn
