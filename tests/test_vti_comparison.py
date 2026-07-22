from contextlib import contextmanager
from datetime import datetime,timezone

import app.metrics as metrics


EXPECTED={"category","operation","severity","samples_gained","samples_lost","net"}


class Cursor:
    def __init__(self,state):self.state=state
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def execute(self,sql,params):self.state["sql"]=sql;self.state["params"]=params
    def fetchall(self):return self.state["rows"]


class Connection:
    def __init__(self,state):self.state=state
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def cursor(self):return Cursor(self.state)


def factory(state):
    @contextmanager
    def connect():yield Connection(state)
    return connect


def test_lost_only_vti_is_retained_and_page_is_limited(monkeypatch):
    lost_only={"category":"Execution","operation":"example","severity":4,"samples_gained":0,"samples_lost":3,"net":-3}
    state={"rows":[lost_only]};monkeypatch.setattr(metrics,"connection",factory(state))
    window=metrics.Window(datetime(2026,1,1,tzinfo=timezone.utc),datetime(2026,2,1,tzinfo=timezone.utc))
    rows=metrics.new_vtis_by_arm(window,"file",60,180)
    assert set(rows[0])==EXPECTED
    assert rows[0]["samples_gained"]==0 and rows[0]["samples_lost"]>0
    assert "FULL OUTER JOIN" in state["sql"] and "lost_agg" in state["sql"]
    assert state["sql"].rstrip().endswith("LIMIT 25")


def test_export_query_is_uncapped(monkeypatch):
    state={"rows":[]};monkeypatch.setattr(metrics,"connection",factory(state))
    window=metrics.Window(datetime(2026,1,1,tzinfo=timezone.utc),datetime(2026,2,1,tzinfo=timezone.utc))
    metrics.new_vtis_by_arm(window,"url",60,120,limit=None)
    assert "LIMIT" not in state["sql"].upper()
