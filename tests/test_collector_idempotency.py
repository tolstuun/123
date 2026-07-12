import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
from app import collector, grouping


class FakeClient:
    def __init__(self):self.calls=[]
    async def detail(self,aid):self.calls.append(("detail",aid));return {"data":{"analysis_id":aid}}
    async def vtis(self,aid):self.calls.append(("vtis",aid));return {"data":{"threat_indicators":[]}}
    async def sample(self,sid):self.calls.append(("sample",sid));return {"data":{"sample_id":sid}}
    async def archive(self,aid):self.calls.append(("archive",aid));return b"archive"


def items(count=1,sample_id=10):return [{"analysis_id":index+1,"analysis_sample_id":sample_id} for index in range(count)]


def test_existing_analysis_skips_all_detail_calls(monkeypatch):
    client=FakeClient();monkeypatch.setattr(collector,"ingest",lambda *args:99)
    result=asyncio.run(collector.process_page(client,items(),{1},{}))
    assert client.calls==[]
    assert result["discovered"]==1 and result["new"]==0 and result["skipped_existing"]==1 and result["ingested"]==0


def test_six_new_analyses_regroup_one_sample_once(monkeypatch):
    client=FakeClient();monkeypatch.setattr(collector,"ingest",lambda *args:77)
    called=[];monkeypatch.setattr(collector,"regroup_samples",lambda sample_ids:called.append(set(sample_ids)))
    result=asyncio.run(collector.process_page(client,items(6),set(),{}))
    count=collector.regroup_changed_samples(result["changed_samples"])
    assert result["ingested"]==6 and result["new"]==6 and count==1 and called==[{77}]
    assert len([call for call in client.calls if call[0]=="sample"])==1


def test_new_analysis_triggers_one_ingest_and_one_regroup(monkeypatch):
    client=FakeClient();ingests=[];regroups=[]
    monkeypatch.setattr(collector,"ingest",lambda *args:ingests.append(args) or 42)
    monkeypatch.setattr(collector,"regroup_samples",lambda ids:regroups.append(set(ids)))
    result=asyncio.run(collector.process_page(client,items(),set(),{}));collector.regroup_changed_samples(result["changed_samples"])
    assert len(ingests)==1 and regroups==[{42}]
    assert (result["discovered"],result["new"],result["skipped_existing"],result["ingested"])==(1,1,0,1)


class LockCursor:
    def __init__(self,acquired):self.acquired=acquired
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def execute(self,*args):pass
    def fetchone(self):return {"acquired":self.acquired}
class LockConnection:
    def __init__(self,acquired):self.acquired=acquired
    def cursor(self):return LockCursor(self.acquired)


def test_overlapping_cycle_is_rejected_by_advisory_lock():
    assert collector.acquire_cycle_lock(LockConnection(False)) is False
    assert collector.acquire_cycle_lock(LockConnection(True)) is True


def test_unchanged_grouping_performs_no_delete_or_reinsert(monkeypatch):
    run={"id":1,"sample_id":5,"vmray_analysis_id":101,"vmray_submission_id":201,"analysis_type":"dynamic","duration_bucket":60,"started_at":datetime.now(timezone.utc),"completed_at":datetime.now(timezone.utc),"is_demo":False}
    proposal=grouping.Proposal(5,"logical:5:101",[(run,"dynamic_60")],[],run["started_at"],run["started_at"],False)
    statements=[]
    class Cursor:
        rows=[]
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def execute(self,sql,params=()):
            statements.append(sql);self.sql=sql
            if "source_submission_group_runs WHERE" in sql:self.rows=[{"analysis_run_id":1}]
            elif "g.group_key,l.analysis_run_id" in sql:self.rows=[{"group_key":"logical:5:101","analysis_run_id":1,"expected_slot":"dynamic_60"}]
            else:self.rows=[]
        def fetchall(self):return self.rows
    class Conn:
        def cursor(self):return Cursor()
        def commit(self):pass
    @contextmanager
    def fake_connection():yield Conn()
    monkeypatch.setattr(grouping,"connection",fake_connection)
    assert grouping.apply_proposals([proposal],[run]) is False
    assert not any(sql.startswith("DELETE") or "INSERT INTO logical_experiment_group_runs" in sql for sql in statements)
