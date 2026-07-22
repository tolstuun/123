import asyncio
from app import collector


class FakeClient:
    def __init__(self):self.calls=[]
    async def detail(self,aid):self.calls.append(("detail",aid));return {"data":{"analysis_id":aid}}
    async def vtis(self,aid):self.calls.append(("vtis",aid));return {"data":{"threat_indicators":[]}}
    async def sample(self,sid):self.calls.append(("sample",sid));return {"data":{"sample_id":sid}}
    async def submission(self,sid):self.calls.append(("submission",sid));return {"data":{"submission_created":"2026-01-01T00:00:00Z","submission_interface_name":"1minute"}}


def items(count=1,sample_id=10):return [{"analysis_id":index+1,"analysis_sample_id":sample_id} for index in range(count)]


def test_existing_analysis_skips_all_detail_calls(monkeypatch):
    client=FakeClient();monkeypatch.setattr(collector,"ingest",lambda *args:99)
    result=asyncio.run(collector.process_page(client,items(),{1},{},{}))
    assert client.calls==[]
    assert result["discovered"]==1 and result["new"]==0 and result["skipped_existing"]==1 and result["ingested"]==0


def test_new_analyses_are_ingested_without_grouping(monkeypatch):
    client=FakeClient();monkeypatch.setattr(collector,"ingest",lambda *args:77)
    result=asyncio.run(collector.process_page(client,items(6),set(),{},{}))
    assert result["ingested"]==6 and result["new"]==6
    assert len([call for call in client.calls if call[0]=="sample"])==1


def test_new_analysis_triggers_one_ingest(monkeypatch):
    client=FakeClient();ingests=[]
    monkeypatch.setattr(collector,"ingest",lambda *args:ingests.append(args) or 42)
    result=asyncio.run(collector.process_page(client,items(),set(),{},{}))
    assert len(ingests)==1
    assert (result["discovered"],result["new"],result["skipped_existing"],result["ingested"])==(1,1,0,1)
    assert all(call[0] != "archive" for call in client.calls)


def test_vmray_client_has_no_archive_endpoint():
    from app.vmray import VMRayClient
    assert not hasattr(VMRayClient, "archive")


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
