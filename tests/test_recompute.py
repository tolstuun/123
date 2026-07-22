from contextlib import contextmanager

import app.recompute as recompute
from app.vti_taxonomy import NON_BEHAVIOURAL


class FakeCursor:
    def __init__(self,state):self.state=state;self.rowcount=0;self.params=None
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def execute(self,sql,params):
        self.params=params;ids=params[3]
        selected=self.state["runs"] if ids is None else {key:value for key,value in self.state["runs"].items() if key in ids}
        for run_id,counters in selected.items():
            observations=[o for o in self.state["observations"] if o[0]==run_id]
            high=[o for o in observations if o[2]>=3]
            counters.update({
                "vti_total":len(observations),
                "vti_nonbehavioural_high":sum(category in NON_BEHAVIOURAL for _,category,_ in high),
                "vti_behavioural_high":sum(category not in NON_BEHAVIOURAL for _,category,_ in high),
                "vti_config_extraction_high":sum(category=="Extracted Configuration" for _,category,_ in high),
            })
        self.rowcount=len(selected)


class FakeConnection:
    def __init__(self,state):self.state=state
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def cursor(self):return FakeCursor(self.state)
    def commit(self):pass


def fake_factory(state):
    @contextmanager
    def factory():yield FakeConnection(state)
    return factory


def test_recompute_is_idempotent_and_repairs_corrupt_counters(monkeypatch):
    state={"runs":{1:{"vti_behavioural_high":999,"vti_nonbehavioural_high":999,"vti_config_extraction_high":999,"vti_total":999}},
           "observations":[(1,"Invented",4),(1,"Antivirus",3),(1,"Extracted Configuration",5),(1,"YARA",2)]}
    monkeypatch.setattr(recompute,"connection",fake_factory(state))
    assert recompute.recompute_vti_counters()==1
    expected={"vti_behavioural_high":2,"vti_nonbehavioural_high":1,"vti_config_extraction_high":1,"vti_total":4}
    assert state["runs"][1]==expected
    assert recompute.recompute_vti_counters()==1
    assert state["runs"][1]==expected


def test_migration_011_only_drops_unknown_counter():
    from pathlib import Path
    statements=[line.strip() for line in Path("migrations/011_drop_unknown_vti_counter.sql").read_text().splitlines() if line.strip()]
    assert statements==["ALTER TABLE analysis_runs DROP COLUMN vti_unknown_category_high;"]
