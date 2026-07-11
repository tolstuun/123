from datetime import datetime, timedelta, timezone
from app import grouping

BASE=datetime(2026,7,11,12,0,tzinfo=timezone.utc)


def run(identifier,kind,duration=None,seconds=0,submission=None,sample=1):
    return {"id":identifier,"sample_id":sample,"vmray_analysis_id":identifier,"vmray_submission_id":submission or identifier,
            "analysis_type":kind,"duration_bucket":duration,"started_at":BASE+timedelta(seconds=seconds),"completed_at":BASE+timedelta(seconds=seconds+60),"is_demo":False}


def cycle(offset=0,start_id=1,sample=1):
    return [run(start_id,"static",seconds=offset,submission=100+start_id,sample=sample),run(start_id+1,"static",seconds=offset+2,submission=101+start_id,sample=sample),
            run(start_id+2,"static",seconds=offset+4,submission=102+start_id,sample=sample),run(start_id+3,"dynamic",60,offset+6,103+start_id,sample),
            run(start_id+4,"dynamic",120,offset+8,104+start_id,sample),run(start_id+5,"dynamic",180,offset+10,105+start_id,sample)]


def test_six_submissions_form_one_logical_experiment_and_static_slots():
    proposals,unassigned=grouping.build_proposals(cycle())
    assert len(proposals)==1 and not unassigned
    assert [slot for _,slot in proposals[0].assignments[:3]]==["static_1","static_2","static_3"]
    assert len({r["vmray_submission_id"] for r,_ in proposals[0].assignments})==6


def test_repeated_sha_cycles_remain_separate():
    proposals,_=grouping.build_proposals(cycle()+cycle(900,20))
    assert len(proposals)==2
    assert all(len(p.assignments)==6 for p in proposals)


def test_overlapping_candidates_are_ambiguous_and_not_double_assigned():
    duplicate=run(50,"dynamic",60,12,999)
    proposals,unassigned=grouping.build_proposals(cycle()+[duplicate])
    assert proposals[0].ambiguity
    assert duplicate in unassigned
    assigned=[r["id"] for p in proposals for r,_ in p.assignments]
    assert len(assigned)==len(set(assigned))


def test_delayed_arrival_joins_recent_group_by_original_start_time():
    partial=cycle()[:-1]
    first,_=grouping.build_proposals(partial)
    later,_=grouping.build_proposals(partial+[cycle()[-1]])
    assert first[0].group_key==later[0].group_key
    assert len(later[0].assignments)==6


def test_duplicate_static_does_not_fill_another_slot():
    runs=cycle()[:2]+[run(70,"static",seconds=3),run(71,"static",seconds=4)]+cycle()[3:]
    proposals,unassigned=grouping.build_proposals(runs)
    slots=[slot for _,slot in proposals[0].assignments]
    assert slots.count("static_3")==1 and len(unassigned)==1


def test_deterministic_rerun_and_provenance_unchanged():
    runs=cycle(); submissions=[r["vmray_submission_id"] for r in runs]
    first,_=grouping.build_proposals(list(reversed(runs)))
    second,_=grouping.build_proposals(runs)
    assert [(p.group_key,[(r["id"],s) for r,s in p.assignments]) for p in first]==[(p.group_key,[(r["id"],s) for r,s in p.assignments]) for p in second]
    assert [r["vmray_submission_id"] for r in runs]==submissions


def test_dry_run_does_not_call_apply(monkeypatch):
    runs=cycle(); called=[]
    monkeypatch.setattr(grouping,"migrate",lambda:None)
    monkeypatch.setattr(grouping,"load_runs",lambda sample_ids=None:runs)
    monkeypatch.setattr(grouping,"apply_proposals",lambda *args:called.append(True))
    report=grouping.regroup(True)
    assert report["complete_groups"]==1 and not called
