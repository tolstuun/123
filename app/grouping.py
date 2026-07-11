import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from .config import settings
from .db import connection
from .migrate import migrate

GROUPING_VERSION = "temporal-v1"
SLOTS = ("static_1","static_2","static_3","dynamic_60","dynamic_120","dynamic_180")


@dataclass
class Proposal:
    sample_id: int
    group_key: str
    assignments: list
    unassigned: list
    first_at: datetime
    last_at: datetime
    ambiguity: bool


def timestamp(run): return run.get("started_at") or run.get("completed_at")


def build_proposals(runs, max_gap_seconds=300):
    by_sample=defaultdict(list)
    for run in runs:by_sample[run["sample_id"]].append(run)
    proposals=[]; globally_unassigned=[]
    for sample_id,sample_runs in sorted(by_sample.items()):
        ordered=sorted(sample_runs,key=lambda r:(timestamp(r) or datetime.min.replace(tzinfo=timezone.utc),r["vmray_analysis_id"]))
        clusters=[]; current=[]; anchor=None
        for run in ordered:
            when=timestamp(run)
            if current and anchor and when and (when-anchor).total_seconds()>max_gap_seconds:
                clusters.append(current);current=[];anchor=None
            if not current:anchor=when
            current.append(run)
        if current:clusters.append(current)
        for cluster in clusters:
            statics=sorted([r for r in cluster if r["analysis_type"]=="static"],key=lambda r:(timestamp(r),r["vmray_analysis_id"]))
            dynamic={duration:sorted([r for r in cluster if r["analysis_type"]=="dynamic" and r["duration_bucket"]==duration],key=lambda r:(timestamp(r),r["vmray_analysis_id"])) for duration in (60,120,180)}
            recognized=set(r["id"] for r in statics)
            for values in dynamic.values():recognized.update(r["id"] for r in values)
            extras=[r for r in cluster if r["id"] not in recognized]+statics[3:]
            assignments=[]
            for index,run in enumerate(statics[:3],1):assignments.append((run,f"static_{index}"))
            for duration,values in dynamic.items():
                if values:assignments.append((values[0],f"dynamic_{duration}"));extras.extend(values[1:])
            ambiguity=bool(extras)
            if not assignments:
                globally_unassigned.extend(cluster);continue
            times=[timestamp(r) for r,_ in assignments if timestamp(r)]
            first=min(times);last=max(times);minimum_id=min(r["vmray_analysis_id"] for r in cluster)
            proposals.append(Proposal(sample_id,f"logical:{sample_id}:{minimum_id}",assignments,extras,first,last,ambiguity))
            globally_unassigned.extend(extras)
    return proposals,globally_unassigned


def load_runs(sample_ids=None):
    sql="SELECT id,sample_id,vmray_analysis_id,vmray_submission_id,analysis_type,duration_bucket,started_at,completed_at,is_demo FROM analysis_runs"
    params=()
    if sample_ids:sql+=" WHERE sample_id=ANY(%s)";params=(list(sample_ids),)
    with connection() as conn,conn.cursor() as cur:cur.execute(sql,params);return cur.fetchall()


def summarize(proposals,unassigned,total):
    sizes=Counter(len(p.assignments) for p in proposals);spans=Counter()
    for p in proposals:
        seconds=int((p.last_at-p.first_at).total_seconds());spans["0-30s" if seconds<=30 else "31-60s" if seconds<=60 else "61-300s"]+=1
    complete=sum(len(p.assignments)==6 and not p.ambiguity for p in proposals)
    return {"unique_sample_hashes":len({p.sample_id for p in proposals}),"eligible_analyses":total,"logical_groups":len(proposals),"complete_groups":complete,"incomplete_groups":len(proposals)-complete,
            "ambiguous_groups":sum(p.ambiguity for p in proposals),"unassigned_analyses":len(unassigned),"cycle_sizes":dict(sorted(sizes.items())),
            "temporal_spans":dict(spans),"duplicate_slot_clusters":sum(p.ambiguity for p in proposals)}


def integrity(proposals,runs,unassigned):
    assigned=[run["id"] for p in proposals for run,_ in p.assignments]
    if len(assigned)!=len(set(assigned)):raise RuntimeError("An analysis was proposed for more than one logical group")
    for p in proposals:
        if any(run["sample_id"]!=p.sample_id for run,_ in p.assignments):raise RuntimeError("A logical group crossed a sample boundary")
        slots=[slot for _,slot in p.assignments]
        if len(slots)!=len(set(slots)):raise RuntimeError("A proposed group contained duplicate slots")
        if len([s for s in slots if s.startswith("static_")])>3:raise RuntimeError("A proposed group exceeded static capacity")
    unassigned_ids=[run["id"] for run in unassigned]
    if set(assigned)&set(unassigned_ids):raise RuntimeError("An analysis was both assigned and unassigned")
    if set(assigned)|set(unassigned_ids)!={run["id"] for run in runs}:raise RuntimeError("A source analysis was lost during grouping")


def apply_proposals(proposals,runs,sample_ids=None):
    now=datetime.now(timezone.utc); proposed_keys={p.group_key for p in proposals}
    with connection() as conn,conn.cursor() as cur:
        for run in runs:
            submission=run["vmray_submission_id"]
            source_key=f"sample:{run['sample_id']}:submission:{submission}" if submission is not None else f"sample:{run['sample_id']}:analysis:{run['vmray_analysis_id']}"
            cur.execute("INSERT INTO source_submission_groups(sample_id,vmray_submission_id,source_key,first_analysis_at,last_analysis_at) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(source_key) DO UPDATE SET first_analysis_at=LEAST(source_submission_groups.first_analysis_at,EXCLUDED.first_analysis_at),last_analysis_at=GREATEST(source_submission_groups.last_analysis_at,EXCLUDED.last_analysis_at) RETURNING id",(run["sample_id"],submission,source_key,timestamp(run),timestamp(run))); source_id=cur.fetchone()["id"]
            cur.execute("INSERT INTO source_submission_group_runs(source_submission_group_id,analysis_run_id) VALUES(%s,%s) ON CONFLICT(analysis_run_id) DO NOTHING",(source_id,run["id"]))
        target_samples=sorted({r["sample_id"] for r in runs})
        if target_samples:
            cur.execute("DELETE FROM logical_experiment_group_runs WHERE logical_experiment_group_id IN(SELECT id FROM logical_experiment_groups WHERE sample_id=ANY(%s) AND grouping_version=%s)",(target_samples,GROUPING_VERSION))
            cur.execute("UPDATE analysis_runs SET static_repetition=NULL WHERE sample_id=ANY(%s) AND analysis_type='static'",(target_samples,))
        for proposal in proposals:
            complete=len(proposal.assignments)==6 and not proposal.ambiguity
            settled=(now-proposal.last_at).total_seconds()>=settings.logical_group_settling_seconds
            explanation=f"Same SHA-256; analysis start timestamps within {settings.logical_group_max_gap_seconds}s; exact slot capacity enforced."
            cur.execute("INSERT INTO logical_experiment_groups(sample_id,group_key,grouping_method,grouping_confidence,grouping_version,grouping_explanation,ambiguity_flag,finalized_at,first_analysis_at,last_analysis_at,is_demo) VALUES(%s,%s,'temporal_start_cluster',%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(group_key) DO UPDATE SET grouping_confidence=EXCLUDED.grouping_confidence,grouping_explanation=EXCLUDED.grouping_explanation,ambiguity_flag=EXCLUDED.ambiguity_flag,finalized_at=EXCLUDED.finalized_at,first_analysis_at=EXCLUDED.first_analysis_at,last_analysis_at=EXCLUDED.last_analysis_at,assigned_at=now() RETURNING id",(proposal.sample_id,proposal.group_key,"low" if proposal.ambiguity else "medium",GROUPING_VERSION,explanation,proposal.ambiguity,now if complete and settled else None,proposal.first_at,proposal.last_at,proposal.assignments[0][0]["is_demo"])); group_id=cur.fetchone()["id"]
            for run,slot in proposal.assignments:
                cur.execute("INSERT INTO logical_experiment_group_runs(logical_experiment_group_id,analysis_run_id,expected_slot) VALUES(%s,%s,%s)",(group_id,run["id"],slot))
                if slot.startswith("static_"):cur.execute("UPDATE analysis_runs SET static_repetition=%s WHERE id=%s",(int(slot[-1]),run["id"]))
        if target_samples:
            cur.execute("DELETE FROM logical_experiment_groups WHERE sample_id=ANY(%s) AND grouping_version=%s AND NOT(group_key=ANY(%s))",(target_samples,GROUPING_VERSION,list(proposed_keys) or [""]))
        conn.commit()


def regroup(dry_run=True,sample_ids=None):
    migrate();runs=load_runs(sample_ids);proposals,unassigned=build_proposals(runs,settings.logical_group_max_gap_seconds);integrity(proposals,runs,unassigned);report=summarize(proposals,unassigned,len(runs))
    if not dry_run:apply_proposals(proposals,runs,sample_ids)
    return report


def regroup_sample(sample_id):return regroup(False,[sample_id])


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("command",choices=["dry-run","apply"]);args=parser.parse_args()
    report=regroup(args.command=="dry-run")
    for key,value in report.items():print(f"{key}={value}")
