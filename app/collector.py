import argparse, asyncio, json, logging, random, time
from datetime import datetime, timedelta, timezone
from .config import settings
from .db import connection
from .domain import classify_support, normalize_verdict
from .migrate import migrate
from .vmray import VMRayClient, parse_time
from .grouping import regroup_samples

logging.basicConfig(level=logging.INFO, format='{"time":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
log = logging.getLogger("collector")
logging.getLogger("httpx").setLevel(logging.WARNING)
PARSER_VERSION = "1.0.0"


def ingest(detail_payload, vti_payload, sample_payload, demo=False):
    a=detail_payload.get("data",detail_payload); s=sample_payload.get("data",sample_payload)
    vtis=(vti_payload.get("data") or {}).get("threat_indicators",[])
    analysis_id=a["analysis_id"]; created=parse_time(a.get("analysis_created")) or datetime.now(timezone.utc); started=parse_time(a.get("analysis_job_started"))
    job_type=a.get("analysis_job_type"); analysis_type="static" if job_type=="only_static_analysis" else "dynamic" if job_type=="full_analysis" else "unknown"
    config=a.get("analysis_user_config_config") or "{}"
    try: config=json.loads(config) if isinstance(config,str) else config
    except json.JSONDecodeError: config={"raw":config}
    requested=int(config.get("timeout")) if analysis_type=="dynamic" and str(config.get("timeout","")).isdigit() else None
    sha256=(a.get("analysis_sample_sha256") or s.get("sample_sha256hash") or "").lower(); submission=a.get("analysis_submission_id")
    grouping_key=f"{sha256}:submission:{submission}" if submission else f"{sha256}:window:{created.strftime('%Y%m%d%H')}"
    confidence="high" if submission else "ambiguous"; warning=None if submission else "Submission ID unavailable; grouped by deterministic UTC hour."
    verdict=normalize_verdict(a.get("analysis_verdict"), a.get("analysis_result_code") not in (1,"1")); support=classify_support(vtis)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO samples(vmray_sample_id,sha256,sha1,md5,filename,file_type,first_seen,latest_seen,is_demo) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(sha256,is_demo) DO UPDATE SET latest_seen=GREATEST(samples.latest_seen,EXCLUDED.latest_seen),filename=COALESCE(samples.filename,EXCLUDED.filename) RETURNING id",(a.get("analysis_sample_id"),sha256,a.get("analysis_sample_sha1"),a.get("analysis_sample_md5"),s.get("sample_filename"),s.get("sample_type"),created,created,demo)); sample_pk=cur.fetchone()["id"]
        cur.execute("INSERT INTO sample_analysis_groups(sample_id,grouping_key,vmray_submission_id,grouping_confidence,grouping_warning,created_at,is_demo) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(grouping_key,is_demo) DO UPDATE SET grouping_warning=EXCLUDED.grouping_warning RETURNING id",(sample_pk,grouping_key,submission,confidence,warning,created,demo)); group=cur.fetchone()["id"]
        actual=int((created-started).total_seconds()) if started and created>=started else None
        cur.execute("INSERT INTO analysis_runs(group_id,sample_id,vmray_analysis_id,vmray_sample_id,vmray_submission_id,vmray_job_id,analysis_type,requested_duration_seconds,actual_duration_seconds,duration_bucket,created_at,started_at,completed_at,vmray_version,analysis_configuration,target_environment,status,failure_state,verdict,original_verdict,verdict_score,verdict_reason,support_classification,grouping_confidence,is_demo,parser_version) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(vmray_analysis_id,is_demo) DO UPDATE SET ingested_at=now() RETURNING id",(group,sample_pk,analysis_id,a.get("analysis_sample_id"),submission,a.get("analysis_job_id"),analysis_type,requested,actual,requested if requested in (60,120,180) else None,created,started,created,a.get("analysis_analyzer_version") or a.get("analysis_static_engine_version") or a.get("analysis_dynamic_engine_version"),json.dumps(config),a.get("analysis_platform"),a.get("analysis_result_str"),None if a.get("analysis_result_code") in (1,"1") else a.get("analysis_result_str"),verdict,a.get("analysis_verdict"),a.get("analysis_vti_score"),a.get("analysis_verdict_reason_description"),support,confidence,demo,PARSER_VERSION)); run=cur.fetchone()["id"]
        cur.execute("INSERT INTO verdict_observations(analysis_run_id,normalized_verdict,original_value,score,reason_code,reason_description,observed_at) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(analysis_run_id) DO NOTHING",(run,verdict,a.get("analysis_verdict"),a.get("analysis_vti_score"),a.get("analysis_verdict_reason_code"),a.get("analysis_verdict_reason_description"),created))
        for v in vtis:
            stable=str(v.get("id") or "");
            if not stable:continue
            cur.execute("INSERT INTO vti_definitions(stable_id,category,operation,classifications) VALUES(%s,%s,%s,%s) ON CONFLICT(stable_id) DO UPDATE SET category=EXCLUDED.category,operation=EXCLUDED.operation,classifications=EXCLUDED.classifications RETURNING id",(stable,v.get("category"),v.get("operation"),json.dumps(v.get("classifications") or []))); definition=cur.fetchone()["id"]
            cur.execute("INSERT INTO vti_observations(analysis_run_id,vti_definition_id,score,observed_at) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",(run,definition,v.get("score"),created))
        conn.commit()
    return sample_pk


COLLECTOR_LOCK_ID=81472932


def acquire_cycle_lock(conn):
    with conn.cursor() as cur:cur.execute("SELECT pg_try_advisory_lock(%s) acquired",(COLLECTOR_LOCK_ID,));return cur.fetchone()["acquired"]


def existing_analysis_ids(ids):
    if not ids:return set()
    with connection() as conn,conn.cursor() as cur:cur.execute("SELECT vmray_analysis_id FROM analysis_runs WHERE vmray_analysis_id=ANY(%s) AND NOT is_demo",(list(ids),));return {row["vmray_analysis_id"] for row in cur.fetchall()}


async def process_page(client,items,existing_ids,sample_cache):
    result={"discovered":len(items),"new":0,"skipped_existing":0,"ingested":0,"updated":0,"changed_samples":set(),"failures":[]}
    for item in items:
        aid=item["analysis_id"]
        if aid in existing_ids:
            result["skipped_existing"]+=1;continue
        result["new"]+=1
        try:
            detail=await client.detail(aid);vtis=await client.vtis(aid);source_sample_id=item["analysis_sample_id"]
            if source_sample_id not in sample_cache:sample_cache[source_sample_id]=await client.sample(source_sample_id)
            sample_pk=ingest(detail,vtis,sample_cache[source_sample_id])
            result["changed_samples"].add(sample_pk);result["ingested"]+=1
        except Exception as exc:result["failures"].append((aid,exc))
    return result


def regroup_changed_samples(sample_ids):
    if not sample_ids:return 0
    regroup_samples(set(sample_ids));return len(set(sample_ids))


async def collect_once():
    migrate();started=time.monotonic();now=datetime.now(timezone.utc)
    with connection() as lock_conn:
        if not acquire_cycle_lock(lock_conn):
            log.info("collection skipped: another cycle holds the advisory lock");return {"lock_acquired":False}
        client=None;batch=None
        totals={"discovered":0,"new":0,"skipped_existing":0,"ingested":0,"updated":0,"failed":0,"regrouped_samples":0}
        try:
            with connection() as conn,conn.cursor() as cur:
                cur.execute("UPDATE ingestion_batches SET status='interrupted',completed_at=now() WHERE status='running'")
                cur.execute("INSERT INTO ingestion_batches(status) VALUES('running') RETURNING id");batch=cur.fetchone()["id"]
                cur.execute("UPDATE collector_status SET state='running',last_attempt_at=%s WHERE singleton",(now,));conn.commit()
                cur.execute("SELECT completed_at FROM collection_checkpoints WHERE name='analyses'");row=cur.fetchone();cutoff=(row["completed_at"]-timedelta(hours=settings.overlap_hours)) if row and row["completed_at"] else now-timedelta(hours=24)
                cur.execute("INSERT INTO collection_checkpoints(name,completed_at) VALUES('analyses',%s) ON CONFLICT(name) DO NOTHING",(cutoff,));conn.commit()
            client=VMRayClient();max_id=None;seen=set();newest=None;changed_samples=set();sample_cache={}
            while True:
                rows=await client.analyses(max_id)
                if not rows:break
                stop=False;candidates=[]
                for item in rows:
                    aid=item["analysis_id"]
                    if aid in seen:continue
                    seen.add(aid);completed=parse_time(item.get("analysis_created"))
                    if completed and completed<cutoff:stop=True;continue
                    candidates.append(item);newest=max(newest,completed) if newest and completed else completed or newest
                existing=existing_analysis_ids({item["analysis_id"] for item in candidates})
                page=await process_page(client,candidates,existing,sample_cache)
                for key in ("discovered","new","skipped_existing","ingested","updated"):totals[key]+=page[key]
                changed_samples.update(page["changed_samples"]);totals["failed"]+=len(page["failures"])
                for aid,exc in page["failures"]:
                    message=str(exc).replace(settings.vmray_api_key,"[REDACTED]")[:1000]
                    with connection() as conn,conn.cursor() as cur:cur.execute("INSERT INTO collection_errors(batch_id,analysis_id,error_type,message) VALUES(%s,%s,%s,%s)",(batch,aid,type(exc).__name__,message));conn.commit()
                if stop or len(rows)<50:break
                max_id=min(x["analysis_id"] for x in rows)
            totals["regrouped_samples"]=regroup_changed_samples(changed_samples)
            duration=time.monotonic()-started
            with connection() as conn,conn.cursor() as cur:
                if newest:cur.execute("INSERT INTO collection_checkpoints(name,completed_at,stable_id) VALUES('analyses',%s,%s) ON CONFLICT(name) DO UPDATE SET completed_at=GREATEST(collection_checkpoints.completed_at,EXCLUDED.completed_at),stable_id=EXCLUDED.stable_id,updated_at=now()",(newest,max(seen) if seen else None))
                cur.execute("UPDATE ingestion_batches SET completed_at=now(),status=%s,discovered=%s,ingested=%s,failed=%s,new_count=%s,skipped_existing=%s,updated=%s,regrouped_samples=%s,duration_seconds=%s WHERE id=%s",("partial" if totals["failed"] else "success",totals["discovered"],totals["ingested"],totals["failed"],totals["new"],totals["skipped_existing"],totals["updated"],totals["regrouped_samples"],duration,batch))
                cur.execute("UPDATE collector_status SET state=%s,last_success_at=now(),connectivity_ok=true,lag_seconds=%s,error_count=error_count+%s,last_cycle_duration_seconds=%s,last_discovered=%s,last_new=%s,last_skipped_existing=%s,last_updated=%s,last_failed=%s,last_regrouped_samples=%s,message=%s WHERE singleton",("degraded" if totals["failed"] else "healthy",int((now-newest).total_seconds()) if newest else None,totals["failed"],duration,totals["discovered"],totals["new"],totals["skipped_existing"],totals["updated"],totals["failed"],totals["regrouped_samples"],f"New {totals['ingested']}; skipped {totals['skipped_existing']}; regrouped samples {totals['regrouped_samples']}"));conn.commit()
            log.info("collection complete %s duration=%.2fs",totals,duration);return {"lock_acquired":True,**totals,"duration_seconds":duration}
        except Exception:
            duration=time.monotonic()-started
            if batch is not None:
                try:
                    with connection() as conn,conn.cursor() as cur:
                        cur.execute("UPDATE ingestion_batches SET completed_at=now(),status='error',failed=GREATEST(failed,1),duration_seconds=%s WHERE id=%s",(duration,batch));conn.commit()
                except Exception as batch_error:log.error("unable to finalize failed ingestion batch: %s",type(batch_error).__name__)
            raise
        finally:
            if client:await client.close()
            with lock_conn.cursor() as cur:cur.execute("SELECT pg_advisory_unlock(%s)",(COLLECTOR_LOCK_ID,))


async def run_forever():
    while True:
        try: await collect_once()
        except Exception as exc:
            message=str(exc).replace(settings.vmray_api_key,"[REDACTED]"); log.error("collection cycle failed: %s",message)
            try:
                with connection() as conn, conn.cursor() as cur: cur.execute("UPDATE collector_status SET state='error',connectivity_ok=false,error_count=error_count+1,message=%s WHERE singleton",(message[:500],)); conn.commit()
            except Exception as telemetry_error:log.error("unable to persist collector failure telemetry: %s",type(telemetry_error).__name__)
        await asyncio.sleep(max(30,settings.poll_seconds))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("command",choices=["run","once"],default="run",nargs="?"); args=parser.parse_args()
    settings.validate_collector(); asyncio.run(collect_once() if args.command=="once" else run_forever())
