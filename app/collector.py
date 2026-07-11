import argparse, asyncio, csv, gzip, io, json, logging, random, zipfile
from datetime import datetime, timedelta, timezone
from .config import settings
from .db import connection
from .domain import classify_support, normalize_ioc, normalize_verdict, payload_digest
from .migrate import migrate
from .vmray import VMRayClient, parse_time
from .grouping import regroup_sample

logging.basicConfig(level=logging.INFO, format='{"time":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
log = logging.getLogger("collector")
logging.getLogger("httpx").setLevel(logging.WARNING)
PARSER_VERSION = "1.0.0"


def raw(cur, kind, identifier, content, content_type):
    compressed = gzip.compress(content)
    digest = payload_digest(content)
    cur.execute("INSERT INTO raw_api_payloads(source_kind,source_identifier,content_type,payload,sha256) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(source_kind,source_identifier,sha256) DO UPDATE SET source_identifier=EXCLUDED.source_identifier RETURNING id", (kind,str(identifier),content_type,compressed,digest))
    return cur.fetchone()["id"]


def archive_iocs(content):
    observations=[]
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names=[n for n in archive.namelist() if n.lower().endswith("all_iocs.csv")]
            if not names:return observations
            text=io.TextIOWrapper(archive.open(names[0]), encoding="utf-8-sig", errors="replace")
            for row in csv.DictReader(text):
                lower={str(k).lower():v for k,v in row.items()}
                value=next((lower[k] for k in ("value","ioc","artifact","original_value") if lower.get(k)),None)
                if not value:continue
                kind=next((lower[k] for k in ("type","ioc_type","artifact_type") if lower.get(k)),"unknown")
                verdict=lower.get("verdict") or lower.get("ioc_verdict")
                observations.append({"type":kind,"value":value,"verdict":verdict,"source":"analysis_archive","context":lower.get("context")})
    except (zipfile.BadZipFile, KeyError): log.warning("Archive did not contain parseable IOC CSV")
    return observations


def ingest(detail_payload, vti_payload, sample_payload, archive_content=None, demo=False):
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
    iocs=archive_iocs(archive_content) if archive_content else []
    with connection() as conn, conn.cursor() as cur:
        detail_raw=raw(cur,"analysis_detail",analysis_id,json.dumps(detail_payload,separators=(",",":"),default=str).encode(),"application/json")
        raw(cur,"analysis_vtis",analysis_id,json.dumps(vti_payload,separators=(",",":"),default=str).encode(),"application/json")
        raw(cur,"sample_detail",a.get("analysis_sample_id"),json.dumps(sample_payload,separators=(",",":"),default=str).encode(),"application/json")
        if archive_content: raw(cur,"analysis_archive",analysis_id,archive_content,"application/zip")
        cur.execute("INSERT INTO samples(vmray_sample_id,sha256,sha1,md5,filename,file_type,first_seen,latest_seen,is_demo) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(sha256,is_demo) DO UPDATE SET latest_seen=GREATEST(samples.latest_seen,EXCLUDED.latest_seen),filename=COALESCE(samples.filename,EXCLUDED.filename) RETURNING id",(a.get("analysis_sample_id"),sha256,a.get("analysis_sample_sha1"),a.get("analysis_sample_md5"),s.get("sample_filename"),s.get("sample_type"),created,created,demo)); sample_pk=cur.fetchone()["id"]
        cur.execute("INSERT INTO sample_analysis_groups(sample_id,grouping_key,vmray_submission_id,grouping_confidence,grouping_warning,created_at,is_demo) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(grouping_key,is_demo) DO UPDATE SET grouping_warning=EXCLUDED.grouping_warning RETURNING id",(sample_pk,grouping_key,submission,confidence,warning,created,demo)); group=cur.fetchone()["id"]
        actual=int((created-started).total_seconds()) if started and created>=started else None
        cur.execute("INSERT INTO analysis_runs(group_id,sample_id,vmray_analysis_id,vmray_sample_id,vmray_submission_id,vmray_job_id,analysis_type,requested_duration_seconds,actual_duration_seconds,duration_bucket,created_at,started_at,completed_at,vmray_version,analysis_configuration,target_environment,status,failure_state,verdict,original_verdict,verdict_score,verdict_reason,support_classification,grouping_confidence,is_demo,raw_payload_id,parser_version) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(vmray_analysis_id,is_demo) DO UPDATE SET ingested_at=now() RETURNING id",(group,sample_pk,analysis_id,a.get("analysis_sample_id"),submission,a.get("analysis_job_id"),analysis_type,requested,actual,requested if requested in (60,120,180) else None,created,started,created,a.get("analysis_analyzer_version") or a.get("analysis_static_engine_version") or a.get("analysis_dynamic_engine_version"),json.dumps(config),a.get("analysis_platform"),a.get("analysis_result_str"),None if a.get("analysis_result_code") in (1,"1") else a.get("analysis_result_str"),verdict,a.get("analysis_verdict"),a.get("analysis_vti_score"),a.get("analysis_verdict_reason_description"),support,confidence,demo,detail_raw,PARSER_VERSION)); run=cur.fetchone()["id"]
        cur.execute("INSERT INTO verdict_observations(analysis_run_id,normalized_verdict,original_value,score,reason_code,reason_description,observed_at) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(analysis_run_id) DO NOTHING",(run,verdict,a.get("analysis_verdict"),a.get("analysis_vti_score"),a.get("analysis_verdict_reason_code"),a.get("analysis_verdict_reason_description"),created))
        for v in vtis:
            stable=str(v.get("id") or "");
            if not stable:continue
            cur.execute("INSERT INTO vti_definitions(stable_id,category,operation,classifications) VALUES(%s,%s,%s,%s) ON CONFLICT(stable_id) DO UPDATE SET category=EXCLUDED.category,operation=EXCLUDED.operation,classifications=EXCLUDED.classifications RETURNING id",(stable,v.get("category"),v.get("operation"),json.dumps(v.get("classifications") or []))); definition=cur.fetchone()["id"]
            cur.execute("INSERT INTO vti_observations(analysis_run_id,vti_definition_id,score,observed_at) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",(run,definition,v.get("score"),created))
        for i in iocs:
            normalized=normalize_ioc(i["type"],i["value"]); actionable=str(i.get("verdict") or "").lower() in {"malicious","suspicious"}
            cur.execute("INSERT INTO ioc_observations(analysis_run_id,ioc_type,original_value,normalized_value,verdict,source,extraction_context,actionable,observed_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",(run,i["type"],i["value"],normalized,i.get("verdict"),i.get("source"),i.get("context"),actionable,created))
        conn.commit()
    return sample_pk


async def collect_once():
    migrate(); client=VMRayClient(); now=datetime.now(timezone.utc)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO ingestion_batches(status) VALUES('running') RETURNING id"); batch=cur.fetchone()["id"]
        cur.execute("UPDATE collector_status SET state='running',last_attempt_at=%s WHERE singleton",(now,)); conn.commit()
    discovered=ingested=failed=0
    try:
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT completed_at FROM collection_checkpoints WHERE name='analyses'"); row=cur.fetchone(); cutoff=(row["completed_at"]-timedelta(hours=settings.overlap_hours)) if row and row["completed_at"] else now-timedelta(hours=24)
            cur.execute("INSERT INTO collection_checkpoints(name,completed_at) VALUES('analyses',%s) ON CONFLICT(name) DO NOTHING",(cutoff,)); conn.commit()
        max_id=None; seen=set(); newest=None
        while True:
            rows=await client.analyses(max_id)
            if not rows:break
            stop=False
            for item in rows:
                aid=item["analysis_id"]
                if aid in seen:continue
                seen.add(aid); completed=parse_time(item.get("analysis_created"))
                if completed and completed<cutoff: stop=True; continue
                discovered+=1; newest=max(newest,completed) if newest and completed else completed or newest
                try:
                    with connection() as conn, conn.cursor() as cur:
                        cur.execute("SELECT 1 FROM analysis_runs WHERE vmray_analysis_id=%s AND NOT is_demo",(aid,)); exists=cur.fetchone()
                    detail=await client.detail(aid); vtis=await client.vtis(aid); sample=await client.sample(item["analysis_sample_id"])
                    archive=None if exists else await client.archive(aid)
                    sample_pk=ingest(detail,vtis,sample,archive); regroup_sample(sample_pk); ingested+=1
                    with connection() as conn, conn.cursor() as cur:
                        cur.execute("UPDATE collector_status SET state='running',last_success_at=now(),connectivity_ok=true,lag_seconds=%s,message=%s WHERE singleton",(int((now-completed).total_seconds()) if completed else None,f"Ingested analysis {aid}; backfill in progress")); conn.commit()
                except Exception as exc:
                    failed+=1; message=str(exc).replace(settings.vmray_api_key,"[REDACTED]")[:1000]
                    with connection() as conn, conn.cursor() as cur: cur.execute("INSERT INTO collection_errors(batch_id,analysis_id,error_type,message) VALUES(%s,%s,%s,%s)",(batch,aid,type(exc).__name__,message)); conn.commit()
            if stop or len(rows)<50:break
            max_id=min(x["analysis_id"] for x in rows)
        with connection() as conn, conn.cursor() as cur:
            if newest: cur.execute("INSERT INTO collection_checkpoints(name,completed_at,stable_id) VALUES('analyses',%s,%s) ON CONFLICT(name) DO UPDATE SET completed_at=GREATEST(collection_checkpoints.completed_at,EXCLUDED.completed_at),stable_id=EXCLUDED.stable_id,updated_at=now()",(newest,max(seen) if seen else None))
            cur.execute("UPDATE ingestion_batches SET completed_at=now(),status=%s,discovered=%s,ingested=%s,failed=%s WHERE id=%s",("partial" if failed else "success",discovered,ingested,failed,batch)); cur.execute("UPDATE collector_status SET state=%s,last_success_at=now(),connectivity_ok=true,lag_seconds=%s,error_count=error_count+%s,message=%s WHERE singleton",("degraded" if failed else "healthy",int((now-newest).total_seconds()) if newest else None,failed,f"Ingested {ingested}; failed {failed}")); conn.commit()
    finally: await client.close()
    log.info("collection complete discovered=%s ingested=%s failed=%s",discovered,ingested,failed)


async def run_forever():
    while True:
        try: await collect_once()
        except Exception as exc:
            message=str(exc).replace(settings.vmray_api_key,"[REDACTED]"); log.error("collection cycle failed: %s",message)
            with connection() as conn, conn.cursor() as cur: cur.execute("UPDATE collector_status SET state='error',connectivity_ok=false,error_count=error_count+1,message=%s WHERE singleton",(message[:500],)); conn.commit()
        await asyncio.sleep(settings.poll_seconds)


def reprocess_raw():
    migrate()
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT source_kind,source_identifier,payload FROM raw_api_payloads WHERE source_kind IN ('analysis_detail','analysis_vtis','sample_detail','analysis_archive') ORDER BY collected_at")
        sources={}
        for row in cur.fetchall(): sources[(row["source_kind"],row["source_identifier"])]=gzip.decompress(row["payload"])
    count=0
    for (kind,identifier),detail_bytes in list(sources.items()):
        if kind!="analysis_detail":continue
        detail=json.loads(detail_bytes); a=detail.get("data",detail); sample_id=str(a.get("analysis_sample_id")); vti=sources.get(("analysis_vtis",identifier),b'{"data":{"threat_indicators":[]}}'); sample=sources.get(("sample_detail",sample_id),b'{"data":{}}'); archive=sources.get(("analysis_archive",identifier))
        ingest(detail,json.loads(vti),json.loads(sample),archive); count+=1
    log.info("reprocessed %s stored analysis payloads",count)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("command",choices=["run","once","reprocess"],default="run",nargs="?"); args=parser.parse_args()
    if args.command=="reprocess": reprocess_raw()
    else: settings.validate_collector(); asyncio.run(collect_once() if args.command=="once" else run_forever())
