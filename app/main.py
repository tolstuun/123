import csv, hmac, io, json
from datetime import date, datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from .config import settings
from .db import connection, open_pool
from .migrate import migrate
from .analytics import EXPECTED_SLOTS, zero_fill_daily

app=FastAPI(title="VMRay Analytics",docs_url=None,redoc_url=None,openapi_url=None)
templates=Jinja2Templates(directory="app/templates"); app.mount("/static",StaticFiles(directory="app/static"),name="static"); security=HTTPBasic()


@app.on_event("startup")
def startup(): settings.validate_web(); open_pool(); migrate()


@app.middleware("http")
async def headers(request,call_next):
    if request.headers.get("content-length") and int(request.headers["content-length"])>1_048_576:return Response(status_code=413)
    response=await call_next(request); response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Content-Security-Policy":"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:","Cache-Control":"no-store"}); return response


def auth(credentials:HTTPBasicCredentials=Depends(security)):
    good=hmac.compare_digest(credentials.username.encode(),settings.dashboard_username.encode()) and hmac.compare_digest(credentials.password.encode(),settings.dashboard_password.encode())
    if not good:raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,headers={"WWW-Authenticate":"Basic realm=VMRay Analytics"})


def filters(request):
    mode=request.query_params.get("mode","real"); days=max(1,min(int(request.query_params.get("days","7")),3650)); today=datetime.now(timezone.utc).date(); start=datetime.combine(today-timedelta(days=days-1),datetime.min.time(),tzinfo=timezone.utc); return mode,start,days


def mode_sql(mode,alias="r"):
    return ("TRUE",()) if mode=="combined" else (f"{alias}.is_demo=%s",(mode=="demo",))


@app.get("/health")
def health():return {"status":"alive"}


@app.get("/ready")
def ready():
    try:
        with connection() as conn,conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"); version=cur.fetchone()
        return {"status":"ready","database":"ok","migration":version["version"]}
    except Exception:raise HTTPException(503,"not ready")


def render(request,name,context):
    mode,_,days=filters(request); return templates.TemplateResponse(request,name,{"mode":mode,"days":days,**context})


def human_time(value):
    return value.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC") if value else "Never"


def human_duration(seconds):
    if seconds is None:return "Unknown"
    seconds=max(0,int(seconds)); hours,remainder=divmod(seconds,3600); minutes,secs=divmod(remainder,60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m {secs}s" if minutes else f"{secs}s"


templates.env.globals.update(human_time=human_time,human_duration=human_duration)


@app.get("/",response_class=HTMLResponse,dependencies=[Depends(auth)])
def overview(request:Request):
    mode,start,days=filters(request); where,args=mode_sql(mode); metric=request.query_params.get("metric","runs"); metric=metric if metric in {"runs","samples","groups"} else "runs"; end=datetime.now(timezone.utc).date()
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT count(*) analyses,count(DISTINCT sample_id) unique_samples,count(*) FILTER(WHERE analysis_type='static') static_analyses,count(*) FILTER(WHERE analysis_type='dynamic') dynamic_analyses,count(*) FILTER(WHERE completed_at>=date_trunc('day',now())) analyses_today FROM analysis_runs r WHERE {where} AND completed_at>=%s",args+(start,)); metrics=cur.fetchone()
        sample_where,sample_args=mode_sql(mode,"s"); cur.execute(f"SELECT count(*) FILTER(WHERE first_seen>=date_trunc('day',now())) samples_first_seen_today FROM samples s WHERE {sample_where}",sample_args); metrics.update(cur.fetchone())
        group_where,group_args=mode_sql(mode,"g"); cur.execute(f"SELECT count(*) analysis_groups,count(*) FILTER(WHERE c.completeness_status='complete_clean') complete_groups,count(*) FILTER(WHERE c.missing_slot_count>0) incomplete_groups,count(*) FILTER(WHERE c.duplicate_slot_count>0) duplicate_groups,coalesce(sum(c.unmapped_run_count),0) unmapped_analyses FROM analysis_group_completeness c JOIN sample_analysis_groups g ON g.id=c.group_id WHERE {group_where} AND c.last_analysis_at>=%s",group_args+(start,)); metrics.update(cur.fetchone())
        cur.execute(f"SELECT slot,count(*) count FROM analysis_group_completeness c JOIN sample_analysis_groups g ON g.id=c.group_id CROSS JOIN LATERAL unnest(c.missing_slots) slot WHERE {group_where} AND c.last_analysis_at>=%s GROUP BY slot ORDER BY slot",group_args+(start,)); missing={row["slot"]:row["count"] for row in cur.fetchall()}
        if metric=="runs":
            cur.execute(f"SELECT completed_at::date AS \"day\",count(*) FILTER(WHERE analysis_type='static' AND static_repetition IN(1,2,3)) static,count(*) FILTER(WHERE analysis_type='dynamic' AND duration_bucket=60) dynamic_60,count(*) FILTER(WHERE analysis_type='dynamic' AND duration_bucket=120) dynamic_120,count(*) FILTER(WHERE analysis_type='dynamic' AND duration_bucket=180) dynamic_180,count(*) FILTER(WHERE NOT ((analysis_type='static' AND static_repetition IN(1,2,3)) OR (analysis_type='dynamic' AND duration_bucket IN(60,120,180)))) other FROM analysis_runs r WHERE {where} AND completed_at>=%s GROUP BY 1 ORDER BY 1",args+(start,)); raw_daily=cur.fetchall(); keys=("static","dynamic_60","dynamic_120","dynamic_180","other")
        elif metric=="samples":
            cur.execute(f"SELECT first_seen::date AS \"day\",count(*) total FROM samples s WHERE {sample_where} AND first_seen>=%s GROUP BY 1 ORDER BY 1",sample_args+(start,)); raw_daily=cur.fetchall(); keys=("total",)
        else:
            cur.execute(f"SELECT created_at::date AS \"day\",count(*) total FROM sample_analysis_groups g WHERE {group_where} AND created_at>=%s GROUP BY 1 ORDER BY 1",group_args+(start,)); raw_daily=cur.fetchall(); keys=("total",)
        daily=zero_fill_daily(start.date(),end,raw_daily,keys)
        cur.execute(f"SELECT CASE WHEN analysis_type='static' THEN 'Static' WHEN duration_bucket=60 THEN 'Dynamic 60s' WHEN duration_bucket=120 THEN 'Dynamic 120s' WHEN duration_bucket=180 THEN 'Dynamic 180s' ELSE 'Other' END run_kind,verdict,count(*) count FROM analysis_runs r WHERE {where} AND completed_at>=%s AND (analysis_type='static' OR duration_bucket IN(60,120,180)) GROUP BY 1,2 ORDER BY 1,2",args+(start,)); verdicts=cur.fetchall()
        cur.execute("SELECT * FROM collector_status WHERE singleton"); collector=cur.fetchone()
        cur.execute("SELECT count(*) count FROM collection_errors WHERE occurred_at>=now()-interval '24 hours'"); recent_errors=cur.fetchone()["count"]
    chart_max=max([sum(row[key] for key in keys) for row in daily] or [1]); chart_max=max(chart_max,1)
    verdict_categories=("malicious","suspicious","benign","unknown","failed"); verdict_kinds=("Static","Dynamic 60s","Dynamic 120s","Dynamic 180s")
    verdict_lookup={(row["run_kind"],row["verdict"]):row["count"] for row in verdicts}
    verdict_matrix=[{"kind":kind,"counts":{category:verdict_lookup.get((kind,category),0) for category in verdict_categories}} for kind in verdict_kinds]
    for row in verdict_matrix:row["total"]=sum(row["counts"].values())
    return render(request,"overview.html",{"title":"Overview","metrics":metrics,"daily":daily,"chart_keys":keys,"chart_max":chart_max,"metric":metric,"verdict_matrix":verdict_matrix,"verdict_categories":verdict_categories,"collector":collector,"missing":missing,"recent_errors":recent_errors})


@app.get("/groups/incomplete",response_class=HTMLResponse,dependencies=[Depends(auth)])
def incomplete_groups(request:Request,page:int=1):
    mode,start,_=filters(request); where,args=mode_sql(mode,"g"); page=max(page,1)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT c.group_id,s.id sample_id,s.sha256,s.filename,g.grouping_confidence,c.expected_slots_present,c.missing_slots,c.duplicate_slots,c.first_analysis_at,c.last_analysis_at FROM analysis_group_completeness c JOIN sample_analysis_groups g ON g.id=c.group_id JOIN samples s ON s.id=g.sample_id WHERE {where} AND c.missing_slot_count>0 AND c.last_analysis_at>=%s ORDER BY c.last_analysis_at DESC LIMIT 100 OFFSET %s",args+(start,(page-1)*100)); rows=cur.fetchall()
    return render(request,"groups.html",{"title":"Incomplete analysis groups","groups":rows,"page":page})


@app.get("/verdicts",response_class=HTMLResponse,dependencies=[Depends(auth)])
def verdicts(request:Request):
    mode,start,_=filters(request); where,args=mode_sql(mode)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT analysis_type,duration_bucket,verdict,support_classification,count(*) count FROM analysis_runs r WHERE {where} AND completed_at>=%s GROUP BY 1,2,3,4 ORDER BY count DESC",args+(start,)); rows=cur.fetchall()
        cur.execute(f"SELECT a.duration_bucket from_duration,b.duration_bucket to_duration,a.verdict from_verdict,b.verdict to_verdict,count(*) count FROM analysis_runs a JOIN analysis_runs b ON a.group_id=b.group_id AND a.duration_bucket<b.duration_bucket WHERE {where.replace('r.','a.')} AND a.completed_at>=%s AND a.analysis_type='dynamic' AND b.analysis_type='dynamic' GROUP BY 1,2,3,4 ORDER BY 1,2,3,4",args+(start,)); transitions=cur.fetchall()
    return render(request,"table_page.html",{"title":"Verdict comparison","intro":"Static consensus and duration transitions. Links open the matching sample set.","sections":[("Verdict and support totals",rows),("Dynamic transition matrices",transitions)]})


@app.get("/vtis",response_class=HTMLResponse,dependencies=[Depends(auth)])
def vtis(request:Request):
    mode,start,_=filters(request); where,args=mode_sql(mode)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT d.stable_id,d.category,d.operation,count(*) observations,round(avg(o.score),2) avg_score,max(o.score) max_score FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id WHERE {where} AND r.completed_at>=%s GROUP BY 1,2,3 ORDER BY observations DESC LIMIT 100",args+(start,)); top=cur.fetchall()
        cur.execute(f"SELECT r.analysis_type,r.duration_bucket,round(avg(x.n),2) average,percentile_cont(.5) WITHIN GROUP(ORDER BY x.n) median,max(x.n) maximum FROM (SELECT analysis_run_id,count(*) n FROM vti_observations GROUP BY 1)x JOIN analysis_runs r ON r.id=x.analysis_run_id WHERE {where} AND r.completed_at>=%s GROUP BY 1,2 ORDER BY 1,2",args+(start,)); stats=cur.fetchall()
    return render(request,"table_page.html",{"title":"VTI analytics","intro":"Stable identities are compared independently from observation scores and artifact scope.","sections":[("VTI counts",stats),("Top VTI",top)]})


@app.get("/iocs",response_class=HTMLResponse,dependencies=[Depends(auth)])
def iocs(request:Request):
    mode,start,_=filters(request); where,args=mode_sql(mode)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT i.ioc_type,count(*) observations,count(*) FILTER(WHERE i.actionable) actionable,count(DISTINCT i.normalized_value) unique_values FROM ioc_observations i JOIN analysis_runs r ON r.id=i.analysis_run_id WHERE {where} AND r.completed_at>=%s GROUP BY 1 ORDER BY observations DESC",args+(start,)); types=cur.fetchall()
        cur.execute(f"SELECT i.normalized_value,i.ioc_type,count(*) observations,count(*) FILTER(WHERE i.actionable) actionable FROM ioc_observations i JOIN analysis_runs r ON r.id=i.analysis_run_id WHERE {where} AND r.completed_at>=%s GROUP BY 1,2 ORDER BY observations DESC LIMIT 100",args+(start,)); top=cur.fetchall()
    return render(request,"table_page.html",{"title":"IOC analytics","intro":"Immutable per-analysis IOC snapshots, normalized deterministically.","sections":[("IOC types and actionability",types),("Top normalized IOC values",top)]})


@app.get("/samples",response_class=HTMLResponse,dependencies=[Depends(auth)])
def samples(request:Request,q:str="",page:int=1):
    mode,start,_=filters(request); where,args=mode_sql(mode,"s"); page=max(1,page); search=f"%{q.strip()}%"
    search_sql="" if not q else "AND (s.sha256 ILIKE %s OR s.sha1 ILIKE %s OR s.md5 ILIKE %s OR s.filename ILIKE %s OR EXISTS(SELECT 1 FROM analysis_runs ar WHERE ar.sample_id=s.id AND (ar.vmray_analysis_id::text ILIKE %s OR ar.vmray_submission_id::text ILIKE %s)) OR EXISTS(SELECT 1 FROM ioc_observations io JOIN analysis_runs ar ON ar.id=io.analysis_run_id WHERE ar.sample_id=s.id AND (io.original_value ILIKE %s OR io.normalized_value ILIKE %s)) OR EXISTS(SELECT 1 FROM vti_observations vo JOIN analysis_runs ar ON ar.id=vo.analysis_run_id JOIN vti_definitions vd ON vd.id=vo.vti_definition_id WHERE ar.sample_id=s.id AND vd.stable_id ILIKE %s))"
    params=args+(start,)+((search,)*9 if q else ())+(50,(page-1)*50)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT s.id,s.sha256,s.filename,s.first_seen,s.latest_seen,s.is_demo,g.id group_id,g.grouping_confidence,c.completeness_status,c.expected_slots_present,c.missing_slots,c.duplicate_slots,max(r.verdict) FILTER(WHERE r.analysis_type='static') static_verdict,max(r.verdict) FILTER(WHERE r.duration_bucket=60) dynamic_60,max(r.verdict) FILTER(WHERE r.duration_bucket=120) dynamic_120,max(r.verdict) FILTER(WHERE r.duration_bucket=180) dynamic_180,string_agg(DISTINCT r.support_classification,', ') support FROM samples s JOIN sample_analysis_groups g ON g.sample_id=s.id JOIN analysis_group_completeness c ON c.group_id=g.id JOIN analysis_runs r ON r.group_id=g.id WHERE {where} AND r.completed_at>=%s {search_sql} GROUP BY s.id,g.id,c.group_id,c.completeness_status,c.expected_slots_present,c.missing_slots,c.duplicate_slots ORDER BY s.latest_seen DESC,g.id DESC LIMIT %s OFFSET %s",params); rows=cur.fetchall()
    return render(request,"samples.html",{"title":"Samples","samples":rows,"q":q,"page":page})


@app.get("/samples/{sample_id}",response_class=HTMLResponse,dependencies=[Depends(auth)])
def sample_detail(request:Request,sample_id:int):
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT * FROM samples WHERE id=%s",(sample_id,)); sample=cur.fetchone()
        if not sample:raise HTTPException(404)
        cur.execute("SELECT g.*,c.expected_slots_present,c.missing_slots,c.duplicate_slots,c.unmapped_run_count,c.completeness_status FROM sample_analysis_groups g JOIN analysis_group_completeness c ON c.group_id=g.id WHERE g.sample_id=%s ORDER BY g.created_at,g.id",(sample_id,)); groups=cur.fetchall()
        cur.execute("SELECT r.*,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id) vti_count,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id AND score>=3) high_vti_count,(SELECT count(*) FROM ioc_observations WHERE analysis_run_id=r.id) ioc_count,(SELECT count(*) FROM ioc_observations WHERE analysis_run_id=r.id AND actionable) actionable_ioc_count FROM analysis_runs r WHERE r.sample_id=%s ORDER BY r.group_id,r.completed_at,r.vmray_analysis_id",(sample_id,)); runs=cur.fetchall()
    by_group={group["id"]:group for group in groups}
    for group in groups: group["slots"]={slot:[] for slot in EXPECTED_SLOTS}; group["unmapped_runs"]=[]
    for run in runs:
        slot=None
        if run["analysis_type"]=="static" and run["static_repetition"] in (1,2,3):slot=f"static_{run['static_repetition']}"
        elif run["analysis_type"]=="dynamic" and run["duration_bucket"] in (60,120,180):slot=f"dynamic_{run['duration_bucket']}"
        if slot:by_group[run["group_id"]]["slots"][slot].append(run)
        else:by_group[run["group_id"]]["unmapped_runs"].append(run)
    return render(request,"sample_detail.html",{"title":"Sample detail","sample":sample,"groups":groups,"expected_slots":EXPECTED_SLOTS})


EXPORTS={
 "samples":"SELECT s.*,g.id AS group_id,g.grouping_confidence,c.completeness_status,c.expected_slots_present,c.missing_slots,c.duplicate_slots,c.unmapped_run_count FROM samples s JOIN sample_analysis_groups g ON g.sample_id=s.id JOIN analysis_group_completeness c ON c.group_id=g.id WHERE s.is_demo=%s ORDER BY s.latest_seen DESC,g.id", "analysis-runs":"SELECT * FROM analysis_runs WHERE is_demo=%s ORDER BY completed_at DESC",
 "vti-observations":"SELECT o.*,d.stable_id,d.category,d.operation FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id WHERE r.is_demo=%s",
 "ioc-observations":"SELECT i.* FROM ioc_observations i JOIN analysis_runs r ON r.id=i.analysis_run_id WHERE r.is_demo=%s", "collection-errors":"SELECT * FROM collection_errors ORDER BY occurred_at DESC",
 "verdict-comparisons":"SELECT group_id,analysis_type,duration_bucket,verdict,support_classification FROM analysis_runs WHERE is_demo=%s ORDER BY group_id,duration_bucket",
 "vti-comparisons":"SELECT r.group_id,r.duration_bucket,d.stable_id,o.score,o.scope,o.artifact_id FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id WHERE r.is_demo=%s",
 "ioc-comparisons":"SELECT r.group_id,r.duration_bucket,i.ioc_type,i.normalized_value,i.actionable FROM ioc_observations i JOIN analysis_runs r ON r.id=i.analysis_run_id WHERE r.is_demo=%s"
}
@app.get("/exports/{kind}.csv",dependencies=[Depends(auth)])
def export(request:Request,kind:str):
    if kind not in EXPORTS:raise HTTPException(404)
    mode,_,_=filters(request); sql=EXPORTS[kind]; params=() if kind=="collection-errors" else (mode=="demo",)
    if mode=="combined" and kind!="collection-errors":sql=sql.replace("WHERE is_demo=%s","WHERE TRUE").replace("WHERE r.is_demo=%s","WHERE TRUE").replace("WHERE s.is_demo=%s","WHERE TRUE");params=()
    with connection() as conn,conn.cursor() as cur:cur.execute(sql,params);rows=cur.fetchall()
    out=io.StringIO(); writer=csv.DictWriter(out,fieldnames=list(rows[0]) if rows else ["empty"]);writer.writeheader();writer.writerows(rows)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{kind}.csv"'})
