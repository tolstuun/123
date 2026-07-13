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
from .analytics import ELIGIBILITY_PREDICATE, VERDICT_CATEGORIES, fetch_sample_cohort, fetch_sample_results, summarize_cohort, summarize_sample_results, zero_fill_daily

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
    mode,start,days=filters(request); end=datetime.now(timezone.utc).date()
    with connection() as conn,conn.cursor() as cur:
        cohort=fetch_sample_cohort(cur,mode,start); sample_ids={row["sample_id"] for row in cohort}
        sample_results=fetch_sample_results(cur,sample_ids)
        cur.execute("SELECT * FROM collector_status WHERE singleton"); collector=cur.fetchone()
        cur.execute("SELECT count(*) count FROM collection_errors WHERE occurred_at>=now()-interval '24 hours'"); recent_errors=cur.fetchone()["count"]
    metrics,raw_daily=summarize_cohort(cohort)
    keys=("samples_received","static_analyzed","dynamic_60","dynamic_120","dynamic_180");daily=zero_fill_daily(start.date(),end,raw_daily,keys)
    sample_summary=summarize_sample_results(sample_results)
    verdict_matrix=[{"kind":row["kind"],"counts":row["verdicts"],"total":row["total"]} for row in sample_summary]
    return render(request,"overview.html",{"title":"Overview","metrics":metrics,"daily":daily,"chart_keys":keys,"verdict_matrix":verdict_matrix,"verdict_categories":VERDICT_CATEGORIES,"verdict_labels":{"malicious":"Malicious","suspicious":"Suspicious","benign":"Benign","no_verdict":"No verdict / not analyzed"},"detection_rows":sample_summary,"collector":collector,"recent_errors":recent_errors})


@app.get("/verdicts",response_class=HTMLResponse,dependencies=[Depends(auth)])
def verdicts(request:Request):
    mode,start,_=filters(request); where,args=mode_sql(mode,"s")
    with connection() as conn,conn.cursor() as cur:
        cohort=fetch_sample_cohort(cur,mode,start);ids=[r["sample_id"] for r in cohort]
        cur.execute("SELECT static_verdict,dynamic_60_verdict,dynamic_120_verdict,dynamic_180_verdict,count(*) count FROM sample_analysis_summary WHERE sample_id=ANY(%s) GROUP BY 1,2,3,4 ORDER BY count DESC",(ids or [0],)); rows=cur.fetchall()
    return render(request,"table_page.html",{"title":"Verdict comparison","intro":"Sample-level verdicts; repeated runs are combined as consensus or mixed.","sections":[("Sample verdict combinations",rows)]})


@app.get("/vtis",response_class=HTMLResponse,dependencies=[Depends(auth)])
def vtis(request:Request):
    mode,start,_=filters(request)
    with connection() as conn,conn.cursor() as cur:
        cohort=fetch_sample_cohort(cur,mode,start);ids=[r["sample_id"] for r in cohort]
        cur.execute("SELECT d.stable_id,d.category,d.operation,count(*) observations,round(avg(o.score),2) avg_score,max(o.score) max_score FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id WHERE r.sample_id=ANY(%s) GROUP BY 1,2,3 ORDER BY observations DESC LIMIT 100",(ids or [0],)); top=cur.fetchall()
        cur.execute("SELECT r.analysis_type,r.duration_bucket,round(avg(x.n),2) average,percentile_cont(.5) WITHIN GROUP(ORDER BY x.n) median,max(x.n) maximum FROM (SELECT analysis_run_id,count(*) n FROM vti_observations GROUP BY 1)x JOIN analysis_runs r ON r.id=x.analysis_run_id WHERE r.sample_id=ANY(%s) GROUP BY 1,2 ORDER BY 1,2",(ids or [0],)); stats=cur.fetchall()
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
        cur.execute(f"SELECT s.*,sas.* FROM samples s JOIN sample_analysis_summary sas ON sas.sample_id=s.id WHERE {where} AND s.latest_seen>=%s {search_sql} ORDER BY s.latest_seen DESC LIMIT %s OFFSET %s",params); rows=cur.fetchall()
    return render(request,"samples.html",{"title":"Samples","samples":rows,"q":q,"page":page})


@app.get("/samples/{sample_id}",response_class=HTMLResponse,dependencies=[Depends(auth)])
def sample_detail(request:Request,sample_id:int):
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT * FROM samples WHERE id=%s",(sample_id,)); sample=cur.fetchone()
        if not sample:raise HTTPException(404)
        cur.execute("SELECT r.*,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id) vti_count,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id AND score>=3) high_vti_count,(SELECT count(*) FROM ioc_observations WHERE analysis_run_id=r.id) ioc_count,(SELECT count(*) FROM ioc_observations WHERE analysis_run_id=r.id AND actionable) actionable_ioc_count FROM analysis_runs r WHERE r.sample_id=%s ORDER BY coalesce(r.started_at,r.completed_at),r.vmray_analysis_id",(sample_id,)); runs=cur.fetchall()
    sections={"Static analyses":[],"Dynamic 60s analyses":[],"Dynamic 120s analyses":[],"Dynamic 180s analyses":[],"Other/unknown analyses":[]}
    for run in runs:
        key="Static analyses" if run["analysis_type"]=="static" else f"Dynamic {run['duration_bucket']}s analyses" if run["analysis_type"]=="dynamic" and run["duration_bucket"] in (60,120,180) else "Other/unknown analyses";sections[key].append(run)
    return render(request,"sample_detail.html",{"title":"Sample detail","sample":sample,"sections":sections})


EXPORTS={
 "samples":"SELECT s.*,sas.static_count,sas.dynamic_60_count,sas.dynamic_120_count,sas.dynamic_180_count,sas.static_verdict,sas.dynamic_60_verdict,sas.dynamic_120_verdict,sas.dynamic_180_verdict FROM samples s JOIN sample_analysis_summary sas ON sas.sample_id=s.id WHERE s.id=ANY(%s) ORDER BY s.latest_seen DESC", "analysis-runs":"SELECT * FROM analysis_runs WHERE is_demo=%s ORDER BY completed_at DESC",
 "vti-observations":"SELECT o.*,d.stable_id,d.category,d.operation FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id WHERE r.sample_id=ANY(%s)",
 "ioc-observations":"SELECT i.* FROM ioc_observations i JOIN analysis_runs r ON r.id=i.analysis_run_id WHERE r.is_demo=%s", "collection-errors":"SELECT * FROM collection_errors ORDER BY occurred_at DESC",
 "verdict-comparisons":"SELECT sample_id,analysis_type,duration_bucket,verdict,support_classification FROM analysis_runs WHERE sample_id=ANY(%s) ORDER BY sample_id,completed_at",
 "vti-comparisons":"SELECT r.sample_id,r.duration_bucket,d.stable_id,o.score,o.scope,o.artifact_id FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id WHERE r.sample_id=ANY(%s)",
 "ioc-comparisons":"SELECT r.sample_id,r.duration_bucket,i.ioc_type,i.normalized_value,i.actionable FROM ioc_observations i JOIN analysis_runs r ON r.id=i.analysis_run_id WHERE r.is_demo=%s"
}
@app.get("/exports/{kind}.csv",dependencies=[Depends(auth)])
def export(request:Request,kind:str):
    if kind not in EXPORTS:raise HTTPException(404)
    mode,start,_=filters(request); sql=EXPORTS[kind]; params=() if kind=="collection-errors" else (mode=="demo",)
    if kind in {"samples","vti-observations","verdict-comparisons","vti-comparisons"}:
        with connection() as conn,conn.cursor() as cur:ids=[r["sample_id"] for r in fetch_sample_cohort(cur,mode,start)]
        params=(ids or [0],)
    if mode=="combined" and kind not in {"collection-errors","samples","vti-observations","verdict-comparisons","vti-comparisons"}:sql=sql.replace("WHERE is_demo=%s","WHERE TRUE").replace("WHERE r.is_demo=%s","WHERE TRUE").replace("WHERE s.is_demo=%s","WHERE TRUE");params=()
    with connection() as conn,conn.cursor() as cur:cur.execute(sql,params);rows=cur.fetchall()
    out=io.StringIO(); writer=csv.DictWriter(out,fieldnames=list(rows[0]) if rows else ["empty"]);writer.writeheader();writer.writerows(rows)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{kind}.csv"'})
