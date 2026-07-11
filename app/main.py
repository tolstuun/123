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
    mode=request.query_params.get("mode","real"); days=max(1,min(int(request.query_params.get("days","30")),3650)); return mode,datetime.now(timezone.utc)-timedelta(days=days),days


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


@app.get("/",response_class=HTMLResponse,dependencies=[Depends(auth)])
def overview(request:Request):
    mode,start,_=filters(request); where,args=mode_sql(mode)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"SELECT count(*) analyses,count(DISTINCT sample_id) samples,count(*) FILTER(WHERE analysis_type='static') static_count,count(*) FILTER(WHERE analysis_type='dynamic') dynamic_count,count(*) FILTER(WHERE completed_at>=date_trunc('day',now())) today_analyses,count(DISTINCT sample_id) FILTER(WHERE completed_at>=date_trunc('day',now())) today_samples FROM analysis_runs r WHERE {where} AND completed_at>=%s",args+(start,)); metrics=cur.fetchone()
        cur.execute(f"SELECT count(*) FILTER(WHERE n=6) complete,count(*) FILTER(WHERE n<>6) incomplete FROM (SELECT group_id,count(*) n FROM analysis_runs r WHERE {where} AND completed_at>=%s GROUP BY group_id)x",args+(start,)); metrics.update(cur.fetchone())
        cur.execute(f"SELECT completed_at::date AS observation_day,count(*) analyses,count(DISTINCT sample_id) samples,count(*) FILTER(WHERE analysis_type='static') static,count(*) FILTER(WHERE analysis_type='dynamic') dynamic FROM analysis_runs r WHERE {where} AND completed_at>=%s GROUP BY 1 ORDER BY 1",args+(start,)); daily=cur.fetchall()
        cur.execute(f"SELECT analysis_type,duration_bucket,verdict,count(*) count FROM analysis_runs r WHERE {where} AND completed_at>=%s GROUP BY 1,2,3 ORDER BY 1,2,3",args+(start,)); verdicts=cur.fetchall()
        cur.execute("SELECT * FROM collector_status WHERE singleton"); collector=cur.fetchone()
    return render(request,"overview.html",{"title":"Overview","metrics":metrics,"daily":daily,"verdicts":verdicts,"collector":collector})


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
        cur.execute(f"SELECT s.id,s.sha256,s.filename,s.first_seen,s.latest_seen,s.is_demo,g.grouping_confidence,count(r.id) completeness,max(r.verdict) FILTER(WHERE r.analysis_type='static') static_verdict,max(r.verdict) FILTER(WHERE r.duration_bucket=60) dynamic_60,max(r.verdict) FILTER(WHERE r.duration_bucket=120) dynamic_120,max(r.verdict) FILTER(WHERE r.duration_bucket=180) dynamic_180,string_agg(DISTINCT r.support_classification,', ') support FROM samples s JOIN sample_analysis_groups g ON g.sample_id=s.id JOIN analysis_runs r ON r.group_id=g.id WHERE {where} AND r.completed_at>=%s {search_sql} GROUP BY s.id,g.id ORDER BY s.latest_seen DESC LIMIT %s OFFSET %s",params); rows=cur.fetchall()
    return render(request,"samples.html",{"title":"Samples","samples":rows,"q":q,"page":page})


@app.get("/samples/{sample_id}",response_class=HTMLResponse,dependencies=[Depends(auth)])
def sample_detail(request:Request,sample_id:int):
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT * FROM samples WHERE id=%s",(sample_id,)); sample=cur.fetchone()
        if not sample:raise HTTPException(404)
        cur.execute("SELECT r.*,g.grouping_warning,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id) vti_count,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id AND score>=3) high_vti_count,(SELECT count(*) FROM ioc_observations WHERE analysis_run_id=r.id) ioc_count,(SELECT count(*) FROM ioc_observations WHERE analysis_run_id=r.id AND actionable) actionable_ioc_count FROM analysis_runs r JOIN sample_analysis_groups g ON g.id=r.group_id WHERE r.sample_id=%s ORDER BY r.group_id,r.analysis_type DESC,r.static_repetition,r.duration_bucket",(sample_id,)); runs=cur.fetchall()
    return render(request,"sample_detail.html",{"title":"Sample detail","sample":sample,"runs":runs})


EXPORTS={
 "samples":"SELECT * FROM samples WHERE is_demo=%s ORDER BY latest_seen DESC", "analysis-runs":"SELECT * FROM analysis_runs WHERE is_demo=%s ORDER BY completed_at DESC",
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
    if mode=="combined" and kind!="collection-errors":sql=sql.replace("WHERE is_demo=%s","WHERE TRUE").replace("WHERE r.is_demo=%s","WHERE TRUE");params=()
    with connection() as conn,conn.cursor() as cur:cur.execute(sql,params);rows=cur.fetchall()
    out=io.StringIO(); writer=csv.DictWriter(out,fieldnames=list(rows[0]) if rows else ["empty"]);writer.writeheader();writer.writerows(rows)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{kind}.csv"'})
