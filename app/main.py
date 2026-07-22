import csv, hmac, io
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .db import connection, open_pool
from .metrics import Window, detection_by_arm, new_vtis_by_arm
from .migrate import migrate

app=FastAPI(title="VMRay Analytics",docs_url=None,redoc_url=None,openapi_url=None)
templates=Jinja2Templates(directory="app/templates");app.mount("/static",StaticFiles(directory="app/static"),name="static");security=HTTPBasic()

@app.on_event("startup")
def startup():settings.validate_web();open_pool();migrate()

@app.middleware("http")
async def headers(request,call_next):
    if request.headers.get("content-length") and int(request.headers["content-length"])>1_048_576:return Response(status_code=413)
    response=await call_next(request);response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Content-Security-Policy":"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:","Cache-Control":"no-store"});return response

def auth(credentials:HTTPBasicCredentials=Depends(security)):
    good=hmac.compare_digest(credentials.username.encode(),settings.dashboard_username.encode()) and hmac.compare_digest(credentials.password.encode(),settings.dashboard_password.encode())
    if not good:raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,headers={"WWW-Authenticate":"Basic realm=VMRay Analytics"})

def filters(request):
    days=max(1,min(int(request.query_params.get("days","7")),3650));end=datetime.now(timezone.utc);return end-timedelta(days=days),end,days

def render(request,name,context):
    _,_,days=filters(request);return templates.TemplateResponse(request,name,{"days":days,**context})

def human_time(value):return value.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC") if value else "Never"
def human_duration(seconds):
    if seconds is None:return "Unknown"
    seconds=max(0,int(seconds));hours,remainder=divmod(seconds,3600);minutes,secs=divmod(remainder,60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m {secs}s" if minutes else f"{secs}s"
templates.env.globals.update(human_time=human_time,human_duration=human_duration)

@app.get("/health")
def health():return {"status":"alive"}

@app.get("/ready")
def ready():
    try:
        with connection() as conn,conn.cursor() as cur:cur.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1");version=cur.fetchone()
        return {"status":"ready","database":"ok","migration":version["version"]}
    except Exception:raise HTTPException(503,"not ready")

@app.get("/",response_class=HTMLResponse,dependencies=[Depends(auth)])
def overview(request:Request):
    start,end,days=filters(request);rows=detection_by_arm(Window(start,end))
    categories=("behavioural_malicious","behavioural_suspicious","nonbehavioural_malicious","nonbehavioural_suspicious","benign","no_verdict","failed","missing")
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT * FROM collector_status WHERE singleton");collector=cur.fetchone()
        cur.execute("SELECT count(*) count FROM collection_errors WHERE occurred_at>=now()-interval '24 hours'");recent_errors=cur.fetchone()["count"]
    return render(request,"overview.html",{"title":"Overview","detection_rows":rows,"categories":categories,"collector":collector,"recent_errors":recent_errors})

@app.get("/vtis",response_class=HTMLResponse,dependencies=[Depends(auth)])
def vtis(request:Request):
    start,end,_=filters(request);window=Window(start,end)
    rows=new_vtis_by_arm(window,60,120)+new_vtis_by_arm(window,120,180)
    return render(request,"table_page.html",{"title":"VTI analytics","intro":"New VTIs compare dynamic arms within the same sample and submission round.","sections":[("New VTIs by arm",rows)]})

SAMPLE_SUMMARY="""SELECT s.*,
 count(r.id) FILTER(WHERE r.analysis_type='static')::int static_count,
 count(r.id) FILTER(WHERE r.analysis_type='dynamic' AND r.duration_bucket=60)::int dynamic_60_count,
 count(r.id) FILTER(WHERE r.analysis_type='dynamic' AND r.duration_bucket=120)::int dynamic_120_count,
 count(r.id) FILTER(WHERE r.analysis_type='dynamic' AND r.duration_bucket=180)::int dynamic_180_count
 FROM samples s LEFT JOIN analysis_runs r ON r.sample_id=s.id"""

@app.get("/samples",response_class=HTMLResponse,dependencies=[Depends(auth)])
def samples(request:Request,q:str="",page:int=1):
    start,_,_=filters(request);page=max(1,page);search=f"%{q.strip()}%"
    search_sql="" if not q else "AND (s.sha256 ILIKE %s OR s.sha1 ILIKE %s OR s.md5 ILIKE %s OR s.filename ILIKE %s OR EXISTS(SELECT 1 FROM analysis_runs ar WHERE ar.sample_id=s.id AND (ar.vmray_analysis_id::text ILIKE %s OR ar.vmray_submission_id::text ILIKE %s)) OR EXISTS(SELECT 1 FROM vti_observations vo JOIN analysis_runs ar ON ar.id=vo.analysis_run_id JOIN vti_definitions vd ON vd.id=vo.vti_definition_id WHERE ar.sample_id=s.id AND vd.stable_id ILIKE %s))"
    params=(start,)+((search,)*7 if q else ())+(50,(page-1)*50)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(f"{SAMPLE_SUMMARY} WHERE s.latest_seen>=%s {search_sql} GROUP BY s.id ORDER BY s.latest_seen DESC LIMIT %s OFFSET %s",params);rows=cur.fetchall()
    return render(request,"samples.html",{"title":"Samples","samples":rows,"q":q,"page":page})

@app.get("/samples/{sample_id}",response_class=HTMLResponse,dependencies=[Depends(auth)])
def sample_detail(request:Request,sample_id:int):
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT * FROM samples WHERE id=%s",(sample_id,));sample=cur.fetchone()
        if not sample:raise HTTPException(404)
        cur.execute("SELECT r.*,(SELECT count(*) FROM vti_observations WHERE analysis_run_id=r.id) vti_count FROM analysis_runs r WHERE r.sample_id=%s ORDER BY r.round_id,coalesce(r.submission_created,r.created_at),r.vmray_analysis_id",(sample_id,));runs=cur.fetchall()
    sections={"Static analyses":[],"Dynamic 60s analyses":[],"Dynamic 120s analyses":[],"Dynamic 180s analyses":[],"Other/unknown analyses":[]}
    for run in runs:
        key="Static analyses" if run["analysis_type"]=="static" else f"Dynamic {run['duration_bucket']}s analyses" if run["analysis_type"]=="dynamic" and run["duration_bucket"] in (60,120,180) else "Other/unknown analyses";sections[key].append(run)
    return render(request,"sample_detail.html",{"title":"Sample detail","sample":sample,"sections":sections})

EXPORTS={
 "samples":"SELECT * FROM samples ORDER BY latest_seen DESC",
 "analysis-runs":"SELECT * FROM analysis_runs ORDER BY created_at DESC",
 "vti-observations":"SELECT o.*,d.stable_id,d.category,d.operation,r.sample_id,r.round_id FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id ORDER BY o.id",
 "collection-errors":"SELECT * FROM collection_errors ORDER BY occurred_at DESC",
 "vti-comparisons":"SELECT r.sample_id,r.round_id,r.duration_bucket,d.stable_id,o.score,o.scope,o.artifact_id FROM vti_observations o JOIN vti_definitions d ON d.id=o.vti_definition_id JOIN analysis_runs r ON r.id=o.analysis_run_id ORDER BY r.sample_id,r.round_id"
}

@app.get("/exports/{kind}.csv",dependencies=[Depends(auth)])
def export(kind:str):
    if kind not in EXPORTS:raise HTTPException(404)
    with connection() as conn,conn.cursor() as cur:cur.execute(EXPORTS[kind]);rows=cur.fetchall()
    out=io.StringIO();writer=csv.DictWriter(out,fieldnames=list(rows[0]) if rows else ["empty"]);writer.writeheader();writer.writerows(rows)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{kind}.csv"'})
