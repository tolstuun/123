import csv, hmac, io
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .db import connection, open_pool
from .metrics import Window, cohort_bundle, detection_by_arm, duration_lift, new_vtis_by_arm, submission_order_fixed_pct
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

CATEGORIES=("behavioural_malicious","behavioural_suspicious","nonbehavioural_malicious","nonbehavioural_suspicious","benign","no_verdict")
CATEGORY_LABELS={"behavioural_malicious":"Behavioural malicious","behavioural_suspicious":"Behavioural suspicious","nonbehavioural_malicious":"AV/Rep/YARA-only malicious","nonbehavioural_suspicious":"AV/Rep/YARA-only suspicious","benign":"Benign","no_verdict":"No verdict"}
ARM_LABELS={"static":"Static","60":"60s","120":"120s","180":"180s"}

def aggregate_detection(rows,include_static=True):
    output=[]
    for arm in (("static","60","120","180") if include_static else ("60","120","180")):
        selected=[r for r in rows if r["arm"]==arm]
        counts={category:sum(int(r[category]) for r in selected) for category in CATEGORIES}
        output.append({"arm":arm,"label":ARM_LABELS[arm],"counts":counts,"total":sum(counts.values())})
    return output

def sparklines(rows,end,days):
    indexed={row["cohort_day"]:row for row in rows};dates=[(end-timedelta(days=offset)).date() for offset in range(days-1,-1,-1)]
    result=[]
    for arm,key in (("static","static"),("60","d60"),("120","d120"),("180","d180")):
        values=[int(indexed.get(day,{}).get(key,0)) for day in dates];peak=max(values,default=0)
        points=" ".join(f"{(i*100/(len(values)-1) if len(values)>1 else 50):.2f},{(36-(value/peak*32) if peak else 36):.2f}" for i,value in enumerate(values))
        result.append({"label":ARM_LABELS[arm],"points":points,"values":values,"peak":peak})
    return result

def cohort_dashboard(window,cohort_type,title):
    bundle=cohort_bundle(window,cohort_type);coverage_rows=[]
    for base,longer in ((60,120),(120,180),(60,180)):
        pair=[r for r in bundle["coverage"] if r["base"]==base and r["longer"]==longer]
        overall=next(r for r in pair if r["order_side"]=="all")
        coverage_rows.append({"label":f"{base}s → {longer}s","overall":overall})
    return {"type":cohort_type,"title":title,"bars":aggregate_detection(bundle["detection"],cohort_type=="file"),"daily":bundle["daily"],
      "exclusions":bundle["exclusions"],"coverage_rows":coverage_rows,
      "new_60_180":bundle["new_60_180"],"new_60_120":bundle["new_60_120"]}

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
    start,end,days=filters(request);window=Window(start,end)
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT * FROM collector_status WHERE singleton");collector=cur.fetchone()
        cur.execute("""SELECT count(*) FILTER(WHERE analysis_type='dynamic' AND duration_bucket IS NULL) null_duration,
          count(*) FILTER(WHERE is_failed) failed_runs,(SELECT count(*) FROM vti_seen_categories) categories_seen
          FROM analysis_runs WHERE created_at>=%s AND created_at<%s""",(start,end));health=cur.fetchone()
    health["submission_order_fixed_pct"]=submission_order_fixed_pct(window)
    cohorts=[cohort_dashboard(window,"file","Files"),cohort_dashboard(window,"url","URLs")]
    combined_daily={}
    for cohort in cohorts:
        for row in cohort["daily"]:
            target=combined_daily.setdefault(row["cohort_day"],{"cohort_day":row["cohort_day"],"static":0,"d60":0,"d120":0,"d180":0})
            for key in ("static","d60","d120","d180"):target[key]+=row[key]
    sparks=sparklines(list(combined_daily.values()),end,days)
    return render(request,"overview.html",{"title":"Overview","cohorts":cohorts,"categories":CATEGORIES,"category_labels":CATEGORY_LABELS,"collector":collector,"health":health,"sparks":sparks})

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

@app.get("/vti-categories",response_class=HTMLResponse,dependencies=[Depends(auth)])
def vti_categories(request:Request):
    with connection() as conn,conn.cursor() as cur:
        cur.execute("SELECT category,occurrences,max_score,first_seen,last_seen FROM vti_seen_categories ORDER BY occurrences DESC,category");rows=cur.fetchall()
    return render(request,"table_page.html",{"title":"VTI categories seen","intro":"Passive inventory of high-confidence VTI categories; this table does not influence scoring.","sections":[("Categories",rows)]})

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

@app.get("/exports/{kind}.csv",dependencies=[Depends(auth)])
def export(request:Request,kind:str):
    start,end,_=filters(request);window=Window(start,end)
    if kind=="analysis-runs":
        with connection() as conn,conn.cursor() as cur:cur.execute("SELECT * FROM analysis_runs WHERE created_at>=%s AND created_at<%s ORDER BY created_at",(start,end));rows=cur.fetchall()
    elif kind=="detection-by-arm":rows=[{"cohort_type":cohort,**dict(row)} for cohort in ("file","url") for row in detection_by_arm(window,cohort)]
    elif kind=="behavioural-coverage":
        columns=("base","longer","order_side","rounds","behav_base","behav_longer","exclusive","crossout","pct_coverage_gain","pct_uplift_over_base","underpowered")
        rows=[]
        for cohort in ("file","url"):
            for row in cohort_bundle(window,cohort)["coverage"]:
                rows.append({"cohort_type":cohort,**{column:row[column] for column in columns}})
    elif kind=="duration-lift":rows=[{"cohort_type":cohort,**dict(row)} for cohort in ("file","url") for row in duration_lift(window,cohort)]
    elif kind=="new-vtis":
        rows=[]
        for cohort in ("file","url"):
            for base,longer in ((60,120),(60,180),(120,180)):rows.extend({"cohort_type":cohort,"base":base,"longer":longer,**dict(row)} for row in new_vtis_by_arm(window,cohort,base,longer,limit=None))
    else:raise HTTPException(404)
    out=io.StringIO();writer=csv.DictWriter(out,fieldnames=list(rows[0]) if rows else ["empty"]);writer.writeheader();writer.writerows(rows)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{kind}.csv"'})
