from datetime import date, timedelta

RUN_KINDS = ("Static", "Dynamic 60s", "Dynamic 120s", "Dynamic 180s")
VERDICT_CATEGORIES = ("malicious", "suspicious", "benign", "unknown", "failed", "mixed", "missing")
SUPPORT_CATEGORIES = ("av_only", "yara_only", "av_yara_only", "behavioral", "none", "missing")

SAMPLE_COHORT_SQL = """
SELECT s.id sample_id,s.first_seen,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='static') has_static,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='dynamic' AND r.duration_bucket=60) has_dynamic_60,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='dynamic' AND r.duration_bucket=120) has_dynamic_120,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='dynamic' AND r.duration_bucket=180) has_dynamic_180
FROM samples s WHERE {mode_clause} AND s.first_seen >= %s
"""

SAMPLE_RESULTS_SQL = """
WITH selected AS (
 SELECT s.id,sas.static_verdict,sas.dynamic_60_verdict,sas.dynamic_120_verdict,sas.dynamic_180_verdict
 FROM samples s JOIN sample_analysis_summary sas ON sas.sample_id=s.id WHERE s.id=ANY(%s)
), kinds(kind) AS (VALUES ('Static'),('Dynamic 60s'),('Dynamic 120s'),('Dynamic 180s')),
evidence AS (
 SELECT selected.id sample_id,k.kind,
  CASE k.kind WHEN 'Static' THEN selected.static_verdict WHEN 'Dynamic 60s' THEN selected.dynamic_60_verdict WHEN 'Dynamic 120s' THEN selected.dynamic_120_verdict ELSE selected.dynamic_180_verdict END verdict,
  count(r.id) run_count,
  bool_or(o.score BETWEEN 3 AND 5 AND lower(trim(d.category))='antivirus') has_av,
  bool_or(o.score BETWEEN 3 AND 5 AND lower(trim(d.category))='yara') has_yara,
  bool_or(o.score BETWEEN 3 AND 5 AND lower(trim(d.category)) NOT IN ('antivirus','yara')) has_behavioral
 FROM selected CROSS JOIN kinds k
 LEFT JOIN analysis_runs r ON r.sample_id=selected.id AND ((k.kind='Static' AND r.analysis_type='static') OR (k.kind='Dynamic 60s' AND r.analysis_type='dynamic' AND r.duration_bucket=60) OR (k.kind='Dynamic 120s' AND r.analysis_type='dynamic' AND r.duration_bucket=120) OR (k.kind='Dynamic 180s' AND r.analysis_type='dynamic' AND r.duration_bucket=180))
 LEFT JOIN vti_observations o ON o.analysis_run_id=r.id LEFT JOIN vti_definitions d ON d.id=o.vti_definition_id
 GROUP BY selected.id,k.kind,selected.static_verdict,selected.dynamic_60_verdict,selected.dynamic_120_verdict,selected.dynamic_180_verdict
)
SELECT sample_id,kind run_kind,verdict,
 CASE WHEN run_count=0 THEN 'missing' WHEN has_behavioral THEN 'behavioral' WHEN has_av AND has_yara THEN 'av_yara_only' WHEN has_av THEN 'av_only' WHEN has_yara THEN 'yara_only' ELSE 'none' END support
FROM evidence
"""


def fetch_sample_cohort(cur, mode, start):
    clause = "TRUE" if mode == "combined" else "s.is_demo=%s"
    args = (start,) if mode == "combined" else (mode == "demo", start)
    cur.execute(SAMPLE_COHORT_SQL.format(mode_clause=clause), args)
    return cur.fetchall()


def fetch_sample_results(cur, sample_ids):
    if not sample_ids:return []
    cur.execute(SAMPLE_RESULTS_SQL, (list(sample_ids),))
    return cur.fetchall()


def summarize_sample_results(rows):
    output=[]
    for kind in RUN_KINDS:
        selected=[r for r in rows if r["run_kind"]==kind]
        verdicts={c:sum(r["verdict"]==c for r in selected) for c in VERDICT_CATEGORIES}
        support={c:sum(r["support"]==c for r in selected) for c in SUPPORT_CATEGORIES}
        av_yara=sum(support[c] for c in ("av_only","yara_only","av_yara_only"))
        output.append({"kind":kind,"total":len(selected),"verdicts":verdicts,"support":support,"av_yara_only":av_yara,
         "av_yara_malicious":sum(r["support"] in ("av_only","yara_only","av_yara_only") and r["verdict"]=="malicious" for r in selected),
         "av_yara_suspicious":sum(r["support"] in ("av_only","yara_only","av_yara_only") and r["verdict"]=="suspicious" for r in selected)})
    return output


def summarize_cohort(rows):
    metrics={"samples_received":len(rows),"static_analyzed":sum(r["has_static"] for r in rows),"dynamic_60":sum(r["has_dynamic_60"] for r in rows),"dynamic_120":sum(r["has_dynamic_120"] for r in rows),"dynamic_180":sum(r["has_dynamic_180"] for r in rows)}
    daily=[]
    for day in sorted({r["first_seen"].date() for r in rows}):
        selected=[r for r in rows if r["first_seen"].date()==day]
        daily.append({"day":day,"samples_received":len(selected),"static_analyzed":sum(r["has_static"] for r in selected),"dynamic_60":sum(r["has_dynamic_60"] for r in selected),"dynamic_120":sum(r["has_dynamic_120"] for r in selected),"dynamic_180":sum(r["has_dynamic_180"] for r in selected)})
    return metrics,daily


def zero_fill_daily(start: date, end: date, rows, keys):
    indexed={row["day"]:row for row in rows}; output=[]; current=start
    while current<=end:
        source=indexed.get(current,{})
        output.append({"day":current,**{key:int(source.get(key) or 0) for key in keys}});current+=timedelta(days=1)
    return output
