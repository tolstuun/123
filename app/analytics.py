from datetime import date, timedelta

RUN_KINDS = ("Static", "Dynamic 60s", "Dynamic 120s", "Dynamic 180s")
VERDICT_CATEGORIES = ("malicious", "suspicious", "benign")

ELIGIBILITY_PREDICATE = """
EXISTS(SELECT 1 FROM analysis_runs er WHERE er.sample_id={alias}.id AND er.analysis_type='static')
AND EXISTS(SELECT 1 FROM analysis_runs er WHERE er.sample_id={alias}.id AND er.analysis_type='dynamic' AND er.duration_bucket=60)
AND EXISTS(SELECT 1 FROM analysis_runs er WHERE er.sample_id={alias}.id AND er.analysis_type='dynamic' AND er.duration_bucket=120)
AND EXISTS(SELECT 1 FROM analysis_runs er WHERE er.sample_id={alias}.id AND er.analysis_type='dynamic' AND er.duration_bucket=180)
"""

SAMPLE_COHORT_SQL = """
SELECT s.id sample_id,s.first_seen,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='static') has_static,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='dynamic' AND r.duration_bucket=60) has_dynamic_60,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='dynamic' AND r.duration_bucket=120) has_dynamic_120,
 EXISTS(SELECT 1 FROM analysis_runs r WHERE r.sample_id=s.id AND r.analysis_type='dynamic' AND r.duration_bucket=180) has_dynamic_180
FROM samples s WHERE {mode_clause} AND s.first_seen >= %s AND {eligibility}
"""

SAMPLE_RESULTS_SQL = """
WITH selected AS (
 SELECT s.id FROM samples s WHERE s.id=ANY(%s)
), kinds(kind) AS (VALUES ('Static'),('Dynamic 60s'),('Dynamic 120s'),('Dynamic 180s')),
results AS (
 SELECT selected.id sample_id,k.kind,
  count(r.id) run_count,
  bool_or(r.verdict='malicious') has_malicious,bool_or(r.verdict='suspicious') has_suspicious,
  bool_or(r.verdict='benign') has_benign
 FROM selected CROSS JOIN kinds k
 LEFT JOIN analysis_runs r ON r.sample_id=selected.id AND ((k.kind='Static' AND r.analysis_type='static') OR (k.kind='Dynamic 60s' AND r.analysis_type='dynamic' AND r.duration_bucket=60) OR (k.kind='Dynamic 120s' AND r.analysis_type='dynamic' AND r.duration_bucket=120) OR (k.kind='Dynamic 180s' AND r.analysis_type='dynamic' AND r.duration_bucket=180))
 GROUP BY selected.id,k.kind
)
SELECT sample_id,kind run_kind,CASE WHEN coalesce(has_malicious,false) THEN 'malicious' WHEN coalesce(has_suspicious,false) THEN 'suspicious' WHEN coalesce(has_benign,false) THEN 'benign' ELSE 'no_verdict' END verdict,
 run_count>0 analyzed
FROM results
"""


def fetch_sample_cohort(cur, mode, start):
    clause = "TRUE" if mode == "combined" else "s.is_demo=%s"
    args = (start,) if mode == "combined" else (mode == "demo", start)
    cur.execute(SAMPLE_COHORT_SQL.format(mode_clause=clause,eligibility=ELIGIBILITY_PREDICATE.format(alias="s")), args)
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
        malicious=verdicts["malicious"];suspicious=verdicts["suspicious"]
        output.append({"kind":kind,"total":len(selected),"verdicts":verdicts,"analyzed":sum(r["analyzed"] for r in selected),
         "malicious":malicious,"suspicious":suspicious,"detected":malicious+suspicious})
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
