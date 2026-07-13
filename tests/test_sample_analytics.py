from datetime import datetime, timezone
from pathlib import Path
from app.analytics import RUN_KINDS, SAMPLE_COHORT_SQL, SAMPLE_RESULTS_SQL, summarize_cohort, summarize_sample_results

def row(sample,kind,verdict,analyzed=True,malicious=False,suspicious=False):return {"sample_id":sample,"run_kind":kind,"verdict":verdict,"analyzed":analyzed,"malicious":malicious,"suspicious":suspicious}

def test_one_sample_produces_one_result_per_kind_and_equal_totals():
    rows=[row(1,k,"no_verdict",False) for k in RUN_KINDS]
    summary=summarize_sample_results(rows)
    assert [x["total"] for x in summary]==[1,1,1,1]
    assert all(x["verdicts"]["no_verdict"]==1 for x in summary)

def test_identical_and_disagreeing_verdicts_are_defined_in_view():
    migration=Path("migrations/006_remove_grouping.sql").read_text().lower()
    assert "count(distinct r.verdict)" in migration
    assert "then min(r.verdict)" in migration
    assert "else 'mixed'" in migration and "then 'missing'" in migration

def test_runtime_has_no_grouping_references():
    deleted=("sample_analysis_groups","source_submission_groups","logical_experiment_groups","logical_experiment_group_runs","analysis_group_completeness","unassigned_analysis_runs","static_repetition","group_id")
    runtime="\n".join(p.read_text(encoding="utf-8") for p in Path("app").rglob("*") if p.is_file() and p.suffix in {".py",".html"})
    for name in deleted:assert name not in runtime

def test_detection_query_uses_sample_and_requested_bucket():
    sql=SAMPLE_RESULTS_SQL.lower();assert "r.sample_id=selected.id" in sql and "duration_bucket=60" in sql
    assert "actual_duration" not in sql and "vti_observations" not in sql
    assert "bool_or(r.verdict='malicious')" in sql

def test_detection_counts_are_unique_and_mutually_exclusive():
    rows=[row(1,"Static","malicious"),row(2,"Static","suspicious"),row(3,"Static","benign")]
    static=summarize_sample_results(rows)[0]
    assert static["analyzed"]==3 and static["malicious"]==1 and static["suspicious"]==1
    assert static["detected"]==static["malicious"]+static["suspicious"]

def test_overview_verdict_priority_and_duration_isolation():
    sql=SAMPLE_RESULTS_SQL.lower()
    assert sql.index("has_malicious") < sql.index("has_suspicious") < sql.index("has_benign")
    assert "r.duration_bucket=60" in sql and "r.duration_bucket=120" in sql and "r.duration_bucket=180" in sql
    assert "mixed" not in sql and "'no_verdict'" in sql

def test_cohort_deduplicates_runs_and_uses_sample_first_seen():
    sql=SAMPLE_COHORT_SQL.lower()
    assert sql.count("exists(select 1 from analysis_runs") == 4
    assert "s.first_seen >= %s" in sql and "completed_at" not in sql
    assert "r.duration_bucket=60" in sql and "actual_duration" not in sql

def test_daily_coverage_never_exceeds_received_samples():
    rows=[{"sample_id":1,"first_seen":datetime(2026,7,13,tzinfo=timezone.utc),"has_static":True,"has_dynamic_60":True,"has_dynamic_120":False,"has_dynamic_180":False},
          {"sample_id":2,"first_seen":datetime(2026,7,13,tzinfo=timezone.utc),"has_static":True,"has_dynamic_60":False,"has_dynamic_120":False,"has_dynamic_180":True}]
    metrics,daily=summarize_cohort(rows)
    assert metrics=={"samples_received":2,"static_analyzed":2,"dynamic_60":1,"dynamic_120":0,"dynamic_180":1}
    assert all(row[key]<=row["samples_received"] for row in daily for key in ("static_analyzed","dynamic_60","dynamic_120","dynamic_180"))

def test_overview_has_no_analysis_level_kpi_and_uses_one_cohort():
    template=Path("app/templates/overview.html").read_text(encoding="utf-8")
    main=Path("app/main.py").read_text(encoding="utf-8")
    assert "Total analyses" not in template and "Static analyses" not in template and "Dynamic analyses" not in template
    assert "sample_ids={row[\"sample_id\"] for row in cohort}" in main
    assert "fetch_sample_results(cur,sample_ids)" in main

def test_migration_preserves_normalized_tables_and_collector_inserts_directly():
    migration=Path("migrations/006_remove_grouping.sql").read_text().lower()
    for table in ("samples","analysis_runs","verdict_observations","vti_observations"):
        assert f"drop table if exists {table}" not in migration
    collector=Path("app/collector.py").read_text(encoding="utf-8")
    assert "insert into analysis_runs(sample_id," in collector.lower()
    assert "group_id" not in collector
