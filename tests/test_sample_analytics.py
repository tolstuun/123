from pathlib import Path
from app.analytics import RUN_KINDS, SAMPLE_RESULTS_SQL, summarize_sample_results

def row(sample,kind,verdict,support="none"):return {"sample_id":sample,"run_kind":kind,"verdict":verdict,"support":support}

def test_one_sample_produces_one_result_per_kind_and_equal_totals():
    rows=[row(1,k,"missing","missing") for k in RUN_KINDS]
    summary=summarize_sample_results(rows)
    assert [x["total"] for x in summary]==[1,1,1,1]
    assert all(x["verdicts"]["missing"]==1 for x in summary)

def test_identical_and_disagreeing_verdicts_are_defined_in_view():
    migration=Path("migrations/006_remove_grouping.sql").read_text().lower()
    assert "count(distinct r.verdict)" in migration
    assert "then min(r.verdict)" in migration
    assert "else 'mixed'" in migration and "then 'missing'" in migration

def test_runtime_has_no_grouping_references():
    deleted=("sample_analysis_groups","source_submission_groups","logical_experiment_groups","logical_experiment_group_runs","analysis_group_completeness","unassigned_analysis_runs","static_repetition","group_id")
    runtime="\n".join(p.read_text(encoding="utf-8") for p in Path("app").rglob("*") if p.is_file() and p.suffix in {".py",".html"})
    for name in deleted:assert name not in runtime

def test_support_query_uses_sample_and_requested_bucket():
    sql=SAMPLE_RESULTS_SQL.lower();assert "r.sample_id=selected.id" in sql and "duration_bucket=60" in sql
    assert "actual_duration" not in sql and "o.score between 3 and 5" in sql

def test_migration_preserves_normalized_tables_and_collector_inserts_directly():
    migration=Path("migrations/006_remove_grouping.sql").read_text().lower()
    for table in ("samples","analysis_runs","verdict_observations","vti_observations"):
        assert f"drop table if exists {table}" not in migration
    collector=Path("app/collector.py").read_text(encoding="utf-8")
    assert "insert into analysis_runs(sample_id," in collector.lower()
    assert "group_id" not in collector
