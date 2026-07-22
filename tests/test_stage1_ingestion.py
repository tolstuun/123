from pathlib import Path


COLLECTOR = Path("app/collector.py").read_text(encoding="utf-8")
MIGRATION = Path("migrations/007_stage1_fields.sql").read_text(encoding="utf-8")


def test_sample_upsert_lowers_first_seen():
    assert "first_seen=LEAST(samples.first_seen,EXCLUDED.first_seen)" in COLLECTOR


def test_analysis_conflict_refreshes_mutable_result_fields():
    conflict = COLLECTOR.split("ON CONFLICT(vmray_analysis_id) DO UPDATE SET",1)[1]
    for assignment in ("verdict=EXCLUDED.verdict","status=EXCLUDED.status","failure_state=EXCLUDED.failure_state","completed_at=EXCLUDED.completed_at"):
        assert assignment in conflict


def test_obsolete_columns_are_dropped_and_new_counts_added():
    assert "DROP COLUMN IF EXISTS actual_duration_seconds" in MIGRATION
    assert "DROP COLUMN IF EXISTS support_classification" in MIGRATION
    for column in ("is_failed","vti_behavioural_high","vti_nonbehavioural_high","vti_config_extraction_high","vti_unknown_category_high","vti_total"):
        assert column in MIGRATION and column in COLLECTOR
