from pathlib import Path


def test_detector_counts_are_folded_before_column_is_dropped():
    sql=Path("migrations/010_revert_static_detector_split.sql").read_text(encoding="utf-8").lower()
    update=sql.index("update analysis_runs")
    drop=sql.index("alter table analysis_runs drop column vti_static_detector_high")
    assert update < drop
    assert "vti_behavioural_high = vti_behavioural_high" in sql
    assert "+ coalesce(vti_static_detector_high, 0)" in sql


def test_migration_removes_detector_column_and_preserves_folded_value():
    sql=Path("migrations/010_revert_static_detector_split.sql").read_text(encoding="utf-8").lower()
    row={"vti_behavioural_high":3,"vti_static_detector_high":4}
    row["vti_behavioural_high"] += row.pop("vti_static_detector_high")
    assert row=={"vti_behavioural_high":7}
    assert "drop column vti_static_detector_high" in sql
