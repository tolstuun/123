from pathlib import Path

from app import metrics


def test_behavioural_coverage_query_uses_complete_rounds_and_pure_crossings():
    sql = metrics.COHORT_CTE + metrics.BEHAVIOURAL_COVERAGE_CTES
    assert "FROM eligible c" in sql
    assert "base_value=0 AND longer_value>0" in sql
    assert "base_value>0 AND longer_value=0" in sql
    assert "exclusive-crossout" not in sql
    assert "nullif(behav_longer,0)" in sql
    assert "nullif(behav_base,0)" in sql


def test_submission_order_split_is_dynamic_and_keeps_zero_sized_side():
    sql = metrics.BEHAVIOURAL_COVERAGE_CTES
    assert "row_number() OVER" in sql
    assert "submission_created NULLS LAST" in sql
    assert "CROSS JOIN sides" in sql
    assert "s.rounds < o.rounds * 0.10" in sql
    assert "'base_first'" in sql
    assert "'longer_first'" in sql


def test_dashboard_replaces_lift_panel_but_keeps_transition_export():
    template = Path("app/templates/cohort_section.html").read_text(encoding="utf-8")
    main = Path("app/main.py").read_text(encoding="utf-8")
    assert "<h2>Behavioural coverage</h2>" in template
    assert "<h2>Duration lift</h2>" not in template
    assert "crossout" in template
    assert "underpowered" in template
    assert 'kind=="duration-lift"' in main
    assert "duration_lift(window,cohort)" in main

