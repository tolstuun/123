from datetime import datetime, timezone
from pathlib import Path

from app.metrics import DETECTION_SQL, RESULTS_CTE, Window
from app.rounds import calculate_rounds


def row(submission, interface, minute):
    return {"vmray_submission_id":submission,"submission_interface_name":interface,
            "submission_created":datetime(2026,1,1,0,minute,tzinfo=timezone.utc)}


def test_repeated_interface_starts_new_round():
    assignments=calculate_rounds([row(1,"1minute",0),row(2,"2minutes",1),row(3,"3minutes",2),row(4,"1minute",3)])
    assert assignments=={1:1,2:1,3:1,4:2}


def test_round_assignment_is_deterministic_and_allows_missing_arms():
    rows=[row(4,"2minutes",3),row(2,"1minute",1),row(3,"1minute",2)]
    assert calculate_rounds(rows)==calculate_rounds(list(reversed(rows)))=={2:1,3:2,4:2}


def test_metrics_anchor_rounds_then_join_all_runs():
    for sql in (DETECTION_SQL,RESULTS_CTE):
        lowered=sql.lower()
        assert "min(r.created_at) first_run" in lowered
        assert "first_run >= %s" in lowered and "first_run < %s" in lowered
        assert lowered.count("created_at >= %s")==0
        assert "not has_failed and has_60 and has_120 and has_180" in lowered
    assert "cross join arms" in DETECTION_SQL.lower()


def test_cleanup_has_no_runtime_dead_feature_references():
    runtime="\n".join(p.read_text(encoding="utf-8") for p in Path("app").rglob("*.py"))
    for deleted in ("ioc_observations","verdict_observations","sample_analysis_summary","normalize_ioc","mode_sql","is_demo"):
        assert deleted not in runtime
