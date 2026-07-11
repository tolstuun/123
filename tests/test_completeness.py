from datetime import date
from app.analytics import classify_group, zero_fill_daily


def six_slots():
    return [
        {"analysis_type": "static", "static_repetition": 1, "duration_bucket": None},
        {"analysis_type": "static", "static_repetition": 2, "duration_bucket": None},
        {"analysis_type": "static", "static_repetition": 3, "duration_bucket": None},
        {"analysis_type": "dynamic", "static_repetition": None, "duration_bucket": 60},
        {"analysis_type": "dynamic", "static_repetition": None, "duration_bucket": 120},
        {"analysis_type": "dynamic", "static_repetition": None, "duration_bucket": 180},
    ]


def test_exact_six_slots_are_clean_complete():
    result = classify_group(six_slots())
    assert result["completeness_status"] == "complete_clean"
    assert result["expected_slots_present"] == 6


def test_five_slots_report_the_exact_missing_slot():
    result = classify_group(six_slots()[:-1])
    assert result["completeness_status"] == "incomplete"
    assert result["missing_slots"] == ["dynamic_180"]


def test_six_rows_with_duplicate_and_missing_are_not_complete():
    runs = six_slots()[:-1] + [six_slots()[0]]
    result = classify_group(runs)
    assert result["completeness_status"] == "duplicate_slots"
    assert result["missing_slots"] == ["dynamic_180"]
    assert result["duplicate_slots"] == ["static_1"]


def test_all_slots_plus_duplicate_are_not_clean_complete():
    result = classify_group(six_slots() + [six_slots()[3]])
    assert result["completeness_status"] == "duplicate_slots"
    assert result["expected_slots_present"] == 6


def test_unmapped_dynamic_duration_is_counted():
    result = classify_group([{"analysis_type": "dynamic", "duration_bucket": 90, "static_repetition": None}])
    assert result["unmapped_run_count"] == 1
    assert result["completeness_status"] == "unmapped_runs"


def test_multiple_groups_for_one_hash_stay_independent():
    groups = {101: six_slots(), 102: six_slots()[:2]}
    summaries = {group_id: classify_group(runs) for group_id, runs in groups.items()}
    assert summaries[101]["completeness_status"] == "complete_clean"
    assert summaries[102]["expected_slots_present"] == 2


def test_daily_series_zero_fills_dates_and_separates_run_types():
    rows = [{"day": date(2026, 7, 9), "static": 3, "dynamic_60": 1, "dynamic_120": 2, "dynamic_180": 4, "other": 1},
            {"day": date(2026, 7, 11), "static": 2, "dynamic_60": 5, "dynamic_120": 0, "dynamic_180": 1, "other": 0}]
    keys = ("static", "dynamic_60", "dynamic_120", "dynamic_180", "other")
    result = zero_fill_daily(date(2026, 7, 9), date(2026, 7, 11), rows, keys)
    assert result[1] == {"day": date(2026, 7, 10), **{key: 0 for key in keys}}
    assert result[0]["static"] == 3 and result[0]["dynamic_60"] == 1
    assert result[0]["dynamic_120"] == 2 and result[0]["dynamic_180"] == 4
