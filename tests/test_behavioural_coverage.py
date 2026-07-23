import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from app.metrics import BEHAVIOURAL_COVERAGE_CTES, COHORT_CTE


@pytest.fixture
def coverage_rows():
    database_url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("PostgreSQL is required for the behavioural coverage fixture")

    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE samples(id bigint PRIMARY KEY,file_type text)")
            cur.execute("""CREATE TEMP TABLE analysis_runs(
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                sample_id bigint NOT NULL,round_id integer NOT NULL,
                vmray_submission_id bigint,duration_bucket integer,
                submission_created timestamptz,created_at timestamptz NOT NULL,
                analysis_type text NOT NULL,is_failed boolean NOT NULL DEFAULT false,
                vti_behavioural_high integer NOT NULL DEFAULT 0
            )""")
            cur.executemany("INSERT INTO samples(id,file_type) VALUES(%s,'file')", [(i,) for i in range(1, 7)])

            rows = []
            for sample_id in range(1, 7):
                rows.append((sample_id, sample_id, 1000 + sample_id, None, start, start, "static", False, 0))
                values = {
                    1: (1, 1),  # behavioural at both
                    2: (0, 1),  # exclusive at longer
                    3: (1, 0),  # crossout
                    4: (0, 0),  # neither
                    5: (1, 1),  # incomplete: no 120
                    6: (1, 1),  # complete but failed
                }[sample_id]
                durations = (60, 180) if sample_id == 5 else (60, 120, 180)
                for index, duration in enumerate(durations):
                    behavioural = values[0] if duration == 60 else values[1] if duration == 120 else 0
                    submission_id = None if sample_id == 4 and duration == 60 else sample_id * 10 + index
                    rows.append((
                        sample_id, sample_id, submission_id, duration,
                        start + timedelta(minutes=index), start + timedelta(minutes=index),
                        "dynamic", sample_id == 6 and duration == 180, behavioural,
                    ))
            cur.executemany("""INSERT INTO analysis_runs(
                sample_id,round_id,vmray_submission_id,duration_bucket,submission_created,
                created_at,analysis_type,is_failed,vti_behavioural_high
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""", rows)
            cur.execute(
                COHORT_CTE + ", " + BEHAVIOURAL_COVERAGE_CTES,
                (start - timedelta(days=1), start + timedelta(days=1), "file"),
            )
            result = cur.fetchall()
        conn.rollback()
    return result


def test_behavioural_crossings_are_counted_without_netting(coverage_rows):
    overall = next(
        row for row in coverage_rows
        if row["base"] == 60 and row["longer"] == 120 and row["order_side"] == "all"
    )
    assert overall["rounds"] == 4
    assert overall["behav_base"] == 2
    assert overall["behav_longer"] == 2
    assert overall["exclusive"] == 1
    assert overall["crossout"] == 1
    assert overall["pct_coverage_gain"] == Decimal("50.0")
    assert overall["pct_uplift_over_base"] == Decimal("50.0")


def test_order_splits_include_unknown_and_sum_to_overall(coverage_rows):
    for base, longer in ((60, 120), (120, 180), (60, 180)):
        pair = [row for row in coverage_rows if row["base"] == base and row["longer"] == longer]
        overall = next(row for row in pair if row["order_side"] == "all")
        splits = [row for row in pair if row["order_side"] != "all"]
        assert {row["order_side"] for row in splits} == {"base_first", "longer_first", "unknown"}
        for field in ("rounds", "behav_base", "behav_longer", "exclusive", "crossout"):
            assert sum(row[field] for row in splits) == overall[field]
    unknown = next(
        row for row in coverage_rows
        if row["base"] == 60 and row["longer"] == 120 and row["order_side"] == "unknown"
    )
    assert unknown["rounds"] == 1


def test_empty_percentage_denominators_are_null(coverage_rows):
    overall = next(
        row for row in coverage_rows
        if row["base"] == 120 and row["longer"] == 180 and row["order_side"] == "all"
    )
    assert overall["behav_longer"] == 0
    assert overall["pct_coverage_gain"] is None


def test_dashboard_replaces_lift_panel_but_keeps_transition_export():
    template = Path("app/templates/cohort_section.html").read_text(encoding="utf-8")
    main = Path("app/main.py").read_text(encoding="utf-8")
    assert "<h2>Behavioural coverage</h2>" in template
    assert "<h2>Duration lift</h2>" not in template
    assert "<th>Comparison</th>" in template
    assert "<th>Missed at the shorter time</th>" in template
    assert "<th>Samples</th>" in template
    assert "<th>Order check</th>" not in template
    assert "row.splits" not in template
    assert "crossout" not in template.lower()
    assert "pct_uplift_over_base" not in template
    assert "/exports/behavioural-coverage.csv" in template
    assert 'kind=="behavioural-coverage"' in main
    assert 'kind=="duration-lift"' in main
    assert "duration_lift(window,cohort)" in main


def test_submission_order_caveat_is_in_health_strip():
    overview = Path("app/templates/overview.html").read_text(encoding="utf-8")
    main = Path("app/main.py").read_text(encoding="utf-8")
    assert "<small>Submission order fixed</small>" in overview
    assert "health.submission_order_fixed_pct > 90" in overview
    assert "submission_order_fixed_pct(window)" in main
