CREATE OR REPLACE VIEW analysis_group_completeness AS
WITH slot_counts AS (
    SELECT
        g.id AS group_id,
        g.sample_id,
        count(r.id) AS analysis_count,
        count(*) FILTER (WHERE r.analysis_type = 'static' AND r.static_repetition = 1) AS static_1_count,
        count(*) FILTER (WHERE r.analysis_type = 'static' AND r.static_repetition = 2) AS static_2_count,
        count(*) FILTER (WHERE r.analysis_type = 'static' AND r.static_repetition = 3) AS static_3_count,
        count(*) FILTER (WHERE r.analysis_type = 'dynamic' AND r.duration_bucket = 60) AS dynamic_60_count,
        count(*) FILTER (WHERE r.analysis_type = 'dynamic' AND r.duration_bucket = 120) AS dynamic_120_count,
        count(*) FILTER (WHERE r.analysis_type = 'dynamic' AND r.duration_bucket = 180) AS dynamic_180_count,
        count(*) FILTER (
            WHERE r.id IS NOT NULL AND NOT (
                (r.analysis_type = 'static' AND r.static_repetition IN (1, 2, 3))
                OR (r.analysis_type = 'dynamic' AND r.duration_bucket IN (60, 120, 180))
            )
        ) AS unmapped_run_count,
        min(r.completed_at) AS first_analysis_at,
        max(r.completed_at) AS last_analysis_at
    FROM sample_analysis_groups g
    LEFT JOIN analysis_runs r ON r.group_id = g.id
    GROUP BY g.id, g.sample_id
), derived AS (
    SELECT *,
        (static_1_count > 0)::int + (static_2_count > 0)::int + (static_3_count > 0)::int
        + (dynamic_60_count > 0)::int + (dynamic_120_count > 0)::int + (dynamic_180_count > 0)::int
            AS expected_slots_present,
        (static_1_count > 1)::int + (static_2_count > 1)::int + (static_3_count > 1)::int
        + (dynamic_60_count > 1)::int + (dynamic_120_count > 1)::int + (dynamic_180_count > 1)::int
            AS duplicate_slot_count,
        array_remove(ARRAY[
            CASE WHEN static_1_count = 0 THEN 'static_1' END,
            CASE WHEN static_2_count = 0 THEN 'static_2' END,
            CASE WHEN static_3_count = 0 THEN 'static_3' END,
            CASE WHEN dynamic_60_count = 0 THEN 'dynamic_60' END,
            CASE WHEN dynamic_120_count = 0 THEN 'dynamic_120' END,
            CASE WHEN dynamic_180_count = 0 THEN 'dynamic_180' END
        ], NULL) AS missing_slots,
        array_remove(ARRAY[
            CASE WHEN static_1_count > 1 THEN 'static_1' END,
            CASE WHEN static_2_count > 1 THEN 'static_2' END,
            CASE WHEN static_3_count > 1 THEN 'static_3' END,
            CASE WHEN dynamic_60_count > 1 THEN 'dynamic_60' END,
            CASE WHEN dynamic_120_count > 1 THEN 'dynamic_120' END,
            CASE WHEN dynamic_180_count > 1 THEN 'dynamic_180' END
        ], NULL) AS duplicate_slots
    FROM slot_counts
)
SELECT *,
    6 - expected_slots_present AS missing_slot_count,
    CASE
        WHEN expected_slots_present = 6 AND duplicate_slot_count = 0 AND unmapped_run_count = 0 THEN 'complete_clean'
        WHEN duplicate_slot_count > 0 THEN 'duplicate_slots'
        WHEN unmapped_run_count > 0 THEN 'unmapped_runs'
        ELSE 'incomplete'
    END AS completeness_status,
    static_1_count > 0 AS has_static_1,
    static_2_count > 0 AS has_static_2,
    static_3_count > 0 AS has_static_3,
    dynamic_60_count > 0 AS has_dynamic_60,
    dynamic_120_count > 0 AS has_dynamic_120,
    dynamic_180_count > 0 AS has_dynamic_180
FROM derived;

CREATE INDEX IF NOT EXISTS analysis_runs_group_slot_idx
    ON analysis_runs(group_id, analysis_type, static_repetition, duration_bucket);
