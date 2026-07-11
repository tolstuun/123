DROP VIEW IF EXISTS analysis_group_completeness;

CREATE TABLE source_submission_groups (
    id bigserial PRIMARY KEY,
    sample_id bigint NOT NULL REFERENCES samples(id),
    vmray_submission_id bigint,
    source_key text NOT NULL UNIQUE,
    first_analysis_at timestamptz,
    last_analysis_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX source_submission_groups_sample_idx ON source_submission_groups(sample_id);

CREATE TABLE source_submission_group_runs (
    source_submission_group_id bigint NOT NULL REFERENCES source_submission_groups(id) ON DELETE CASCADE,
    analysis_run_id bigint NOT NULL UNIQUE REFERENCES analysis_runs(id) ON DELETE CASCADE,
    PRIMARY KEY(source_submission_group_id, analysis_run_id)
);

CREATE TABLE logical_experiment_groups (
    id bigserial PRIMARY KEY,
    sample_id bigint NOT NULL REFERENCES samples(id),
    group_key text NOT NULL UNIQUE,
    grouping_method text NOT NULL,
    grouping_confidence text NOT NULL,
    grouping_version text NOT NULL,
    grouping_explanation text NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    ambiguity_flag boolean NOT NULL DEFAULT false,
    finalized_at timestamptz,
    first_analysis_at timestamptz,
    last_analysis_at timestamptz,
    is_demo boolean NOT NULL DEFAULT false
);
CREATE INDEX logical_experiment_groups_sample_idx ON logical_experiment_groups(sample_id);
CREATE INDEX logical_experiment_groups_time_idx ON logical_experiment_groups(last_analysis_at DESC);

CREATE TABLE logical_experiment_group_runs (
    logical_experiment_group_id bigint NOT NULL REFERENCES logical_experiment_groups(id) ON DELETE CASCADE,
    analysis_run_id bigint NOT NULL UNIQUE REFERENCES analysis_runs(id) ON DELETE CASCADE,
    expected_slot text NOT NULL CHECK(expected_slot IN ('static_1','static_2','static_3','dynamic_60','dynamic_120','dynamic_180')),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(logical_experiment_group_id, analysis_run_id),
    UNIQUE(logical_experiment_group_id, expected_slot)
);
CREATE INDEX logical_group_runs_group_slot_idx ON logical_experiment_group_runs(logical_experiment_group_id, expected_slot);

CREATE OR REPLACE VIEW analysis_group_completeness AS
WITH slot_counts AS (
    SELECT
        g.id AS group_id,
        g.sample_id,
        count(l.analysis_run_id) AS analysis_count,
        count(*) FILTER (WHERE l.expected_slot='static_1') AS static_1_count,
        count(*) FILTER (WHERE l.expected_slot='static_2') AS static_2_count,
        count(*) FILTER (WHERE l.expected_slot='static_3') AS static_3_count,
        count(*) FILTER (WHERE l.expected_slot='dynamic_60') AS dynamic_60_count,
        count(*) FILTER (WHERE l.expected_slot='dynamic_120') AS dynamic_120_count,
        count(*) FILTER (WHERE l.expected_slot='dynamic_180') AS dynamic_180_count,
        count(DISTINCT r.vmray_submission_id) FILTER (WHERE r.vmray_submission_id IS NOT NULL) AS source_submission_count,
        g.first_analysis_at,
        g.last_analysis_at,
        g.ambiguity_flag,
        g.grouping_method,
        g.grouping_confidence,
        g.grouping_version,
        g.grouping_explanation
    FROM logical_experiment_groups g
    LEFT JOIN logical_experiment_group_runs l ON l.logical_experiment_group_id=g.id
    LEFT JOIN analysis_runs r ON r.id=l.analysis_run_id
    GROUP BY g.id
)
SELECT *,
    (static_1_count>0)::int+(static_2_count>0)::int+(static_3_count>0)::int
      +(dynamic_60_count>0)::int+(dynamic_120_count>0)::int+(dynamic_180_count>0)::int AS expected_slots_present,
    6-((static_1_count>0)::int+(static_2_count>0)::int+(static_3_count>0)::int
      +(dynamic_60_count>0)::int+(dynamic_120_count>0)::int+(dynamic_180_count>0)::int) AS missing_slot_count,
    array_remove(ARRAY[
      CASE WHEN static_1_count=0 THEN 'static_1' END,CASE WHEN static_2_count=0 THEN 'static_2' END,
      CASE WHEN static_3_count=0 THEN 'static_3' END,CASE WHEN dynamic_60_count=0 THEN 'dynamic_60' END,
      CASE WHEN dynamic_120_count=0 THEN 'dynamic_120' END,CASE WHEN dynamic_180_count=0 THEN 'dynamic_180' END],NULL) AS missing_slots,
    0::bigint AS duplicate_slot_count,
    ARRAY[]::text[] AS duplicate_slots,
    0::bigint AS unmapped_run_count,
    CASE WHEN static_1_count=1 AND static_2_count=1 AND static_3_count=1 AND dynamic_60_count=1 AND dynamic_120_count=1 AND dynamic_180_count=1 AND NOT ambiguity_flag THEN 'complete_clean' WHEN ambiguity_flag THEN 'ambiguous' ELSE 'incomplete' END AS completeness_status,
    static_1_count>0 AS has_static_1,static_2_count>0 AS has_static_2,static_3_count>0 AS has_static_3,
    dynamic_60_count>0 AS has_dynamic_60,dynamic_120_count>0 AS has_dynamic_120,dynamic_180_count>0 AS has_dynamic_180,
    extract(epoch FROM (last_analysis_at-first_analysis_at))::int AS experiment_span_seconds
FROM slot_counts;

CREATE OR REPLACE VIEW unassigned_analysis_runs AS
SELECT r.* FROM analysis_runs r LEFT JOIN logical_experiment_group_runs l ON l.analysis_run_id=r.id WHERE l.analysis_run_id IS NULL;
