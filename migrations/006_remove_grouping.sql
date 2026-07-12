DROP VIEW IF EXISTS unassigned_analysis_runs;
DROP VIEW IF EXISTS analysis_group_completeness;
DROP TABLE IF EXISTS logical_experiment_group_runs;
DROP TABLE IF EXISTS logical_experiment_groups;
DROP TABLE IF EXISTS source_submission_group_runs;
DROP TABLE IF EXISTS source_submission_groups;
ALTER TABLE analysis_runs DROP CONSTRAINT IF EXISTS analysis_runs_group_id_fkey;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS group_id;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS static_repetition;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS grouping_confidence;
DROP TABLE IF EXISTS sample_analysis_groups;
ALTER TABLE ingestion_batches DROP COLUMN IF EXISTS regrouped_samples;
ALTER TABLE collector_status DROP COLUMN IF EXISTS last_regrouped_samples;

CREATE VIEW sample_analysis_summary AS
SELECT s.id AS sample_id,
 count(r.id) FILTER (WHERE r.analysis_type='static')::int AS static_count,
 count(r.id) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=60)::int AS dynamic_60_count,
 count(r.id) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=120)::int AS dynamic_120_count,
 count(r.id) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=180)::int AS dynamic_180_count,
 CASE WHEN count(r.id) FILTER (WHERE r.analysis_type='static')=0 THEN 'missing' WHEN count(DISTINCT r.verdict) FILTER (WHERE r.analysis_type='static')=1 THEN min(r.verdict) FILTER (WHERE r.analysis_type='static') ELSE 'mixed' END AS static_verdict,
 CASE WHEN count(r.id) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=60)=0 THEN 'missing' WHEN count(DISTINCT r.verdict) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=60)=1 THEN min(r.verdict) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=60) ELSE 'mixed' END AS dynamic_60_verdict,
 CASE WHEN count(r.id) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=120)=0 THEN 'missing' WHEN count(DISTINCT r.verdict) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=120)=1 THEN min(r.verdict) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=120) ELSE 'mixed' END AS dynamic_120_verdict,
 CASE WHEN count(r.id) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=180)=0 THEN 'missing' WHEN count(DISTINCT r.verdict) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=180)=1 THEN min(r.verdict) FILTER (WHERE r.analysis_type='dynamic' AND r.duration_bucket=180) ELSE 'mixed' END AS dynamic_180_verdict
FROM samples s LEFT JOIN analysis_runs r ON r.sample_id=s.id GROUP BY s.id;
