DROP VIEW IF EXISTS unassigned_analysis_runs;
ALTER TABLE analysis_runs DROP CONSTRAINT IF EXISTS analysis_runs_raw_payload_id_fkey;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS raw_payload_id;
DROP TABLE IF EXISTS raw_api_payloads;
CREATE VIEW unassigned_analysis_runs AS
SELECT r.*
FROM analysis_runs r
LEFT JOIN logical_experiment_group_runs l ON l.analysis_run_id = r.id
WHERE l.analysis_run_id IS NULL;
