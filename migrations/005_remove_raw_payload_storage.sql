ALTER TABLE analysis_runs DROP CONSTRAINT IF EXISTS analysis_runs_raw_payload_id_fkey;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS raw_payload_id;
DROP TABLE IF EXISTS raw_api_payloads;
