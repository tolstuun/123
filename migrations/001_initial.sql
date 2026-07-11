CREATE TABLE schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE schema_parser_versions (version text PRIMARY KEY, description text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO schema_parser_versions(version, description) VALUES ('1.0.0', 'Initial verified VMRay parser');

CREATE TABLE samples (
 id bigserial PRIMARY KEY, vmray_sample_id bigint, sha256 char(64) NOT NULL, sha1 char(40), md5 char(32), filename text,
 mime_type text, file_type text, first_seen timestamptz NOT NULL, latest_seen timestamptz NOT NULL, is_demo boolean NOT NULL DEFAULT false,
 UNIQUE(sha256, is_demo)
);
CREATE INDEX samples_hashes_idx ON samples(sha1, md5); CREATE INDEX samples_filename_idx ON samples(lower(filename));

CREATE TABLE sample_analysis_groups (
 id bigserial PRIMARY KEY, sample_id bigint NOT NULL REFERENCES samples(id), grouping_key text NOT NULL,
 vmray_submission_id bigint, grouping_confidence text NOT NULL CHECK(grouping_confidence IN ('high','medium','ambiguous')),
 grouping_warning text, created_at timestamptz NOT NULL, is_demo boolean NOT NULL DEFAULT false, UNIQUE(grouping_key, is_demo)
);
CREATE INDEX groups_sample_idx ON sample_analysis_groups(sample_id);

CREATE TABLE ingestion_batches (id bigserial PRIMARY KEY, started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, status text NOT NULL, discovered int NOT NULL DEFAULT 0, ingested int NOT NULL DEFAULT 0, failed int NOT NULL DEFAULT 0);
CREATE TABLE raw_api_payloads (
 id bigserial PRIMARY KEY, source_kind text NOT NULL, source_identifier text NOT NULL, content_type text NOT NULL,
 content_encoding text NOT NULL DEFAULT 'gzip', payload bytea NOT NULL, sha256 char(64) NOT NULL, collected_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source_kind, source_identifier, sha256)
);

CREATE TABLE analysis_runs (
 id bigserial PRIMARY KEY, group_id bigint NOT NULL REFERENCES sample_analysis_groups(id), sample_id bigint NOT NULL REFERENCES samples(id),
 vmray_analysis_id bigint NOT NULL, vmray_sample_id bigint, vmray_submission_id bigint, vmray_job_id bigint,
 analysis_type text NOT NULL CHECK(analysis_type IN ('static','dynamic','unknown')), static_repetition smallint,
 requested_duration_seconds int, actual_duration_seconds int, duration_bucket smallint,
 created_at timestamptz, started_at timestamptz, completed_at timestamptz, ingested_at timestamptz NOT NULL DEFAULT now(),
 vmray_version text, analysis_configuration jsonb, target_environment text, status text, failure_state text,
 verdict text NOT NULL, original_verdict text, verdict_score numeric, verdict_reason text, support_classification text NOT NULL DEFAULT 'none',
 grouping_confidence text NOT NULL, is_demo boolean NOT NULL DEFAULT false, raw_payload_id bigint REFERENCES raw_api_payloads(id), parser_version text NOT NULL REFERENCES schema_parser_versions(version),
 UNIQUE(vmray_analysis_id, is_demo)
);
CREATE INDEX runs_group_idx ON analysis_runs(group_id); CREATE INDEX runs_completed_idx ON analysis_runs(completed_at); CREATE INDEX runs_dimensions_idx ON analysis_runs(is_demo, analysis_type, duration_bucket, verdict);

CREATE TABLE verdict_observations (id bigserial PRIMARY KEY, analysis_run_id bigint NOT NULL UNIQUE REFERENCES analysis_runs(id) ON DELETE CASCADE, normalized_verdict text NOT NULL, original_value text, score numeric, reason_code text, reason_description text, observed_at timestamptz NOT NULL);
CREATE TABLE vti_definitions (id bigserial PRIMARY KEY, stable_id text NOT NULL UNIQUE, category text, operation text, description text, classifications jsonb NOT NULL DEFAULT '[]');
CREATE TABLE vti_observations (
 id bigserial PRIMARY KEY, analysis_run_id bigint NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE, vti_definition_id bigint NOT NULL REFERENCES vti_definitions(id),
 score numeric, scope text NOT NULL DEFAULT 'analysis', artifact_id text NOT NULL DEFAULT '', artifact_type text, artifact_name text, observed_at timestamptz NOT NULL,
 UNIQUE(analysis_run_id, vti_definition_id, scope, artifact_id)
);
CREATE INDEX vti_obs_run_idx ON vti_observations(analysis_run_id); CREATE INDEX vti_obs_score_idx ON vti_observations(score);
CREATE TABLE ioc_observations (
 id bigserial PRIMARY KEY, analysis_run_id bigint NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE, ioc_type text NOT NULL,
 original_value text NOT NULL, normalized_value text NOT NULL, verdict text, source text, extraction_context text, associated_artifact text,
 actionable boolean NOT NULL DEFAULT false, observed_at timestamptz NOT NULL, first_seen_at timestamptz,
 UNIQUE(analysis_run_id, ioc_type, normalized_value, associated_artifact)
);
CREATE INDEX ioc_search_idx ON ioc_observations(normalized_value); CREATE INDEX ioc_run_idx ON ioc_observations(analysis_run_id);

CREATE TABLE collection_checkpoints (name text PRIMARY KEY, completed_at timestamptz, stable_id bigint, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE collection_errors (id bigserial PRIMARY KEY, batch_id bigint REFERENCES ingestion_batches(id), analysis_id bigint, occurred_at timestamptz NOT NULL DEFAULT now(), error_type text NOT NULL, message text NOT NULL, permanent boolean NOT NULL DEFAULT false, retry_count int NOT NULL DEFAULT 0);
CREATE INDEX collection_errors_time_idx ON collection_errors(occurred_at DESC);
CREATE TABLE collector_status (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), state text NOT NULL, last_attempt_at timestamptz, last_success_at timestamptz, connectivity_ok boolean, lag_seconds int, error_count int NOT NULL DEFAULT 0, message text);
INSERT INTO collector_status(singleton,state) VALUES(true,'starting');
