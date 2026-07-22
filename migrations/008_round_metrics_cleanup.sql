DROP VIEW IF EXISTS sample_analysis_summary;
DROP TABLE IF EXISTS ioc_observations;
DROP TABLE IF EXISTS verdict_observations;

ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS submission_created timestamptz;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS submission_interface_name text;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS round_id integer;

UPDATE analysis_runs r SET submission_created=x.created
FROM (
  SELECT sample_id,vmray_submission_id,min(created_at) created
  FROM analysis_runs WHERE vmray_submission_id IS NOT NULL GROUP BY 1,2
) x WHERE r.sample_id=x.sample_id AND r.vmray_submission_id=x.vmray_submission_id;

UPDATE analysis_runs r SET submission_interface_name=x.interface_name
FROM (
  SELECT sample_id,vmray_submission_id,
    CASE max(duration_bucket) FILTER (WHERE analysis_type='dynamic')
      WHEN 60 THEN '1minute' WHEN 120 THEN '2minutes' WHEN 180 THEN '3minutes'
    END interface_name
  FROM analysis_runs WHERE vmray_submission_id IS NOT NULL GROUP BY 1,2
) x WHERE r.sample_id=x.sample_id AND r.vmray_submission_id=x.vmray_submission_id
  AND x.interface_name IS NOT NULL;

WITH RECURSIVE ordered AS (
  SELECT sample_id,vmray_submission_id,submission_interface_name,min(submission_created) submission_created,
    row_number() OVER (PARTITION BY sample_id ORDER BY min(submission_created),vmray_submission_id) rn
  FROM analysis_runs WHERE vmray_submission_id IS NOT NULL
  GROUP BY sample_id,vmray_submission_id,submission_interface_name
), walk AS (
  SELECT sample_id,vmray_submission_id,rn,1 round_id,
    ARRAY[coalesce(submission_interface_name,'submission:'||vmray_submission_id::text)]::text[] seen
  FROM ordered WHERE rn=1
  UNION ALL
  SELECT o.sample_id,o.vmray_submission_id,o.rn,
    CASE WHEN coalesce(o.submission_interface_name,'submission:'||o.vmray_submission_id::text)=ANY(w.seen) THEN w.round_id+1 ELSE w.round_id END,
    CASE WHEN coalesce(o.submission_interface_name,'submission:'||o.vmray_submission_id::text)=ANY(w.seen)
      THEN ARRAY[coalesce(o.submission_interface_name,'submission:'||o.vmray_submission_id::text)]::text[]
      ELSE w.seen||coalesce(o.submission_interface_name,'submission:'||o.vmray_submission_id::text) END
  FROM walk w JOIN ordered o ON o.sample_id=w.sample_id AND o.rn=w.rn+1
)
UPDATE analysis_runs r SET round_id=w.round_id FROM walk w
WHERE r.sample_id=w.sample_id AND r.vmray_submission_id=w.vmray_submission_id;

UPDATE analysis_runs SET round_id=1 WHERE round_id IS NULL;
ALTER TABLE analysis_runs ALTER COLUMN round_id SET NOT NULL;
ALTER TABLE analysis_runs ALTER COLUMN round_id SET DEFAULT 1;

ALTER TABLE analysis_runs DROP CONSTRAINT IF EXISTS analysis_runs_vmray_analysis_id_is_demo_key;
ALTER TABLE samples DROP CONSTRAINT IF EXISTS samples_sha256_is_demo_key;
DROP INDEX IF EXISTS runs_dimensions_idx;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS is_demo;
ALTER TABLE samples DROP COLUMN IF EXISTS is_demo;
ALTER TABLE analysis_runs ADD CONSTRAINT analysis_runs_vmray_analysis_id_key UNIQUE(vmray_analysis_id);
ALTER TABLE samples ADD CONSTRAINT samples_sha256_key UNIQUE(sha256);

CREATE INDEX IF NOT EXISTS runs_created_arm_idx ON analysis_runs(created_at,sample_id,round_id,analysis_type,duration_bucket);
CREATE INDEX IF NOT EXISTS runs_submission_idx ON analysis_runs(sample_id,submission_created,vmray_submission_id);
