ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS vti_static_detector_high integer NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS runs_round_created_idx ON analysis_runs(sample_id,round_id,created_at);

WITH counts AS (
 SELECT r.id,count(o.id) FILTER (
   WHERE o.score>=3 AND d.category IN ('Computer Vision','Heuristics','Machine Learning','Masquerade')
 )::int AS static_detector
 FROM analysis_runs r
 LEFT JOIN vti_observations o ON o.analysis_run_id=r.id
 LEFT JOIN vti_definitions d ON d.id=o.vti_definition_id
 GROUP BY r.id
)
UPDATE analysis_runs r SET vti_static_detector_high=c.static_detector FROM counts c WHERE c.id=r.id;

UPDATE analysis_runs r SET vti_behavioural_high=c.behavioural
FROM (
 SELECT r2.id,count(o.id) FILTER (
   WHERE o.score>=3 AND d.category IN ('Anti Analysis','Browser','Crash','Data Collection','Defense Evasion','Discovery','Execution','Extracted Configuration','Hide Tracks','Injection','Input Capture','Mutex','Network Connection','Obfuscation','Persistence','Privilege Escalation','System Modification','Task Scheduling')
 )::int AS behavioural
 FROM analysis_runs r2
 LEFT JOIN vti_observations o ON o.analysis_run_id=r2.id
 LEFT JOIN vti_definitions d ON d.id=o.vti_definition_id
 GROUP BY r2.id
) c WHERE c.id=r.id;
