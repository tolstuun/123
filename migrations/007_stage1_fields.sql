ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS is_failed boolean NOT NULL DEFAULT false;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS vti_behavioural_high integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS vti_nonbehavioural_high integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS vti_config_extraction_high integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS vti_unknown_category_high integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS vti_total integer NOT NULL DEFAULT 0;

UPDATE analysis_runs SET is_failed = (verdict = 'failed');
WITH counts AS (
 SELECT r.id,
  count(o.id)::int AS total,
  count(o.id) FILTER (WHERE o.score>=3 AND d.category IN ('Antivirus','Reputation','YARA'))::int AS nonbehavioural,
  count(o.id) FILTER (WHERE o.score>=3 AND d.category IN ('Anti Analysis','Browser','Computer Vision','Crash','Data Collection','Defense Evasion','Discovery','Execution','Extracted Configuration','Heuristics','Hide Tracks','Injection','Input Capture','Machine Learning','Masquerade','Mutex','Network Connection','Obfuscation','Persistence','Privilege Escalation','System Modification','Task Scheduling'))::int AS behavioural,
  count(o.id) FILTER (WHERE o.score>=3 AND d.category='Extracted Configuration')::int AS config_extraction,
  count(o.id) FILTER (WHERE o.score>=3 AND (d.category IS NULL OR d.category NOT IN ('Antivirus','Reputation','YARA','Anti Analysis','Browser','Computer Vision','Crash','Data Collection','Defense Evasion','Discovery','Execution','Extracted Configuration','Heuristics','Hide Tracks','Injection','Input Capture','Machine Learning','Masquerade','Mutex','Network Connection','Obfuscation','Persistence','Privilege Escalation','System Modification','Task Scheduling')))::int AS unknown
 FROM analysis_runs r LEFT JOIN vti_observations o ON o.analysis_run_id=r.id LEFT JOIN vti_definitions d ON d.id=o.vti_definition_id GROUP BY r.id
)
UPDATE analysis_runs r SET vti_total=c.total,vti_nonbehavioural_high=c.nonbehavioural,vti_behavioural_high=c.behavioural,vti_config_extraction_high=c.config_extraction,vti_unknown_category_high=c.unknown FROM counts c WHERE c.id=r.id;

ALTER TABLE analysis_runs DROP COLUMN IF EXISTS actual_duration_seconds;
ALTER TABLE analysis_runs DROP COLUMN IF EXISTS support_classification;
