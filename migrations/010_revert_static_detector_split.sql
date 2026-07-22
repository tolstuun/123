UPDATE analysis_runs
SET vti_behavioural_high = vti_behavioural_high
                          + COALESCE(vti_static_detector_high, 0);

ALTER TABLE analysis_runs DROP COLUMN vti_static_detector_high;
