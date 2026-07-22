from dataclasses import dataclass
from datetime import datetime

from .config import settings
from .db import connection


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime


ARMS = ("static", "60", "120", "180")

COHORT_CTE = """
WITH round_starts AS (
 SELECT r.sample_id,r.round_id,min(r.created_at) first_run
 FROM analysis_runs r GROUP BY r.sample_id,r.round_id
), anchored AS (
 SELECT rs.sample_id,rs.round_id,rs.first_run,
  CASE WHEN s.file_type='URL' THEN 'url' ELSE 'file' END cohort_type
 FROM round_starts rs JOIN samples s ON s.id=rs.sample_id
 WHERE rs.first_run >= %s AND rs.first_run < %s
), inventory AS (
 SELECT a.*,
  bool_or(r.analysis_type='static') has_static,
  bool_or(r.analysis_type='dynamic' AND r.duration_bucket=60) has_60,
  bool_or(r.analysis_type='dynamic' AND r.duration_bucket=120) has_120,
  bool_or(r.analysis_type='dynamic' AND r.duration_bucket=180) has_180,
  bool_or(r.is_failed) has_failed
 FROM anchored a JOIN analysis_runs r ON r.sample_id=a.sample_id AND r.round_id=a.round_id
 GROUP BY a.sample_id,a.round_id,a.first_run,a.cohort_type
), selected AS (
 SELECT * FROM inventory WHERE cohort_type=%s
), eligible AS (
 SELECT * FROM selected WHERE NOT has_failed AND has_60 AND has_120 AND has_180
  AND (cohort_type='url' OR has_static)
)
"""

DETECTION_SQL = COHORT_CTE + """
, arms(arm) AS (VALUES ('static'),('60'),('120'),('180')),
evidence AS (
 SELECT c.sample_id,c.round_id,a.arm,count(r.id) run_count,
  bool_or(r.verdict='malicious') malicious,bool_or(r.verdict='suspicious') suspicious,
  bool_or(r.verdict='benign') benign,
  bool_or(r.vti_behavioural_high>0 OR (%s AND r.vti_static_detector_high>0)) behavioural
 FROM eligible c CROSS JOIN arms a LEFT JOIN analysis_runs r
 ON r.sample_id=c.sample_id AND r.round_id=c.round_id
  AND ((a.arm='static' AND r.analysis_type='static') OR
       (a.arm<>'static' AND r.analysis_type='dynamic' AND r.duration_bucket=a.arm::int))
 WHERE c.cohort_type='file' OR a.arm<>'static'
 GROUP BY c.sample_id,c.round_id,a.arm
), classified AS (
 SELECT *,CASE WHEN malicious AND behavioural THEN 'behavioural_malicious'
  WHEN malicious THEN 'nonbehavioural_malicious'
  WHEN suspicious AND behavioural THEN 'behavioural_suspicious'
  WHEN suspicious THEN 'nonbehavioural_suspicious'
  WHEN benign THEN 'benign' ELSE 'no_verdict' END category
 FROM evidence
)
SELECT arm,count(*) cohort_size,
 count(*) FILTER(WHERE category='behavioural_malicious') behavioural_malicious,
 count(*) FILTER(WHERE category='behavioural_suspicious') behavioural_suspicious,
 count(*) FILTER(WHERE category='nonbehavioural_malicious') nonbehavioural_malicious,
 count(*) FILTER(WHERE category='nonbehavioural_suspicious') nonbehavioural_suspicious,
 count(*) FILTER(WHERE category='benign') benign,
 count(*) FILTER(WHERE category='no_verdict') no_verdict
FROM classified GROUP BY arm ORDER BY array_position(ARRAY['static','60','120','180'],arm)
"""

EXCLUSIONS_SQL = COHORT_CTE + """
SELECT count(*) FILTER(WHERE NOT has_failed AND has_60 AND has_120 AND has_180 AND (cohort_type='url' OR has_static)) complete_rounds,
 count(*) FILTER(WHERE has_failed OR NOT has_60 OR NOT has_120 OR NOT has_180 OR (cohort_type='file' AND NOT has_static)) excluded_rounds,
 count(*) FILTER(WHERE cohort_type='file' AND NOT has_static) missing_static,
 count(*) FILTER(WHERE NOT has_60) missing_60,
 count(*) FILTER(WHERE NOT has_120) missing_120,
 count(*) FILTER(WHERE NOT has_180) missing_180,
 count(*) FILTER(WHERE has_failed) failed_run
FROM selected
"""

RESULTS_CTE = COHORT_CTE + """
, arms(arm) AS (VALUES (60),(120),(180)), results AS (
 SELECT c.sample_id,c.round_id,a.arm,
  CASE WHEN bool_or(r.verdict='malicious') THEN 'malicious'
   WHEN bool_or(r.verdict='suspicious') THEN 'suspicious'
   WHEN bool_or(r.verdict='benign') THEN 'benign' ELSE 'no_verdict' END result
 FROM eligible c CROSS JOIN arms a JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id
  AND r.analysis_type='dynamic' AND r.duration_bucket=a.arm
 GROUP BY c.sample_id,c.round_id,a.arm
)
"""


def _cohort_args(window: Window, cohort_type: str):
    if cohort_type not in {"file", "url"}:
        raise ValueError("cohort_type must be file or url")
    return window.start, window.end, cohort_type


def detection_by_arm(window: Window, cohort_type: str):
    with connection() as conn, conn.cursor() as cur:
        cur.execute(DETECTION_SQL, (*_cohort_args(window, cohort_type), settings.count_detectors_as_behavioural))
        return cur.fetchall()


def cohort_exclusions(window: Window, cohort_type: str):
    with connection() as conn, conn.cursor() as cur:
        cur.execute(EXCLUSIONS_SQL, _cohort_args(window, cohort_type))
        return cur.fetchone()


def duration_lift(window: Window, cohort_type: str):
    sql = RESULTS_CTE + """
    , pairs(base,longer) AS (VALUES (60,120),(60,180),(120,180))
    SELECT p.base,p.longer,b.result base_result,l.result longer_result,
      CASE WHEN b.result=l.result THEN 'stable'
       WHEN array_position(ARRAY['no_verdict','benign','suspicious','malicious'],l.result)
          < array_position(ARRAY['no_verdict','benign','suspicious','malicious'],b.result) THEN 'regression'
       ELSE 'upgrade' END direction,count(*) samples
    FROM pairs p JOIN results b ON b.arm=p.base JOIN results l
      ON l.sample_id=b.sample_id AND l.round_id=b.round_id AND l.arm=p.longer
    GROUP BY p.base,p.longer,b.result,l.result ORDER BY p.base,p.longer,direction,samples DESC"""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, _cohort_args(window, cohort_type))
        return cur.fetchall()


def new_vtis_by_arm(window: Window, cohort_type: str, base: int, longer: int):
    if base not in (60,120,180) or longer not in (60,120,180) or base >= longer:
        raise ValueError("base and longer must be increasing dynamic arms")
    sql = COHORT_CTE + """
    , base_vtis AS (
      SELECT DISTINCT r.sample_id,r.round_id,o.vti_definition_id FROM eligible c
      JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
      JOIN vti_observations o ON o.analysis_run_id=r.id
    ), longer_vtis AS (
      SELECT DISTINCT r.sample_id,r.round_id,o.vti_definition_id FROM eligible c
      JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
      JOIN vti_observations o ON o.analysis_run_id=r.id
    )
    SELECT d.stable_id,d.category,d.operation,count(DISTINCT l.sample_id) distinct_samples
    FROM longer_vtis l JOIN vti_definitions d ON d.id=l.vti_definition_id
    LEFT JOIN base_vtis b ON b.sample_id=l.sample_id AND b.round_id=l.round_id AND b.vti_definition_id=l.vti_definition_id
    WHERE b.vti_definition_id IS NULL GROUP BY d.stable_id,d.category,d.operation
    ORDER BY distinct_samples DESC,d.stable_id
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (*_cohort_args(window, cohort_type), base, longer))
        return cur.fetchall()


def daily_complete_rounds(window: Window):
    sql = """
    WITH round_starts AS (
      SELECT r.sample_id,r.round_id,min(r.created_at) first_run FROM analysis_runs r GROUP BY 1,2
    ), inventory AS (
      SELECT rs.sample_id,rs.round_id,rs.first_run,CASE WHEN s.file_type='URL' THEN 'url' ELSE 'file' END cohort_type,
       bool_or(r.analysis_type='static') has_static,
       bool_or(r.analysis_type='dynamic' AND r.duration_bucket=60) has_60,
       bool_or(r.analysis_type='dynamic' AND r.duration_bucket=120) has_120,
       bool_or(r.analysis_type='dynamic' AND r.duration_bucket=180) has_180,bool_or(r.is_failed) has_failed
      FROM round_starts rs JOIN samples s ON s.id=rs.sample_id JOIN analysis_runs r ON r.sample_id=rs.sample_id AND r.round_id=rs.round_id
      WHERE rs.first_run >= %s AND rs.first_run < %s GROUP BY rs.sample_id,rs.round_id,rs.first_run,s.file_type
    ), eligible AS (
      SELECT * FROM inventory WHERE NOT has_failed AND has_60 AND has_120 AND has_180 AND (cohort_type='url' OR has_static)
    )
    SELECT first_run::date cohort_day,count(*) FILTER(WHERE has_static) static,count(*) d60,count(*) d120,count(*) d180
    FROM eligible GROUP BY 1 ORDER BY 1
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (window.start, window.end))
        return cur.fetchall()


def cohort_bundle(window: Window, cohort_type: str):
    """Build the round inventory once for all dashboard panels in one transaction."""
    _cohort_args(window, cohort_type)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS pg_temp.metric_rounds")
        cur.execute("""CREATE TEMP TABLE metric_rounds ON COMMIT DROP AS
          WITH round_starts AS (
            SELECT sample_id,round_id,min(created_at) first_run FROM analysis_runs GROUP BY 1,2
          )
          SELECT rs.sample_id,rs.round_id,rs.first_run,
            bool_or(r.analysis_type='static') has_static,
            bool_or(r.analysis_type='dynamic' AND r.duration_bucket=60) has_60,
            bool_or(r.analysis_type='dynamic' AND r.duration_bucket=120) has_120,
            bool_or(r.analysis_type='dynamic' AND r.duration_bucket=180) has_180,
            bool_or(r.is_failed) has_failed
          FROM round_starts rs JOIN samples s ON s.id=rs.sample_id
          JOIN analysis_runs r ON r.sample_id=rs.sample_id AND r.round_id=rs.round_id
          WHERE rs.first_run>=%s AND rs.first_run<%s
            AND (CASE WHEN s.file_type='URL' THEN 'url' ELSE 'file' END)=%s
          GROUP BY rs.sample_id,rs.round_id,rs.first_run""", _cohort_args(window, cohort_type))
        cur.execute("""SELECT count(*) FILTER(WHERE NOT has_failed AND has_60 AND has_120 AND has_180 AND (%s='url' OR has_static)) complete_rounds,
          count(*) FILTER(WHERE has_failed OR NOT has_60 OR NOT has_120 OR NOT has_180 OR (%s='file' AND NOT has_static)) excluded_rounds,
          count(*) FILTER(WHERE %s='file' AND NOT has_static) missing_static,
          count(*) FILTER(WHERE NOT has_60) missing_60,count(*) FILTER(WHERE NOT has_120) missing_120,
          count(*) FILTER(WHERE NOT has_180) missing_180,count(*) FILTER(WHERE has_failed) failed_run FROM metric_rounds""",
          (cohort_type,cohort_type,cohort_type));exclusions=cur.fetchone()
        cur.execute("""CREATE TEMP TABLE metric_eligible ON COMMIT DROP AS SELECT * FROM metric_rounds
          WHERE NOT has_failed AND has_60 AND has_120 AND has_180 AND (%s='url' OR has_static)""",(cohort_type,))
        cur.execute("""SELECT first_run::date cohort_day,count(*) FILTER(WHERE has_static) static,
          count(*) d60,count(*) d120,count(*) d180 FROM metric_eligible GROUP BY 1 ORDER BY 1""");daily=cur.fetchall()
        cur.execute("""WITH arms(arm) AS (VALUES ('static'),('60'),('120'),('180')), evidence AS (
          SELECT c.sample_id,c.round_id,a.arm,bool_or(r.verdict='malicious') malicious,
           bool_or(r.verdict='suspicious') suspicious,bool_or(r.verdict='benign') benign,
           bool_or(r.vti_behavioural_high>0 OR (%s AND r.vti_static_detector_high>0)) behavioural
          FROM metric_eligible c CROSS JOIN arms a LEFT JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id
           AND ((a.arm='static' AND r.analysis_type='static') OR (a.arm<>'static' AND r.analysis_type='dynamic' AND r.duration_bucket=a.arm::int))
          WHERE %s='file' OR a.arm<>'static' GROUP BY c.sample_id,c.round_id,a.arm
        ), classified AS (SELECT *,CASE WHEN malicious AND behavioural THEN 'behavioural_malicious'
          WHEN malicious THEN 'nonbehavioural_malicious' WHEN suspicious AND behavioural THEN 'behavioural_suspicious'
          WHEN suspicious THEN 'nonbehavioural_suspicious' WHEN benign THEN 'benign' ELSE 'no_verdict' END category FROM evidence)
        SELECT arm,count(*) cohort_size,
          count(*) FILTER(WHERE category='behavioural_malicious') behavioural_malicious,
          count(*) FILTER(WHERE category='behavioural_suspicious') behavioural_suspicious,
          count(*) FILTER(WHERE category='nonbehavioural_malicious') nonbehavioural_malicious,
          count(*) FILTER(WHERE category='nonbehavioural_suspicious') nonbehavioural_suspicious,
          count(*) FILTER(WHERE category='benign') benign,count(*) FILTER(WHERE category='no_verdict') no_verdict
        FROM classified GROUP BY arm ORDER BY array_position(ARRAY['static','60','120','180'],arm)""",
          (settings.count_detectors_as_behavioural,cohort_type));detection=cur.fetchall()
        cur.execute("""WITH arms(arm) AS (VALUES (60),(120),(180)), results AS (
          SELECT c.sample_id,c.round_id,a.arm,CASE WHEN bool_or(r.verdict='malicious') THEN 'malicious'
           WHEN bool_or(r.verdict='suspicious') THEN 'suspicious' WHEN bool_or(r.verdict='benign') THEN 'benign' ELSE 'no_verdict' END result
          FROM metric_eligible c CROSS JOIN arms a JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id
           AND r.analysis_type='dynamic' AND r.duration_bucket=a.arm GROUP BY c.sample_id,c.round_id,a.arm
        ), pairs(base,longer) AS (VALUES (60,120),(60,180),(120,180))
        SELECT p.base,p.longer,b.result base_result,l.result longer_result,
          CASE WHEN b.result=l.result THEN 'stable' WHEN array_position(ARRAY['no_verdict','benign','suspicious','malicious'],l.result)
           < array_position(ARRAY['no_verdict','benign','suspicious','malicious'],b.result) THEN 'regression' ELSE 'upgrade' END direction,count(*) samples
        FROM pairs p JOIN results b ON b.arm=p.base JOIN results l ON l.sample_id=b.sample_id AND l.round_id=b.round_id AND l.arm=p.longer
        GROUP BY p.base,p.longer,b.result,l.result ORDER BY p.base,p.longer,direction,samples DESC""");lift=cur.fetchall()

        def new_vtis(base,longer):
            cur.execute("""WITH base_vtis AS (
              SELECT DISTINCT r.sample_id,r.round_id,o.vti_definition_id FROM metric_eligible c JOIN analysis_runs r
               ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
               JOIN vti_observations o ON o.analysis_run_id=r.id), longer_vtis AS (
              SELECT DISTINCT r.sample_id,r.round_id,o.vti_definition_id FROM metric_eligible c JOIN analysis_runs r
               ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
               JOIN vti_observations o ON o.analysis_run_id=r.id)
              SELECT d.stable_id,d.category,d.operation,count(DISTINCT l.sample_id) distinct_samples FROM longer_vtis l
              JOIN vti_definitions d ON d.id=l.vti_definition_id LEFT JOIN base_vtis b ON b.sample_id=l.sample_id
               AND b.round_id=l.round_id AND b.vti_definition_id=l.vti_definition_id WHERE b.vti_definition_id IS NULL
              GROUP BY d.stable_id,d.category,d.operation ORDER BY distinct_samples DESC,d.stable_id LIMIT 25""",(base,longer))
            return cur.fetchall()

        return {"exclusions":exclusions,"detection":detection,"lift":lift,"daily":daily,
                "new_60_180":new_vtis(60,180),"new_60_120":new_vtis(60,120)}
