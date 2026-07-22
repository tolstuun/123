from dataclasses import dataclass
from datetime import datetime

from .db import connection


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime


ARMS = ("static", "60", "120", "180")

DETECTION_SQL = """
WITH cohort AS (
 SELECT DISTINCT r.sample_id,r.round_id,coalesce(s.file_type,'unknown') sample_type
 FROM analysis_runs r JOIN samples s ON s.id=r.sample_id
 WHERE r.created_at >= %s AND r.created_at < %s
), arms(arm) AS (VALUES ('static'),('60'),('120'),('180')),
evidence AS (
 SELECT c.sample_id,c.round_id,c.sample_type,a.arm,count(r.id) run_count,
  bool_or(r.verdict='malicious') malicious,bool_or(r.verdict='suspicious') suspicious,
  bool_or(r.verdict='benign') benign,bool_or(r.is_failed) failed,
  bool_or(r.vti_behavioural_high>0) behavioural
 FROM cohort c CROSS JOIN arms a LEFT JOIN analysis_runs r
  ON r.sample_id=c.sample_id AND r.round_id=c.round_id
  AND r.created_at >= %s AND r.created_at < %s
  AND ((a.arm='static' AND r.analysis_type='static') OR
       (a.arm<>'static' AND r.analysis_type='dynamic' AND r.duration_bucket=a.arm::int))
 GROUP BY c.sample_id,c.round_id,c.sample_type,a.arm
), classified AS (
 SELECT *,CASE WHEN run_count=0 THEN 'missing'
  WHEN malicious AND behavioural THEN 'behavioural_malicious'
  WHEN malicious THEN 'nonbehavioural_malicious'
  WHEN suspicious AND behavioural THEN 'behavioural_suspicious'
  WHEN suspicious THEN 'nonbehavioural_suspicious'
  WHEN benign THEN 'benign' WHEN failed THEN 'failed' ELSE 'no_verdict' END category
 FROM evidence
)
SELECT sample_type,arm,count(*) cohort_size,
 count(*) FILTER(WHERE category='behavioural_malicious') behavioural_malicious,
 count(*) FILTER(WHERE category='behavioural_suspicious') behavioural_suspicious,
 count(*) FILTER(WHERE category='nonbehavioural_malicious') nonbehavioural_malicious,
 count(*) FILTER(WHERE category='nonbehavioural_suspicious') nonbehavioural_suspicious,
 count(*) FILTER(WHERE category='benign') benign,
 count(*) FILTER(WHERE category='no_verdict') no_verdict,
 count(*) FILTER(WHERE category='failed') failed,
 count(*) FILTER(WHERE category='missing') missing
FROM classified GROUP BY sample_type,arm ORDER BY sample_type,arm
"""

RESULTS_CTE = """
WITH cohort AS (
 SELECT DISTINCT r.sample_id,r.round_id,coalesce(s.file_type,'unknown') sample_type
 FROM analysis_runs r JOIN samples s ON s.id=r.sample_id
 WHERE r.created_at >= %s AND r.created_at < %s
), arms(arm) AS (VALUES (60),(120),(180)), results AS (
 SELECT c.sample_id,c.round_id,c.sample_type,a.arm,
  CASE WHEN count(r.id)=0 THEN 'missing' WHEN bool_or(r.verdict='malicious') THEN 'malicious'
   WHEN bool_or(r.verdict='suspicious') THEN 'suspicious' WHEN bool_or(r.verdict='benign') THEN 'benign'
   WHEN bool_or(r.is_failed) THEN 'failed' ELSE 'no_verdict' END result
 FROM cohort c CROSS JOIN arms a LEFT JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id
  AND r.analysis_type='dynamic' AND r.duration_bucket=a.arm
  AND r.created_at >= %s AND r.created_at < %s
 GROUP BY c.sample_id,c.round_id,c.sample_type,a.arm
)
"""


def detection_by_arm(window: Window):
    with connection() as conn, conn.cursor() as cur:
        cur.execute(DETECTION_SQL, (window.start, window.end, window.start, window.end))
        return cur.fetchall()


def duration_lift(window: Window):
    sql = RESULTS_CTE + """
    , pairs(base,longer) AS (VALUES (60,120),(60,180),(120,180))
    SELECT b.sample_type,p.base,p.longer,b.result base_result,l.result longer_result,
      CASE WHEN b.result=l.result THEN 'stable'
       WHEN b.result='missing' AND l.result<>'missing' THEN 'gained'
       WHEN l.result='missing' THEN 'regression'
       WHEN array_position(ARRAY['no_verdict','failed','benign','suspicious','malicious'],l.result)
          < array_position(ARRAY['no_verdict','failed','benign','suspicious','malicious'],b.result) THEN 'regression'
       ELSE 'upgrade' END direction,count(*) samples
    FROM pairs p JOIN results b ON b.arm=p.base JOIN results l
      ON l.sample_id=b.sample_id AND l.round_id=b.round_id AND l.arm=p.longer
    GROUP BY b.sample_type,p.base,p.longer,b.result,l.result ORDER BY 2,3,7 DESC"""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (window.start, window.end, window.start, window.end))
        return cur.fetchall()


def new_vtis_by_arm(window: Window, base: int, longer: int):
    if base not in (60,120,180) or longer not in (60,120,180) or base >= longer:
        raise ValueError("base and longer must be increasing dynamic arms")
    sql = """
    WITH runs AS (
      SELECT r.*,coalesce(s.file_type,'unknown') sample_type FROM analysis_runs r JOIN samples s ON s.id=r.sample_id
      WHERE r.created_at >= %s AND r.created_at < %s AND r.analysis_type='dynamic'
    ), base_vtis AS (
      SELECT DISTINCT r.sample_id,r.round_id,o.vti_definition_id FROM runs r JOIN vti_observations o ON o.analysis_run_id=r.id WHERE r.duration_bucket=%s
    ), longer_vtis AS (
      SELECT DISTINCT r.sample_id,r.round_id,r.sample_type,o.vti_definition_id FROM runs r JOIN vti_observations o ON o.analysis_run_id=r.id WHERE r.duration_bucket=%s
    )
    SELECT l.sample_type,d.stable_id,d.category,d.operation,count(DISTINCT l.sample_id) distinct_samples
    FROM longer_vtis l JOIN vti_definitions d ON d.id=l.vti_definition_id
    LEFT JOIN base_vtis b ON b.sample_id=l.sample_id AND b.round_id=l.round_id AND b.vti_definition_id=l.vti_definition_id
    WHERE b.vti_definition_id IS NULL GROUP BY l.sample_type,d.stable_id,d.category,d.operation
    ORDER BY distinct_samples DESC,d.stable_id
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (window.start, window.end, base, longer))
        return cur.fetchall()
