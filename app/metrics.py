from dataclasses import dataclass
from datetime import datetime

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
), eligible AS MATERIALIZED (
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
  bool_or(r.vti_behavioural_high>0) behavioural
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
        cur.execute(DETECTION_SQL, _cohort_args(window, cohort_type))
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


BEHAVIOURAL_COVERAGE_CTES = """
pairs(base,longer,pair_order) AS (VALUES (60,120,1),(120,180,2),(60,180,3)),
submission_arms AS (
 SELECT DISTINCT r.sample_id,r.round_id,r.vmray_submission_id,r.duration_bucket arm,r.submission_created
 FROM eligible c JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id
 WHERE r.analysis_type='dynamic' AND r.duration_bucket IN (60,120,180)
), ordered_submissions AS (
 SELECT sa.*,row_number() OVER (
  PARTITION BY sa.sample_id,sa.round_id
  ORDER BY sa.submission_created NULLS LAST,sa.vmray_submission_id,sa.arm
 ) submission_order
 FROM submission_arms sa
), arm_values AS (
 SELECT c.sample_id,c.round_id,
  max(r.vti_behavioural_high) FILTER(WHERE r.duration_bucket=60) behav_60,
  max(r.vti_behavioural_high) FILTER(WHERE r.duration_bucket=120) behav_120,
  max(r.vti_behavioural_high) FILTER(WHERE r.duration_bucket=180) behav_180,
  min(os.submission_order) FILTER(WHERE os.arm=60) order_60,
  min(os.submission_order) FILTER(WHERE os.arm=120) order_120,
  min(os.submission_order) FILTER(WHERE os.arm=180) order_180
 FROM eligible c JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id
  AND r.analysis_type='dynamic' AND r.duration_bucket IN (60,120,180)
 LEFT JOIN ordered_submissions os ON os.sample_id=r.sample_id AND os.round_id=r.round_id
  AND os.vmray_submission_id=r.vmray_submission_id AND os.arm=r.duration_bucket
 GROUP BY c.sample_id,c.round_id
), monotonic AS (
 SELECT * FROM arm_values
 WHERE (coalesce(behav_60,0)>0)::int <= (coalesce(behav_120,0)>0)::int
   AND (coalesce(behav_120,0)>0)::int <= (coalesce(behav_180,0)>0)::int
), reverted AS (
 SELECT count(*) reverted_rounds FROM arm_values a
 LEFT JOIN monotonic m USING(sample_id,round_id) WHERE m.sample_id IS NULL
), scopes(scope) AS (VALUES ('unfiltered'),('monotonic')),
scoped AS (
 SELECT 'unfiltered'::text scope,a.* FROM arm_values a
 UNION ALL SELECT 'monotonic'::text scope,m.* FROM monotonic m
), compared AS (
 SELECT a.scope,p.base,p.longer,p.pair_order,a.sample_id,a.round_id,
  CASE p.base WHEN 60 THEN a.behav_60 WHEN 120 THEN a.behav_120 ELSE a.behav_180 END base_value,
  CASE p.longer WHEN 60 THEN a.behav_60 WHEN 120 THEN a.behav_120 ELSE a.behav_180 END longer_value,
  CASE
   WHEN (CASE p.base WHEN 60 THEN a.order_60 WHEN 120 THEN a.order_120 ELSE a.order_180 END) IS NULL
     OR (CASE p.longer WHEN 60 THEN a.order_60 WHEN 120 THEN a.order_120 ELSE a.order_180 END) IS NULL
    THEN 'unknown'
   WHEN (CASE p.base WHEN 60 THEN a.order_60 WHEN 120 THEN a.order_120 ELSE a.order_180 END)
   < (CASE p.longer WHEN 60 THEN a.order_60 WHEN 120 THEN a.order_120 ELSE a.order_180 END)
   THEN 'base_first' ELSE 'longer_first' END order_side
 FROM scoped a CROSS JOIN pairs p
), overall AS (
 SELECT s.scope,p.base,p.longer,p.pair_order,count(c.sample_id) rounds,
  count(c.sample_id) FILTER(WHERE c.base_value>0) behav_base,
  count(c.sample_id) FILTER(WHERE c.longer_value>0) behav_longer,
  count(c.sample_id) FILTER(WHERE c.base_value=0 AND c.longer_value>0) exclusive,
  count(c.sample_id) FILTER(WHERE c.base_value>0 AND c.longer_value=0) crossout
 FROM scopes s CROSS JOIN pairs p LEFT JOIN compared c
  ON c.scope=s.scope AND c.base=p.base AND c.longer=p.longer
 GROUP BY s.scope,p.base,p.longer,p.pair_order
), sides(order_side) AS (VALUES ('base_first'),('longer_first'),('unknown')),
split AS (
 SELECT sc.scope,p.base,p.longer,p.pair_order,s.order_side,count(c.sample_id) rounds,
  count(c.sample_id) FILTER(WHERE c.base_value>0) behav_base,
  count(c.sample_id) FILTER(WHERE c.longer_value>0) behav_longer,
  count(c.sample_id) FILTER(WHERE c.base_value=0 AND c.longer_value>0) exclusive,
  count(c.sample_id) FILTER(WHERE c.base_value>0 AND c.longer_value=0) crossout
 FROM scopes sc CROSS JOIN pairs p CROSS JOIN sides s LEFT JOIN compared c
  ON c.scope=sc.scope AND c.base=p.base AND c.longer=p.longer AND c.order_side=s.order_side
 GROUP BY sc.scope,p.base,p.longer,p.pair_order,s.order_side
), denominators AS (
 SELECT sc.scope,count(s.sample_id) FILTER(WHERE coalesce(s.behav_180,0)>0) behav_at_180
 FROM scopes sc LEFT JOIN scoped s ON s.scope=sc.scope GROUP BY sc.scope
), coverage AS (
 SELECT o.scope,o.base,o.longer,o.pair_order,'all'::text order_side,o.rounds,o.behav_base,
  o.behav_longer,o.exclusive,o.crossout,false underpowered FROM overall o
 UNION ALL
 SELECT s.scope,s.base,s.longer,s.pair_order,s.order_side,s.rounds,s.behav_base,s.behav_longer,
  s.exclusive,s.crossout,(s.rounds < o.rounds * 0.10) underpowered
 FROM split s JOIN overall o USING(scope,base,longer,pair_order)
)
SELECT c.scope,c.base,c.longer,c.order_side,c.rounds,c.behav_base,c.behav_longer,
 c.exclusive,c.crossout,d.behav_at_180,
 CASE WHEN c.scope='monotonic' AND c.order_side='all' AND c.base=60 AND c.longer=180 THEN
   100.0*(SELECT c1.exclusive FROM coverage c1 WHERE c1.scope=c.scope
    AND c1.base=60 AND c1.longer=120 AND c1.order_side=c.order_side)/nullif(d.behav_at_180,0)
   + 100.0*(SELECT c2.exclusive FROM coverage c2 WHERE c2.scope=c.scope
    AND c2.base=120 AND c2.longer=180 AND c2.order_side=c.order_side)/nullif(d.behav_at_180,0)
  ELSE 100.0*c.exclusive/nullif(d.behav_at_180,0) END pct_of_180_coverage,
 round(100.0*c.exclusive/nullif(c.behav_base,0),1) pct_uplift_over_base,
 c.underpowered,r.reverted_rounds
FROM coverage c JOIN denominators d USING(scope) CROSS JOIN reverted r
ORDER BY CASE c.scope WHEN 'monotonic' THEN 0 ELSE 1 END,c.pair_order,
 CASE c.order_side WHEN 'all' THEN 0 WHEN 'base_first' THEN 1 WHEN 'longer_first' THEN 2 ELSE 3 END
"""


def new_vtis_by_arm(window: Window, cohort_type: str, base: int, longer: int, limit=25):
    if base not in (60,120,180) or longer not in (60,120,180) or base >= longer:
        raise ValueError("base and longer must be increasing dynamic arms")
    sql = COHORT_CTE + """
    , base_vtis AS (
      SELECT r.sample_id,r.round_id,o.vti_definition_id,max(o.score) score FROM eligible c
      JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
      JOIN vti_observations o ON o.analysis_run_id=r.id
      GROUP BY r.sample_id,r.round_id,o.vti_definition_id
    ), longer_vtis AS (
      SELECT r.sample_id,r.round_id,o.vti_definition_id,max(o.score) score FROM eligible c
      JOIN analysis_runs r ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
      JOIN vti_observations o ON o.analysis_run_id=r.id
      GROUP BY r.sample_id,r.round_id,o.vti_definition_id
    ), gained AS (
      SELECT l.* FROM longer_vtis l LEFT JOIN base_vtis b ON b.sample_id=l.sample_id AND b.round_id=l.round_id
       AND b.vti_definition_id=l.vti_definition_id WHERE b.vti_definition_id IS NULL
    ), lost AS (
      SELECT b.* FROM base_vtis b LEFT JOIN longer_vtis l ON l.sample_id=b.sample_id AND l.round_id=b.round_id
       AND l.vti_definition_id=b.vti_definition_id WHERE l.vti_definition_id IS NULL
    ), gained_agg AS (
      SELECT d.category,d.operation,max(g.score) max_score,count(DISTINCT g.sample_id) samples_gained
      FROM gained g JOIN vti_definitions d ON d.id=g.vti_definition_id GROUP BY d.category,d.operation
    ), lost_agg AS (
      SELECT d.category,d.operation,max(l.score) max_score,count(DISTINCT l.sample_id) samples_lost
      FROM lost l JOIN vti_definitions d ON d.id=l.vti_definition_id GROUP BY d.category,d.operation
    )
    SELECT coalesce(g.category,l.category) category,coalesce(g.operation,l.operation) operation,
      coalesce(g.max_score,l.max_score) severity,coalesce(g.samples_gained,0) samples_gained,
      coalesce(l.samples_lost,0) samples_lost,coalesce(g.samples_gained,0)-coalesce(l.samples_lost,0) net
    FROM gained_agg g FULL OUTER JOIN lost_agg l ON coalesce(g.category,'')=coalesce(l.category,'')
      AND coalesce(g.operation,'')=coalesce(l.operation,'')
    ORDER BY samples_gained DESC,severity DESC,operation
    """
    if limit is not None:
        if not isinstance(limit,int) or limit<1:raise ValueError("limit must be a positive integer or None")
        sql+=f" LIMIT {limit}"
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


def submission_order_fixed_pct(window: Window):
    """Share of complete rounds whose dynamic arms were submitted 60s, 120s, then 180s."""
    sql = """
    WITH round_starts AS (
      SELECT sample_id,round_id,min(created_at) first_run FROM analysis_runs GROUP BY 1,2
    ), inventory AS (
      SELECT rs.sample_id,rs.round_id,s.file_type,
       bool_or(r.analysis_type='static') has_static,
       bool_or(r.analysis_type='dynamic' AND r.duration_bucket=60) has_60,
       bool_or(r.analysis_type='dynamic' AND r.duration_bucket=120) has_120,
       bool_or(r.analysis_type='dynamic' AND r.duration_bucket=180) has_180,
       bool_or(r.is_failed) has_failed,
       min(r.submission_created) FILTER(WHERE r.analysis_type='dynamic' AND r.duration_bucket=60) submitted_60,
       min(r.submission_created) FILTER(WHERE r.analysis_type='dynamic' AND r.duration_bucket=120) submitted_120,
       min(r.submission_created) FILTER(WHERE r.analysis_type='dynamic' AND r.duration_bucket=180) submitted_180
      FROM round_starts rs JOIN samples s ON s.id=rs.sample_id
      JOIN analysis_runs r ON r.sample_id=rs.sample_id AND r.round_id=rs.round_id
      WHERE rs.first_run >= %s AND rs.first_run < %s
      GROUP BY rs.sample_id,rs.round_id,s.file_type
    ), eligible AS (
      SELECT * FROM inventory WHERE NOT has_failed AND has_60 AND has_120 AND has_180
       AND (file_type='URL' OR has_static)
    )
    SELECT round(100.0*count(*) FILTER(
      WHERE submitted_60 < submitted_120 AND submitted_120 < submitted_180
    )/nullif(count(*),0),1) fixed_pct
    FROM eligible
    """
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (window.start, window.end))
        return cur.fetchone()["fixed_pct"]


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
           bool_or(r.vti_behavioural_high>0) behavioural
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
          (cohort_type,));detection=cur.fetchall()
        cur.execute("WITH eligible AS (SELECT * FROM metric_eligible), " + BEHAVIOURAL_COVERAGE_CTES)
        coverage=cur.fetchall()

        def new_vtis(base,longer):
            cur.execute("""WITH base_vtis AS (
              SELECT r.sample_id,r.round_id,o.vti_definition_id,max(o.score) score FROM metric_eligible c JOIN analysis_runs r
               ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
               JOIN vti_observations o ON o.analysis_run_id=r.id GROUP BY r.sample_id,r.round_id,o.vti_definition_id), longer_vtis AS (
              SELECT r.sample_id,r.round_id,o.vti_definition_id,max(o.score) score FROM metric_eligible c JOIN analysis_runs r
               ON r.sample_id=c.sample_id AND r.round_id=c.round_id AND r.analysis_type='dynamic' AND r.duration_bucket=%s
               JOIN vti_observations o ON o.analysis_run_id=r.id GROUP BY r.sample_id,r.round_id,o.vti_definition_id), gained AS (
              SELECT l.* FROM longer_vtis l LEFT JOIN base_vtis b ON b.sample_id=l.sample_id AND b.round_id=l.round_id
               AND b.vti_definition_id=l.vti_definition_id WHERE b.vti_definition_id IS NULL), lost AS (
              SELECT b.* FROM base_vtis b LEFT JOIN longer_vtis l ON l.sample_id=b.sample_id AND l.round_id=b.round_id
               AND l.vti_definition_id=b.vti_definition_id WHERE l.vti_definition_id IS NULL), gained_agg AS (
              SELECT d.category,d.operation,max(g.score) max_score,count(DISTINCT g.sample_id) samples_gained FROM gained g
               JOIN vti_definitions d ON d.id=g.vti_definition_id GROUP BY d.category,d.operation), lost_agg AS (
              SELECT d.category,d.operation,max(l.score) max_score,count(DISTINCT l.sample_id) samples_lost FROM lost l
               JOIN vti_definitions d ON d.id=l.vti_definition_id GROUP BY d.category,d.operation)
              SELECT coalesce(g.category,l.category) category,coalesce(g.operation,l.operation) operation,
               coalesce(g.max_score,l.max_score) severity,coalesce(g.samples_gained,0) samples_gained,
               coalesce(l.samples_lost,0) samples_lost,coalesce(g.samples_gained,0)-coalesce(l.samples_lost,0) net
              FROM gained_agg g FULL OUTER JOIN lost_agg l ON coalesce(g.category,'')=coalesce(l.category,'')
               AND coalesce(g.operation,'')=coalesce(l.operation,'')
              ORDER BY samples_gained DESC,severity DESC,operation LIMIT 25""",(base,longer))
            return cur.fetchall()

        return {"exclusions":exclusions,"detection":detection,"coverage":coverage,"daily":daily,
                "new_60_180":new_vtis(60,180),"new_60_120":new_vtis(60,120)}
