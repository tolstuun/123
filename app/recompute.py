import argparse

from .db import connection
from .vti_taxonomy import CONFIG_EXTRACTION_CATEGORY, NON_BEHAVIOURAL


RECOMPUTE_SQL = """
WITH calculated AS (
 SELECT r.id,
  count(o.id)::int total,
  count(o.id) FILTER (WHERE o.score>=3 AND d.category=ANY(%s))::int nonbehavioural,
  count(o.id) FILTER (WHERE o.score>=3 AND (d.category IS NULL OR NOT d.category=ANY(%s)))::int behavioural,
  count(o.id) FILTER (WHERE o.score>=3 AND d.category=%s)::int config_extraction
 FROM analysis_runs r
 LEFT JOIN vti_observations o ON o.analysis_run_id=r.id
 LEFT JOIN vti_definitions d ON d.id=o.vti_definition_id
 WHERE %s::bigint[] IS NULL OR r.id=ANY(%s::bigint[])
 GROUP BY r.id
)
UPDATE analysis_runs r SET
 vti_behavioural_high=c.behavioural,
 vti_nonbehavioural_high=c.nonbehavioural,
 vti_config_extraction_high=c.config_extraction,
 vti_total=c.total
FROM calculated c WHERE c.id=r.id
"""


def recompute_vti_counters(run_ids=None):
    ids=list(dict.fromkeys(run_ids)) if run_ids else None
    denied=sorted(NON_BEHAVIOURAL)
    with connection() as conn,conn.cursor() as cur:
        cur.execute(RECOMPUTE_SQL,(denied,denied,CONFIG_EXTRACTION_CATEGORY,ids,ids))
        changed=cur.rowcount
        conn.commit()
    return changed


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Recompute persisted VTI counters from normalized observations")
    parser.add_argument("run_ids",nargs="*",type=int)
    args=parser.parse_args()
    print(f"Recomputed {recompute_vti_counters(args.run_ids or None)} analysis runs")
