from collections import defaultdict

from .db import connection


def calculate_rounds(submissions):
    """Return submission->round assignments in stable submission chronology."""
    rounds = {}
    seen = set()
    round_id = 1
    for row in sorted(submissions, key=lambda x: (x["submission_created"], x["vmray_submission_id"])):
        interface = row["submission_interface_name"] or f"submission:{row['vmray_submission_id']}"
        if interface in seen:
            round_id += 1
            seen.clear()
        seen.add(interface)
        rounds[row["vmray_submission_id"]] = round_id
    return rounds


def assign_rounds(sample_ids):
    if not sample_ids:
        return 0
    changed = 0
    with connection() as conn, conn.cursor() as cur:
        for sample_id in sorted(set(sample_ids)):
            cur.execute("""SELECT vmray_submission_id,min(submission_created) submission_created,
                max(submission_interface_name) submission_interface_name
                FROM analysis_runs WHERE sample_id=%s AND vmray_submission_id IS NOT NULL
                GROUP BY vmray_submission_id""", (sample_id,))
            assignments = calculate_rounds(cur.fetchall())
            for submission_id, round_id in assignments.items():
                cur.execute("""UPDATE analysis_runs SET round_id=%s
                    WHERE sample_id=%s AND vmray_submission_id=%s AND round_id IS DISTINCT FROM %s""",
                    (round_id, sample_id, submission_id, round_id))
                changed += cur.rowcount
        conn.commit()
    return changed
