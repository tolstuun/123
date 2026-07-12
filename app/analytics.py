from datetime import date, timedelta

EXPECTED_SLOTS = ("static_1", "static_2", "static_3", "dynamic_60", "dynamic_120", "dynamic_180")
VERDICT_CATEGORIES = ("malicious", "suspicious", "benign", "unknown", "failed", "mixed")
SUPPORT_CATEGORIES = ("av_only", "yara_only", "av_yara_only", "behavioral", "none")

LOGICAL_RESULT_SQL = """
WITH selected_groups AS (
    SELECT id FROM logical_experiment_groups g
    WHERE {mode_clause} AND g.last_analysis_at >= %s
), run_evidence AS (
    SELECT lr.logical_experiment_group_id group_id,lr.expected_slot,r.verdict,
           bool_or(o.score BETWEEN 3 AND 5 AND lower(trim(d.category))='antivirus') has_av,
           bool_or(o.score BETWEEN 3 AND 5 AND lower(trim(d.category))='yara') has_yara,
           bool_or(o.score BETWEEN 3 AND 5 AND lower(trim(d.category)) NOT IN ('antivirus','yara')) has_behavioral
    FROM logical_experiment_group_runs lr
    JOIN selected_groups sg ON sg.id=lr.logical_experiment_group_id
    JOIN analysis_runs r ON r.id=lr.analysis_run_id
    LEFT JOIN vti_observations o ON o.analysis_run_id=r.id
    LEFT JOIN vti_definitions d ON d.id=o.vti_definition_id
    WHERE lr.expected_slot IN ('static_1','static_2','static_3','dynamic_60','dynamic_120','dynamic_180')
    GROUP BY 1,2,3
), logical_results AS (
    SELECT group_id,'Static' run_kind,
           CASE WHEN count(DISTINCT verdict)=1 THEN min(verdict) ELSE 'mixed' END verdict,
           bool_or(has_av) has_av,bool_or(has_yara) has_yara,bool_or(has_behavioral) has_behavioral
    FROM run_evidence WHERE expected_slot LIKE 'static_%' GROUP BY group_id
    UNION ALL
    SELECT group_id,CASE expected_slot WHEN 'dynamic_60' THEN 'Dynamic 60s' WHEN 'dynamic_120' THEN 'Dynamic 120s' ELSE 'Dynamic 180s' END,
           verdict,has_av,has_yara,has_behavioral
    FROM run_evidence WHERE expected_slot LIKE 'dynamic_%'
)
SELECT group_id,run_kind,verdict,
       CASE WHEN has_behavioral THEN 'behavioral'
            WHEN has_av AND has_yara THEN 'av_yara_only'
            WHEN has_av THEN 'av_only'
            WHEN has_yara THEN 'yara_only'
            ELSE 'none' END support
FROM logical_results
"""


def fetch_logical_results(cur, mode, start):
    mode_clause = "TRUE" if mode == "combined" else "g.is_demo=%s"
    args = (start,) if mode == "combined" else (mode == "demo", start)
    cur.execute(LOGICAL_RESULT_SQL.format(mode_clause=mode_clause), args)
    return cur.fetchall()


def summarize_logical_results(rows):
    kinds = ("Static", "Dynamic 60s", "Dynamic 120s", "Dynamic 180s")
    output = []
    for kind in kinds:
        selected = [row for row in rows if row["run_kind"] == kind]
        verdicts = {category: sum(row["verdict"] == category for row in selected) for category in VERDICT_CATEGORIES}
        support = {category: sum(row["support"] == category for row in selected) for category in SUPPORT_CATEGORIES}
        av_yara = support["av_only"] + support["yara_only"] + support["av_yara_only"]
        output.append({"kind": kind, "total": len(selected), "verdicts": verdicts, "support": support,
                       "av_yara_only": av_yara,
                       "av_yara_malicious": sum(row["support"] in SUPPORT_CATEGORIES[:3] and row["verdict"] == "malicious" for row in selected),
                       "av_yara_suspicious": sum(row["support"] in SUPPORT_CATEGORIES[:3] and row["verdict"] == "suspicious" for row in selected)})
    return output


def classify_group(runs):
    counts = {slot: 0 for slot in EXPECTED_SLOTS}
    unmapped = 0
    for run in runs:
        slot = None
        if run.get("analysis_type") == "static" and run.get("static_repetition") in (1, 2, 3):
            slot = f"static_{run['static_repetition']}"
        elif run.get("analysis_type") == "dynamic" and run.get("duration_bucket") in (60, 120, 180):
            slot = f"dynamic_{run['duration_bucket']}"
        if slot:
            counts[slot] += 1
        else:
            unmapped += 1
    missing = [slot for slot, count in counts.items() if count == 0]
    duplicates = [slot for slot, count in counts.items() if count > 1]
    if not missing and not duplicates and not unmapped:
        status = "complete_clean"
    elif duplicates:
        status = "duplicate_slots"
    elif unmapped:
        status = "unmapped_runs"
    else:
        status = "incomplete"
    return {"counts": counts, "expected_slots_present": 6 - len(missing), "missing_slots": missing,
            "duplicate_slots": duplicates, "duplicate_slot_count": len(duplicates),
            "unmapped_run_count": unmapped, "completeness_status": status}


def zero_fill_daily(start: date, end: date, rows, keys):
    indexed = {row["day"]: row for row in rows}
    output = []
    current = start
    while current <= end:
        source = indexed.get(current, {})
        output.append({"day": current, **{key: int(source.get(key) or 0) for key in keys}})
        current += timedelta(days=1)
    return output
