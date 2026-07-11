from datetime import date, timedelta

EXPECTED_SLOTS = ("static_1", "static_2", "static_3", "dynamic_60", "dynamic_120", "dynamic_180")


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
