VERDICT_RANK = {"failed": -1, "unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}


def normalize_verdict(value, failed=False):
    if failed:
        return "failed"
    text = str(value or "").strip().lower()
    if text in VERDICT_RANK:
        return text
    if text in {"clean", "not_suspicious"}:
        return "benign"
    return "unknown"


def vti_key(item):
    return str(item.get("id") or item.get("stable_id")), item.get("scope", "analysis"), str(item.get("artifact_id") or "")


def compare_vtis(before, after):
    left, right = {vti_key(x): x for x in before}, {vti_key(x): x for x in after}
    return {
        "added": [right[k] for k in right.keys() - left.keys()],
        "removed": [left[k] for k in left.keys() - right.keys()],
        "score_increased": [(left[k], right[k]) for k in left.keys() & right.keys() if (right[k].get("score") or 0) > (left[k].get("score") or 0)],
        "score_decreased": [(left[k], right[k]) for k in left.keys() & right.keys() if (right[k].get("score") or 0) < (left[k].get("score") or 0)],
    }
