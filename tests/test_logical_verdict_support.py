from app.analytics import LOGICAL_RESULT_SQL, summarize_logical_results


def result(group, kind, verdict, support):
    return {"group_id": group, "run_kind": kind, "verdict": verdict, "support": support}


def test_logical_verdicts_count_each_group_once_and_keep_mixed_static():
    rows = [
        result(1, "Static", "malicious", "av_only"),
        result(2, "Static", "mixed", "behavioral"),
        result(1, "Dynamic 60s", "suspicious", "yara_only"),
    ]
    summary = {row["kind"]: row for row in summarize_logical_results(rows)}
    assert summary["Static"]["total"] == 2
    assert summary["Static"]["verdicts"]["malicious"] == 1
    assert summary["Static"]["verdicts"]["mixed"] == 1
    assert summary["Dynamic 60s"]["total"] == 1


def test_support_categories_partition_every_logical_result():
    supports = ("av_only", "yara_only", "av_yara_only", "behavioral", "none")
    rows = [result(index, "Static", "malicious" if index < 4 else "suspicious", support)
            for index, support in enumerate(supports, 1)]
    static = summarize_logical_results(rows)[0]
    assert static["total"] == 5
    assert sum(static["support"].values()) == static["total"]
    assert static["av_yara_only"] == 3
    assert static["av_yara_malicious"] == 3


def test_vti_mapping_uses_authoritative_category_and_scores_three_to_five():
    sql = LOGICAL_RESULT_SQL.lower()
    assert "o.score between 3 and 5" in sql
    assert "d.category" in sql
    assert "d.description" not in sql
    assert "count(distinct verdict)=1" in sql
