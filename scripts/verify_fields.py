"""Read-only field verification against the latest 500 VMRay analyses."""

import asyncio
import json
import math
import statistics
from collections import Counter, defaultdict
from typing import Any

from app.config import settings
from app.vmray import VMRayClient, parse_time


LIMIT = 500
DETAIL_CONCURRENCY = 10
INTERFACE_TIMEOUTS = {"1minute": 60, "2minutes": 120, "3minutes": 180}


def cell(value: Any) -> str:
    if value is None:
        return "null"
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def table(title: str, headers: list[str], rows: list[list[Any]]) -> None:
    print(f"## {title}")
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join(cell(value) for value in row) + " |")
    if not rows:
        print("| " + " | ".join(["No data"] + [""] * (len(headers) - 1)) + " |")
    print()


def payload_data(payload: Any) -> Any:
    return payload.get("data", payload) if isinstance(payload, dict) else payload


def parse_config(value: Any) -> tuple[bool, dict[str, Any]]:
    if isinstance(value, dict):
        return True, value
    if not isinstance(value, str):
        return False, {}
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return False, {}
    return (True, parsed) if isinstance(parsed, dict) else (True, {})


def is_dynamic(analysis: dict[str, Any]) -> bool:
    return analysis.get("analysis_job_type") == "full_analysis"


async def latest_analyses(client: VMRayClient) -> list[dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    max_id = None
    while len(found) < LIMIT:
        params = {"_limit": 50}
        if max_id is not None:
            params["_max_id"] = max_id
        page = payload_data((await client.get("/rest/analysis", params=params)).json())
        if not page:
            break
        for item in page:
            analysis_id = item.get("analysis_id")
            if analysis_id is not None:
                found[int(analysis_id)] = item
        minimum = min(int(item["analysis_id"]) for item in page if item.get("analysis_id") is not None)
        next_max = minimum - 1
        if max_id is not None and next_max >= max_id:
            break
        max_id = next_max
        if len(page) < 50:
            break
    return sorted(found.values(), key=lambda item: int(item["analysis_id"]), reverse=True)[:LIMIT]


async def hydrate_details(client: VMRayClient, analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

    async def fetch(item: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            detail = payload_data(await client.detail(item["analysis_id"]))
            return detail if isinstance(detail, dict) else item

    detailed = await asyncio.gather(*(fetch(item) for item in analyses[:30]))
    return [{**analyses[index], **detail} for index, detail in enumerate(detailed)] + analyses[30:]


async def main() -> None:
    client = VMRayClient()
    try:
        listed = await latest_analyses(client)
        analyses = await hydrate_details(client, listed)

        job_types = Counter(str(a.get("analysis_job_type") or "null") for a in analyses)
        table("1. analysis_job_type distribution", ["analysis_job_type", "Count", "Percentage"], [
            [job_type, count, f"{count / len(analyses) * 100:.6f}%" if analyses else "0.000000%"]
            for job_type, count in sorted(job_types.items(), key=lambda pair: (-pair[1], pair[0]))
        ])

        config_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"total": 0, "parsed": 0, "timeout": 0, "values": Counter()})
        for analysis in analyses:
            job_type = str(analysis.get("analysis_job_type") or "null")
            stats = config_stats[job_type]
            stats["total"] += 1
            parsed, config = parse_config(analysis.get("analysis_user_config_config"))
            stats["parsed"] += int(parsed)
            if "timeout" in config:
                stats["timeout"] += 1
                stats["values"][json.dumps(config["timeout"], sort_keys=True)] += 1
        dynamic = [a for a in analyses if is_dynamic(a)]
        dynamic_absent = sum("timeout" not in parse_config(a.get("analysis_user_config_config"))[1] for a in dynamic)
        config_rows = []
        for job_type, stats in sorted(config_stats.items()):
            distribution = ", ".join(f"{value}: {count}" for value, count in sorted(stats["values"].items())) or "none"
            config_rows.append([job_type, stats["total"], stats["parsed"], f"{stats['parsed'] / stats['total'] * 100:.6f}%", stats["timeout"], distribution])
        config_rows.append(["Dynamic timeout absent (full_analysis)", len(dynamic), dynamic_absent,
                            f"{dynamic_absent / len(dynamic) * 100:.6f}%" if dynamic else "0.000000%", "—", "—"])
        table("2. Config JSON and timeout", ["analysis_job_type / measure", "Total", "Count", "Percentage", "Has timeout", "Timeout distribution"], config_rows)

        submission_rows = []
        agreements = 0
        for analysis in dynamic[:20]:
            _, config = parse_config(analysis.get("analysis_user_config_config"))
            timeout = config.get("timeout")
            submission_id = analysis.get("analysis_submission_id")
            submission = payload_data(await client.get(f"/rest/submission/{submission_id}"))
            if hasattr(submission, "json"):
                submission = payload_data(submission.json())
            interface = submission.get("submission_interface_name") if isinstance(submission, dict) else None
            expected = INTERFACE_TIMEOUTS.get(str(interface))
            try:
                agrees = expected is not None and int(timeout) == expected
            except (TypeError, ValueError):
                agrees = False
            agreements += int(agrees)
            submission_rows.append([analysis.get("analysis_id"), submission_id, interface, timeout, expected, "yes" if agrees else "NO"])
        submission_rows.append(["Agreement summary", "—", "—", "—", "—", f"{agreements}/{len(submission_rows)} ({agreements / len(submission_rows) * 100:.6f}%)" if submission_rows else "0/0"])
        table("3. Submission interface versus timeout", ["Analysis ID", "Submission ID", "submission_interface_name", "Parsed timeout", "Expected timeout", "Agrees"], submission_rows)

        results = Counter((str(a.get("analysis_result_code") if a.get("analysis_result_code") is not None else "null"),
                           str(a.get("analysis_result_str") or "null")) for a in analyses)
        empty_verdicts = sum(a.get("analysis_verdict") in (None, "") for a in analyses)
        result_rows = [[code, result, count] for (code, result), count in sorted(results.items(), key=lambda pair: (-pair[1], pair[0]))]
        result_rows.append(["Verdict null/empty", "—", empty_verdicts])
        table("4. Analysis results and empty verdicts", ["analysis_result_code", "analysis_result_str / measure", "Count"], result_rows)

        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def fetch_vtis(analysis: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            async with semaphore:
                payload = payload_data(await client.vtis(analysis["analysis_id"]))
                indicators = payload.get("threat_indicators", []) if isinstance(payload, dict) else []
                return analysis, indicators

        vti_results = await asyncio.gather(*(fetch_vtis(analysis) for analysis in analyses[:300]))
        pairs: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {"count": 0, "scores": []})
        raw_indicator = None
        for _, indicators in vti_results[:30]:
            for indicator in indicators:
                if raw_indicator is None:
                    raw_indicator = indicator
                key = (str(indicator.get("category") or "null"), str(indicator.get("operation") or "null"))
                pairs[key]["count"] += 1
                score = indicator.get("score")
                if isinstance(score, (int, float)):
                    pairs[key]["scores"].append(score)
        pair_rows = []
        for (category, operation), values in sorted(pairs.items(), key=lambda pair: (-pair[1]["count"], pair[0])):
            scores = values["scores"]
            pair_rows.append([category, operation, values["count"], min(scores) if scores else "none", max(scores) if scores else "none"])
        table("5a. Distinct VTI category and operation pairs", ["Category", "Operation", "Frequency", "Minimum score", "Maximum score"], pair_rows)
        table("5b. One raw threat_indicator object", ["Raw JSON"], [[json.dumps(raw_indicator, sort_keys=True, separators=(",", ":")) if raw_indicator else "none observed"]])

        started_present = sum(bool(a.get("analysis_job_started")) for a in analyses)
        comparable = 0
        ordered = 0
        violations = 0
        for analysis in analyses:
            started = parse_time(analysis.get("analysis_job_started"))
            created = parse_time(analysis.get("analysis_created"))
            if started and created:
                comparable += 1
                if created >= started:
                    ordered += 1
                else:
                    violations += 1
        table("6. Analysis timestamps", ["Measure", "Count", "Percentage"], [
            ["analysis_job_started present", started_present, f"{started_present / len(analyses) * 100:.6f}%" if analyses else "0.000000%"],
            ["Comparable created/started pairs", comparable, f"{comparable / len(analyses) * 100:.6f}%" if analyses else "0.000000%"],
            ["analysis_created >= analysis_job_started", ordered, f"{ordered / comparable * 100:.6f}%" if comparable else "0.000000%"],
            ["Ordering violations", violations, f"{violations / comparable * 100:.6f}%" if comparable else "0.000000%"],
        ])

        wide_pairs: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "full": 0, "static": 0, "high": 0, "scores": []}
        )
        categories = set()
        for analysis, indicators in vti_results:
            job_type = analysis.get("analysis_job_type")
            for indicator in indicators:
                category = str(indicator.get("category") or "null")
                operation = str(indicator.get("operation") or "null")
                categories.add(category)
                values = wide_pairs[(category, operation)]
                values["count"] += 1
                values["full"] += int(job_type == "full_analysis")
                values["static"] += int(job_type == "only_static_analysis")
                score = indicator.get("score")
                if isinstance(score, (int, float)):
                    values["scores"].append(score)
                    values["high"] += int(score >= 3)
        wide_rows = []
        for (category, operation), values in sorted(wide_pairs.items(), key=lambda pair: (-pair[1]["high"], -pair[1]["count"], pair[0])):
            scores = values["scores"]
            wide_rows.append([category, operation, values["count"], values["full"], values["static"], values["high"],
                              min(scores) if scores else "none", max(scores) if scores else "none"])
        table("7a. VTI taxonomy over 300 analyses", ["Category", "Operation", "Occurrences", "full_analysis", "only_static_analysis", "Score >= 3", "Minimum score", "Maximum score"], wide_rows)
        table("7b. Distinct VTI categories", ["Category"], [[category] for category in sorted(categories)])

        durations: dict[int, list[float]] = defaultdict(list)
        for analysis in dynamic:
            _, config = parse_config(analysis.get("analysis_user_config_config"))
            try:
                timeout = int(config.get("timeout"))
            except (TypeError, ValueError):
                continue
            started = parse_time(analysis.get("analysis_job_started"))
            created = parse_time(analysis.get("analysis_created"))
            if timeout in (60, 120, 180) and started and created:
                durations[timeout].append((created - started).total_seconds())
        duration_rows = []
        for timeout in (60, 120, 180):
            values = sorted(durations[timeout])
            p90 = values[max(0, math.ceil(0.9 * len(values)) - 1)] if values else "none"
            duration_rows.append([timeout, len(values), min(values) if values else "none",
                                  statistics.median(values) if values else "none", p90, max(values) if values else "none"])
        table("8. Timeout fidelity", ["Configured timeout", "Count", "Minimum seconds", "Median seconds", "P90 seconds", "Maximum seconds"], duration_rows)

        arms: dict[Any, dict[str, Any]] = defaultdict(lambda: {"dynamic": 0, "static": 0, "timeouts": []})
        for analysis in analyses:
            sample_id = analysis.get("analysis_sample_id")
            values = arms[sample_id]
            if is_dynamic(analysis):
                values["dynamic"] += 1
                _, config = parse_config(analysis.get("analysis_user_config_config"))
                try:
                    values["timeouts"].append(int(config.get("timeout")))
                except (TypeError, ValueError):
                    pass
            elif analysis.get("analysis_job_type") == "only_static_analysis":
                values["static"] += 1
        tuple_counts = Counter((values["dynamic"], values["static"]) for values in arms.values())
        table("9a. Per-sample arm count distribution", ["Dynamic run count", "Static run count", "Samples"],
              [[dynamic_count, static_count, count] for (dynamic_count, static_count), count in sorted(tuple_counts.items())])
        incomplete_rows = []
        expected_timeouts = {60, 120, 180}
        for sample_id, values in sorted(arms.items(), key=lambda pair: str(pair[0])):
            if (values["dynamic"], values["static"]) == (3, 3):
                continue
            present = sorted(set(values["timeouts"]))
            missing = sorted(expected_timeouts - set(present))
            incomplete_rows.append([sample_id, values["dynamic"], values["static"], ", ".join(map(str, present)) or "none", ", ".join(map(str, missing)) or "none"])
            if len(incomplete_rows) == 20:
                break
        table("9b. Samples not having (3, 3)", ["Sample ID", "Dynamic runs", "Static runs", "Timeouts present", "Timeouts missing"], incomplete_rows)
    finally:
        await client.close()


def safe_error(error: Exception) -> str:
    message = f"{type(error).__name__}: {error}"
    return message.replace(settings.vmray_api_key, "[REDACTED]") if settings.vmray_api_key else message


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        table("Verification error", ["Error"], [[safe_error(error)]])
        raise SystemExit(1)
