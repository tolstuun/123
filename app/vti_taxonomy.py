import logging
from dataclasses import dataclass
from typing import Any

NON_BEHAVIOURAL = {"Antivirus", "Reputation", "YARA"}
KNOWN_BEHAVIOURAL = {
    "Anti Analysis", "Browser", "Computer Vision", "Crash", "Data Collection",
    "Defense Evasion", "Discovery", "Execution", "Extracted Configuration",
    "Heuristics", "Hide Tracks", "Injection", "Input Capture", "Machine Learning",
    "Masquerade", "Mutex", "Network Connection", "Obfuscation", "Persistence",
    "Privilege Escalation", "System Modification", "Task Scheduling",
}
KNOWN_CATEGORIES = NON_BEHAVIOURAL | KNOWN_BEHAVIOURAL


class VTIAnalysisMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class VTICounts:
    behavioural_high: int = 0
    nonbehavioural_high: int = 0
    config_extraction_high: int = 0
    unknown_category_high: int = 0
    total: int = 0


def classify_vtis(vtis: list[dict[str, Any]], analysis_id: int, logger: logging.Logger) -> VTICounts:
    behavioural = nonbehavioural = config_extraction = unknown = 0
    for indicator in vtis:
        if indicator.get("analysis_ids") != [analysis_id]:
            raise VTIAnalysisMismatch(
                f"VTI analysis_ids mismatch for analysis {analysis_id}: {indicator.get('analysis_ids')!r}"
            )
        try:
            high = float(indicator.get("score") or 0) >= 3
        except (TypeError, ValueError):
            high = False
        if not high:
            continue
        category = indicator.get("category")
        if category not in KNOWN_CATEGORIES:
            unknown += 1
            logger.warning("Unknown VTI category for analysis %s: %r", analysis_id, category)
        elif category in NON_BEHAVIOURAL:
            nonbehavioural += 1
        else:
            behavioural += 1
            config_extraction += int(category == "Extracted Configuration")
    return VTICounts(behavioural, nonbehavioural, config_extraction, unknown, len(vtis))
