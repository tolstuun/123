from dataclasses import dataclass
from typing import Any

NON_BEHAVIOURAL = {"Antivirus", "Reputation", "YARA"}
CONFIG_EXTRACTION_CATEGORY = "Extracted Configuration"


class VTIAnalysisMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class VTICounts:
    behavioural_high: int = 0
    nonbehavioural_high: int = 0
    config_extraction_high: int = 0
    total: int = 0
    seen_categories: tuple[tuple[str, int], ...] = ()


def classify_vtis(vtis: list[dict[str, Any]], analysis_id: int, logger=None) -> VTICounts:
    behavioural = nonbehavioural = config_extraction = 0
    seen = []
    for indicator in vtis:
        if indicator.get("analysis_ids") != [analysis_id]:
            raise VTIAnalysisMismatch(
                f"VTI analysis_ids mismatch for analysis {analysis_id}: {indicator.get('analysis_ids')!r}"
            )
        try:
            score = float(indicator.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        if score < 3:
            continue
        category = indicator.get("category")
        seen.append((str(category or "Uncategorized"), int(score)))
        if category in NON_BEHAVIOURAL:
            nonbehavioural += 1
        else:
            behavioural += 1
            config_extraction += int(category == CONFIG_EXTRACTION_CATEGORY)
    return VTICounts(behavioural, nonbehavioural, config_extraction, len(vtis), tuple(seen))
