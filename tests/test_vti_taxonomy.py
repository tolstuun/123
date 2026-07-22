import logging
import pytest
from app.vti_taxonomy import VTIAnalysisMismatch, classify_vtis


def indicator(category,score=3,analysis_id=42,operation="text is irrelevant"):
    return {"category":category,"operation":operation,"score":score,"analysis_ids":[analysis_id]}


def test_category_only_taxonomy_and_counts(caplog):
    caplog.set_level(logging.WARNING)
    counts=classify_vtis([
        indicator("Antivirus"),indicator("Reputation"),indicator("YARA"),
        indicator("Injection",operation="antivirus yara"),indicator("Extracted Configuration"),
        indicator("New Category"),indicator("Injection",score=2),
    ],42,logging.getLogger("test"))
    assert counts.total==7
    assert counts.nonbehavioural_high==3
    assert counts.behavioural_high==2
    assert counts.config_extraction_high==1
    assert counts.unknown_category_high==1
    assert "New Category" in caplog.text


def test_unknown_never_defaults_to_behavioural():
    counts=classify_vtis([indicator(None)],42,logging.getLogger("test"))
    assert counts.unknown_category_high==1 and counts.behavioural_high==0


def test_analysis_id_mismatch_stops_ingestion():
    with pytest.raises(VTIAnalysisMismatch):
        classify_vtis([indicator("Injection",analysis_id=99)],42,logging.getLogger("test"))
