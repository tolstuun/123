from pathlib import Path


def test_collector_persists_normalized_data_without_raw_storage():
    source = Path("app/collector.py").read_text(encoding="utf-8")
    assert "INSERT INTO analysis_runs" in source
    assert "INSERT INTO verdict_observations" in source
    assert "INSERT INTO vti_observations" in source
    assert "raw_api_payloads" not in source
    assert "raw_payload_id" not in source


def test_migration_only_removes_raw_storage_from_normalized_schema():
    migration = Path("migrations/005_remove_raw_payload_storage.sql").read_text(encoding="utf-8").lower()
    assert "drop column if exists raw_payload_id" in migration
    assert "drop table if exists raw_api_payloads" in migration
    for retained in ("samples", "verdict_observations", "vti_definitions", "vti_observations"):
        assert f"drop table {retained}" not in migration
