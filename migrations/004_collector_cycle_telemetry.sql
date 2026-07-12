ALTER TABLE ingestion_batches ADD COLUMN IF NOT EXISTS new_count int NOT NULL DEFAULT 0;
ALTER TABLE ingestion_batches ADD COLUMN IF NOT EXISTS skipped_existing int NOT NULL DEFAULT 0;
ALTER TABLE ingestion_batches ADD COLUMN IF NOT EXISTS updated int NOT NULL DEFAULT 0;
ALTER TABLE ingestion_batches ADD COLUMN IF NOT EXISTS regrouped_samples int NOT NULL DEFAULT 0;
ALTER TABLE ingestion_batches ADD COLUMN IF NOT EXISTS duration_seconds numeric;

ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_cycle_duration_seconds numeric;
ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_discovered int NOT NULL DEFAULT 0;
ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_new int NOT NULL DEFAULT 0;
ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_skipped_existing int NOT NULL DEFAULT 0;
ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_updated int NOT NULL DEFAULT 0;
ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_failed int NOT NULL DEFAULT 0;
ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_regrouped_samples int NOT NULL DEFAULT 0;
