# Changelog

## 1.1.1 - 2026-07-12

- Made overlap collection skip fully imported analyses, batch logical regrouping once per changed sample, added cycle locking/telemetry, eliminated unchanged grouping writes, and disabled automatic large archive retention.

## 1.1.0 - 2026-07-11

- Separated VMRay submission provenance from logical experiment cycles and safely reconstructed production using deterministic start-time clustering.

## 1.0.1 - 2026-07-11

- Corrected six-slot group completeness, added missing/duplicate/unmapped drill-downs, separated group and sample entity metrics, and rebuilt Overview with local accessible SVG charts.

## 1.0.0 - 2026-07-11

- Initial production-capable PostgreSQL platform, collector, authenticated responsive dashboard, comparisons, CSV exports, health/readiness probes, backups, Compose deployment, and GitHub Actions release automation.
