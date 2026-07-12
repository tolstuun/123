# Verified VMRay API Findings

Verified on 2026-07-11 against the configured on-premises server using read-only requests. The authoritative sources are `vmray-pltf-onprem-api-ref.pdf`, `vmray-pltf-api-guide.pdf`, and `vmray-pltf-analysis-results-ref-v2.pdf` in the untracked private documentation directory.

## Authentication and errors

- All calls use HTTPS and `Authorization: api_key <key>`.
- `GET /rest/analysis?_limit=1` without authentication returned 401; the configured key returned 200.
- An unknown REST path returned 404 with JSON keys `error_msg` and `result`.
- No rate-limit or retry headers were present. The client nevertheless handles 429 and transient 5xx responses with exponential backoff and jitter.

## Verified read-only endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/rest/analysis` | Analysis listing |
| GET | `/rest/analysis/{analysis_id}` | Analysis details |
| GET | `/rest/analysis/{analysis_id}/vtis` | Analysis VTI snapshot |
| GET | `/rest/analysis/{analysis_id}/archive` | Analysis archive ZIP |
| GET | `/rest/sample/{sample_id}` | Sample metadata |
| GET | `/rest/sample/{sample_id}/iocs?all_artifacts=true` | Sample IOC data |
| GET | `/rest/sample/{sample_id}/iocs/csv?all_artifacts=true` | IOC CSV |

The archive endpoint ignored a byte Range request and returned a complete ZIP. The production collector therefore does not call this endpoint.

## Listing, filtering, sorting, and pagination

Responses are JSON objects with `data` and `result`. `_limit` is accepted, but the live server capped a requested 100 rows at 50. Results are newest-first. `_max_id` is inclusive: using the smallest ID from one page repeats that row on the next page. The collector deduplicates by `analysis_id`, uses `_max_id`, and combines it with a timestamp overlap checkpoint rather than assuming IDs alone are gap-free. Documented interval filtering includes `/rest/analysis/created/{start}~{end}`; equality filters also exist as path endpoints for sample, submission, job, configuration, verdict, and other fields.

## Analysis and grouping fields

Verified listing/detail fields include `analysis_id`, `analysis_sample_id`, `analysis_submission_id`, `analysis_submission_ids`, `analysis_job_id`, `analysis_parent_analysis_id`, hashes, `analysis_created`, `analysis_job_started`, `analysis_result_code`, `analysis_result_str`, `analysis_verdict`, verdict reason code/description, VTI score, analyzer/static/dynamic engine versions, platform, configuration identifiers, and `analysis_user_config_config`.

The strongest grouping key is SHA-256 plus submission ID. When submission ID is missing, SHA-256 plus a deterministic UTC time window is used and marked ambiguous. Job ID identifies an individual run and is not used alone to group the six runs.

## Static/dynamic and duration identification

- `analysis_job_type=only_static_analysis` identifies static analysis.
- `analysis_job_type=full_analysis` identifies dynamic analysis on this server.
- Dynamic requested durations are verified in the JSON string `analysis_user_config_config`, e.g. `{"timeout":60}`, `120`, and `180`.
- Actual duration is derived from verified start/completion timestamps when both exist. The API listing does not expose a distinct authoritative actual-duration field.
- Static repetition numbers are assigned deterministically within a group by `(analysis_created, analysis_id)` and remain separate observations.

## Status and verdict

Completed live rows had `analysis_result_code=1` and `analysis_result_str="Operation completed successfully."`. Verdict is in `analysis_verdict`; score is `analysis_vti_score`; reason is represented by `analysis_verdict_reason_code` and `analysis_verdict_reason_description`. Original values are retained before normalization.

## VTI representation

`GET /rest/analysis/{id}/vtis` returns `data.status` and `data.threat_indicators`. Each verified indicator contains stable `id`, `category`, `operation`, `classifications`, `score`, and `analysis_ids`. Documentation additionally defines artifact-scoped matches. Identity is the stable ID plus artifact scope; score is observation data and never part of identity.

## IOC representation

Sample IOC JSON and CSV endpoints are available. The analysis archive contains `report/artifacts/all_iocs.csv` plus typed IOC CSV files and STIX reports. IOC acquisition is outside the current collector scope because full archives are not downloaded.

## Live differences and ambiguities

- `_limit=100` returned 50.
- No rate-limit headers were observed.
- Range was ignored for archive and IOC CSV downloads.
- VTI data is nested below `data.threat_indicators`, not a top-level list.
- Completion time and actual duration are not explicit in the verified listing; `analysis_created` is treated as the completion/availability timestamp, while `analysis_job_started` supplies the start.
- Artifact-level VTI structure is documented but was not present in the inspected VTI summaries.

## Safe polling strategy

Poll every `VMRAY_POLL_INTERVAL_SECONDS` (default 300), query a six-hour overlap from the durable completion timestamp checkpoint, page newest-first with inclusive `_max_id`, and upsert normalized immutable observations by stable API identifiers. API responses are discarded after normalization and archives are never requested. Transient failures retry with jitter; permanent per-analysis failures are recorded and do not advance beyond an unsafe gap.
