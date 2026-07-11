# Logical Experiment Grouping

## Production evidence

Aggregate inspection of immutable production runs and compressed raw analysis payloads found 1,218 real analyses across 138 sample hashes at investigation time. Job IDs were unique per analysis; parent analysis IDs and tags were absent. Submission-ID arrays, configuration IDs, user-configuration IDs, and job-rule IDs were populated but did not consistently link the six runs: only 4 of 207 temporal candidate clusters shared a submission-array value, and configuration/job-rule linkage was even rarer. No authoritative cross-submission identifier was found in the documented fields.

Analysis start timestamps provided a strong and stable boundary. Thresholds of 30, 60, 120, and 300 seconds all produced exactly 207 clusters: 200 contained precisely three static runs plus dynamic 60/120/180, seven were incomplete, and none had duplicate slots. Median cluster span was 17 seconds and p95 was 40 seconds. Increasing the threshold to 600 seconds merged independent cycles, producing 12- and 18-run clusters and duplicate slots. This discontinuity supports a conservative five-minute maximum interval while demonstrating that the observed cycles themselves are much tighter.

No sample hashes, filenames, credentials, internal payload values, or malware identifiers are included here.

## Selected deterministic algorithm: `temporal-v1`

1. Partition immutable analyses by sample SHA-256 (represented by the normalized sample ID).
2. Sort by `started_at`, falling back to `completed_at`, then VMRay analysis ID.
3. Start a new cluster when a run is more than `LOGICAL_GROUP_MAX_GAP_SECONDS` from the cluster anchor. Default: 300 seconds.
4. Assign the first three chronological static analyses to `static_1`, `static_2`, and `static_3`.
5. Assign at most one dynamic analysis to each of `dynamic_60`, `dynamic_120`, and `dynamic_180`.
6. A duplicate candidate or unexpected duration is not used to fill another slot. The cluster is marked ambiguous and the conflicting analysis remains unassigned.
7. Group keys use sample identity plus the minimum source analysis ID, making reruns deterministic and allowing delayed runs with original timestamps to join an incomplete cycle.
8. A complete unambiguous group is finalized after `LOGICAL_GROUP_SETTLING_SECONDS` (default 900). Recent incomplete groups are safely reconsidered whenever a new run arrives.

Temporal linkage is assigned medium confidence because it is strongly evidenced but is not an authoritative API relationship. Ambiguous clusters are low confidence. Submission IDs remain unchanged in source provenance tables and on every analysis run.

## Architecture and reconstruction

- `source_submission_groups` and `source_submission_group_runs` retain actual VMRay provenance.
- `logical_experiment_groups` stores product experiment boundaries, method, confidence, version, explanation, timestamps, and ambiguity.
- `logical_experiment_group_runs` provides the exclusive run assignment and expected slot.
- Unassigned runs remain recoverable through `unassigned_analysis_runs`.
- `analysis_group_completeness` derives completeness only from logical membership.

`python -m app.grouping dry-run` reports proposals without mutation. `python -m app.grouping apply` validates exclusive assignment, sample boundaries, slot capacity, deterministic static ordering, and source preservation before applying an idempotent transaction. The production dry-run and applied counts are recorded after deployment in this document's production reconstruction section.

## Production reconstruction

The collector was paused to freeze the production dataset. The final dry-run proposed 243 logical groups from 1,402 eligible immutable analyses: 224 complete, 19 incomplete, zero ambiguous, and zero unassigned. Cycle sizes were five groups with two slots, eight with three, six with four, and 224 with all six. Temporal spans were 204 groups at 0–30 seconds, 36 at 31–60 seconds, and three at 61–300 seconds. No duplicate-slot cluster was proposed.

The identical proposal was applied transactionally. Post-apply checks found 718 source submission groups, 243 logical experiment groups, 1,402 exclusive logical assignments, zero duplicate assignments, zero cross-sample groups, zero missing source-provenance links, and the same 1,402 source analyses as before. The collector was then restarted. These are a point-in-time reconstruction snapshot; continuous ingestion can increase live counts.
