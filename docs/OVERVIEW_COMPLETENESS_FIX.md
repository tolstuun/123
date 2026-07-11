# Overview Completeness Correction

## Production audit

The pre-change production audit was performed while the collector was actively ingesting. It found 88 unique real sample hashes, 315 logical groups, and 613 analysis runs. Group sizes were 298 groups with two runs and 17 with one run. Exact-slot evaluation found all 315 groups incomplete: static repetition 2 and 3 were absent from every group; dynamic 60, 120, and 180 were each absent from roughly 214–215 groups. All 312 static runs were assigned repetition 1. No production identifiers, hashes, filenames, or credentials were recorded in this document.

The previously observed screen values—Samples 45, Complete 0, Incomplete 168—were an earlier point in the same live backfill. `Samples` counted distinct sample database IDs, while `Incomplete` counted logical groups. Those values therefore described different entity levels and were not expected to add up.

## Root cause

Completeness previously used only `count(*) = 6`. It did not verify the six expected slots and could classify duplicates or six static runs as complete. The collector groups by the verified SHA-256 plus submission ID. Current source data commonly places runs for one hash in separate submission groups, and static repetition assignment is deterministic only within each group; consequently each such group has static repetition 1 rather than an inferred cross-submission sequence. This correction does not silently regroup immutable production observations.

## Corrected model

Migration 002 creates `analysis_group_completeness`, the reusable source of truth used by Overview, Samples, group drill-down, and sample detail. It counts exact slots from `analysis_type`, `static_repetition`, and `duration_bucket`; derives missing and duplicate slot arrays; counts unmapped runs; and classifies each group as `complete_clean`, `incomplete`, `duplicate_slots`, or `unmapped_runs`.

A clean complete group has exactly one observation in every expected slot and no unmapped run. Duplicate and unmapped problems are exposed independently. Existing group membership and analysis rows remain unchanged.
