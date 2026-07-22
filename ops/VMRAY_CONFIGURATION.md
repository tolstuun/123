# VMRay Configuration

Set `VMRAY_BASE_URL`, `VMRAY_API_KEY`, `VMRAY_VERIFY_TLS`, and `VMRAY_POLL_INTERVAL_SECONDS` only in the server-side mode-600 `.env`. The default poll interval is 300 seconds and the durable overlap is six hours. The collector performs GET requests only. Run one cycle with `docker compose run --rm collector python -m app.collector once`; view status in `collector_status` and errors in `collection_errors`.

`COUNT_DETECTORS_AS_BEHAVIOURAL` defaults to `false`. When enabled, high-confidence Computer Vision, Heuristics, Machine Learning, and Masquerade VTIs are folded into behavioral detection metrics; they are always stored separately in `vti_static_detector_high`.

The collector uses analysis detail, VTI, and sample endpoints only long enough to normalize their fields. It never downloads full analysis archives and never stores raw API responses.
