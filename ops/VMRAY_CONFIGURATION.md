# VMRay Configuration

Set `VMRAY_BASE_URL`, `VMRAY_API_KEY`, `VMRAY_VERIFY_TLS`, and `VMRAY_POLL_INTERVAL_SECONDS` only in the server-side mode-600 `.env`. The default poll interval is 300 seconds and the durable overlap is six hours. The collector performs GET requests only. Run one cycle with `docker compose run --rm collector python -m app.collector once`; view status in `collector_status` and errors in `collection_errors`.
