# Troubleshooting

- Status: `docker compose ps`.
- Logs: `docker compose logs -f --tail=200 web collector proxy db`.
- Restart: `docker compose restart web collector proxy`.
- Migration: `docker compose run --rm migrate`.
- One-shot collection: `docker compose run --rm collector python -m app.collector once`.
- Collector state: `docker compose exec db psql -U vmray -d vmray -c 'select * from collector_status'`.
- Recent failures: `docker compose exec db psql -U vmray -d vmray -c 'select occurred_at,analysis_id,error_type,message from collection_errors order by occurred_at desc limit 20'`.

401 responses indicate an invalid/expired API key. TLS failures should be corrected at the certificate level; disabling verification is supported only for controlled on-premises environments. No analytics cleanup runs automatically.
