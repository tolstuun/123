#!/bin/sh
set -eu
cd /home/deploy/vmray-analytics
mkdir -p backups
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
docker compose exec -T db pg_dump -U "${POSTGRES_USER:-vmray}" -d "${POSTGRES_DB:-vmray}" -Fc | gzip > "backups/vmray-${stamp}.dump.gz"
printf 'Backup created: %s\n' "backups/vmray-${stamp}.dump.gz"
