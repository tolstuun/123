#!/bin/sh
set -eu
cd /home/deploy/vmray-analytics
touch .env
chmod 600 .env
ensure() { key="$1"; value="$2"; grep -q "^${key}=" .env || printf '%s=%s\n' "$key" "$value" >> .env; }
ensure POSTGRES_DB vmray
ensure POSTGRES_USER vmray
ensure POSTGRES_PASSWORD "$(openssl rand -hex 32)"
ensure DASHBOARD_USERNAME analytics
ensure DASHBOARD_PASSWORD "$(openssl rand -base64 30 | tr -d '/+=' | head -c 32)"
ensure VMRAY_BASE_URL ""
ensure VMRAY_API_KEY ""
ensure VMRAY_VERIFY_TLS true
ensure VMRAY_POLL_INTERVAL_SECONDS 300
ensure VMRAY_FETCH_ANALYSIS_ARCHIVES false
