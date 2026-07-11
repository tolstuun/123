# Deployment

Pushes to `main` run focused tests, build the image, transfer a release over SSH, preserve `.env` and the named PostgreSQL volume, apply migrations, start Compose, and wait for `/ready`.

Manual production startup: `cd /home/deploy/vmray-analytics && ./ops/provision-env.sh && docker compose run --rm migrate && docker compose up -d --build`.

The dashboard is at `http://77.42.72.36`. Retrieve credentials on the host without transmitting them through CI: `ssh -i C:\Users\Administrator\.ssh\vmray_analytics_deploy deploy@77.42.72.36 "cd /home/deploy/vmray-analytics && grep -E '^(DASHBOARD_USERNAME|DASHBOARD_PASSWORD)=' .env"`.

Health: `curl -fsS http://77.42.72.36/health`; readiness: `curl -fsS http://77.42.72.36/ready`.
