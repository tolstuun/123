.PHONY: up down migrate test collect logs backup ready
up:
	docker compose up -d --build
down:
	docker compose down
migrate:
	docker compose run --rm migrate
test:
	docker build -t vmray-analytics:test . && docker run --rm vmray-analytics:test pytest -q
collect:
	docker compose run --rm collector python -m app.collector once
logs:
	docker compose logs -f --tail=200 web collector proxy db
backup:
	sh ops/backup.sh
ready:
	curl -fsS http://localhost:8081/ready
