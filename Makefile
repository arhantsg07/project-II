.PHONY: up down logs topics ps reset attack benign consumer psql test health

COMPOSE := docker compose
PG_DSN  := postgres://postgres:postgres@localhost:5433/detection?sslmode=disable

## Bring up Postgres and Vector alongside the existing Redpanda; create topics.
up:
	$(COMPOSE) up -d --build
	docker exec redpanda rpk topic create auth.raw auditd.raw dns.raw --partitions 3 --replicas 1 --if-not-exists

## Stop project containers (external Redpanda and project data volumes are kept).
down:
	$(COMPOSE) down

## Tail logs from every service.
logs:
	$(COMPOSE) logs -f

## Show container status.
ps:
	$(COMPOSE) ps

## Wipe project containers, Postgres data and generated lab data; keep external Redpanda.
reset:
	$(COMPOSE) down -v
	rm -rf lab/data

## List Redpanda topics.
topics:
	docker exec redpanda rpk topic list

## Run one attack scenario: make attack SCENARIO=1
attack:
	bash lab/attacks/0$(SCENARIO)_*.sh

## Run N seconds of benign noise: make benign SECONDS=60
benign:
	bash lab/benign/generate.sh $(or $(SECONDS),60)

## Run the Go consumer locally against Redpanda and Postgres.
consumer:
	go run ./cmd/consumer -brokers localhost:9092 -pg "$(PG_DSN)"

## Open a psql shell against the lab database.
psql:
	PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -d detection

## Run Go unit + integration tests (integration tests need TEST_DATABASE_URL).
test:
	TEST_DATABASE_URL="$(PG_DSN)" go test ./... -v

## Quick health check: row counts and the most recent watermark per topic.
health:
	PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -d detection -c \
	  "SELECT source, count(*) AS events, max(received_at) AS latest FROM raw_events GROUP BY source ORDER BY source;"
	PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -d detection -c \
	  "SELECT * FROM ingest_watermarks ORDER BY kafka_topic, kafka_partition;"
