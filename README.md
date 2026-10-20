# Mini AI-Assisted Detection & Response

A security event pipeline for a simulated Linux lab. Phase 1 collects and
durably stores raw logs; Phase 2 parses those logs into a common event schema,
extracts entities, deduplicates events, and records parse failures.

## Architecture

```text
                         Phase 1: raw ingestion
┌────────────────────────────┐
│ Lab scripts                │
│ auth.log / auditd.log /    │
│ dns.log                    │
└──────────────┬─────────────┘
               │ append log lines
               ▼
┌────────────────────────────┐
│ Vector collector           │
│ tags source + host         │
└──────────────┬─────────────┘
               │ auth.raw / auditd.raw / dns.raw
               ▼
┌────────────────────────────┐
│ Redpanda (Kafka API)       │
│ external broker            │
└──────────────┬─────────────┘
               │ consumer group: raw-ingest
               ▼
┌────────────────────────────┐
│ Go raw consumer            │
│ commits offsets after DB   │
│ write                      │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────────────────────┐
│ Postgres                                    │
│ raw_events + ingest_watermarks              │
└──────────────────────┬─────────────────────┘
                       │
                       │ Phase 2: poll raw_events
                       ▼
┌────────────────────────────────────────────┐
│ Go normalizer                              │
│ parse • extract entities • deduplicate      │
└────────────┬─────────────────┬─────────────┘
             │                 │
             ▼                 ▼
       ┌───────────┐     ┌───────────────┐
       │ events +  │     │ parse_failures│
       │ entities  │     │ unparseable   │
       └───────────┘     │ records       │
                         └───────────────┘
             └──── progress: normalizer_cursor
```

Vector and Postgres run in Docker Compose. Redpanda is intentionally an
already-running external container named `redpanda`; the compose project
does not create, restart, or remove it. The lab represents one host using
files containing realistic auth, auditd, and DNS log lines.

## Prerequisites

- Docker and Docker Compose v2
- A running Redpanda container named `redpanda`, reachable at
  `localhost:9092` from the host, with `docker exec redpanda` access
- Go 1.22+
- `make`
- `psql` client (optional, for queries and migrations)

## Quick start

Start the database and collector, create the raw topics, and start producing
lab events:

```bash
make up
make attack SCENARIO=1
```

In a second terminal, start the raw consumer:

```bash
make consumer
```

In a third terminal, start the Phase 2 normalizer:

```bash
go run ./cmd/normalizer -pg "postgres://postgres:postgres@localhost:5433/detection?sslmode=disable"
```

The consumer writes raw rows to Postgres; the normalizer polls those rows
every two seconds and writes normalized records. `make health` checks Phase 1
raw ingestion and Kafka watermarks. To inspect Phase 2 output:

```bash
PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -d detection \
  -c "SELECT source, event_type, count(*) FROM events GROUP BY source, event_type ORDER BY source, event_type;"

PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -d detection \
  -c "SELECT source, count(*) FROM parse_failures GROUP BY source ORDER BY source;"
```

Postgres is published on host port `5433` to avoid a local Postgres on
`5432`. The default DSN in the normalizer uses `5432`, so pass the `-pg`
value above when connecting to this compose setup.

## How the phases work

### Phase 1 — raw ingestion

1. `make up` starts Postgres 16 and Vector, then uses `rpk` inside the
   existing `redpanda` container to create `auth.raw`, `auditd.raw`, and
   `dns.raw` if they do not exist.
2. Vector tails files under `lab/data/`, attaches source and host metadata,
   and sends each log line to its topic.
3. `make attack SCENARIO=1` appends an SSH brute-force scenario to
   `lab/data/auth.log`. Use `make attack SCENARIO=2` through `5` for the
   other scenarios, or `make benign SECONDS=30` for benign activity.
4. `make consumer` runs `cmd/consumer`. It stores the untouched log line,
   source, host, Kafka topic/partition/offset, receive time, and a JSON
   payload when applicable in `raw_events`.
5. Kafka offsets are committed only after the database batch is written.
   The unique Kafka-coordinate constraint makes replayed records safe, and
   `ingest_watermarks` provides a quick per-partition progress check.

### Phase 2 — normalization and entity extraction

Run `go run ./cmd/normalizer -pg "<Postgres DSN>"` after Phase 1 has begun
writing raw rows. The normalizer:

- polls `raw_events` in ascending ID batches, tracking progress in
  `normalizer_cursor`;
- dispatches each row to its source parser in `internal/parse`;
- writes common-schema records to `events`, referencing entities by stable,
  deterministic IDs in `entities`;
- prevents duplicate normalized events with a unique `dedup_key`; and
- records unparseable or unsupported rows in `parse_failures` rather than
  stopping the batch.

Each batch's event/entity/failure writes and cursor advancement happen in one
Postgres transaction. A restart resumes from the cursor, and a transaction
that did not commit is replayed safely. For this phase the normalizer reads
from Postgres rather than consuming Kafka directly; the trade-offs are
documented in [docs/NORMALIZER_NOTES.md](./docs/NORMALIZER_NOTES.md).

The normalized event contract and current event types are documented in
[docs/EVENT_SCHEMA_V1.md](./docs/EVENT_SCHEMA_V1.md).

## Database initialization

On a fresh Postgres volume, Compose applies the SQL files in
`pipeline/schema/` in filename order:

- `001_init.sql` creates Phase 1 raw-ingestion tables.
- `002_normalize.sql` adds Phase 2 entities, events, parse failures, and the
  normalizer cursor.

Postgres only runs these initialization scripts when the data directory is
empty. If you have a volume created before Phase 2 was added, apply the
additive Phase 2 schema once:

```bash
PGPASSWORD=postgres psql -h localhost -p 5433 -U postgres -d detection \
  -f pipeline/schema/002_normalize.sql
```

## Tests

```bash
go test ./...
go vet ./...
```

The normalizer tests exercise parsing, entity extraction, replay behavior,
and cursor progress against Postgres when `TEST_DATABASE_URL` is set. To run
with the local compose database:

```bash
TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5433/detection?sslmode=disable" go test ./...
```

## Repository layout

```text
cmd/consumer/          Phase 1 Redpanda -> Postgres raw consumer
cmd/normalizer/        Phase 2 Postgres raw_events -> normalized events
internal/parse/        Source parsers, event types, entity IDs, dedup keys
pipeline/schema/       Phase 1 and additive Phase 2 SQL schemas
collector/             Vector config and an OTel Collector example
lab/                   Attack scenarios and benign log generator
docs/                  Event schema and collector/normalizer design notes
Makefile               Local compose, lab, consumer, and health workflows
```
