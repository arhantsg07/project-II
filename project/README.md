# Mini AI-Assisted Detection & Response

A 6-week, 2-person portfolio build of a scaled-down security detection and
response pipeline: attack happens on a lab host -> logs stream through
Redpanda -> land in Postgres -> (later phases) get parsed, matched against
rules/IOCs/ML, correlated into incidents, investigated by an LLM agent, and
gated through a policy engine before any action is taken.

This repo is being built in phases that match the 6-week plan. **This
README currently covers Phase 1 (Week 1: "Foundations and data in
motion")**. Later phases will extend the same repo rather than replace it.

```
lab host logs -> Vector (collector) -> Redpanda -> Go consumer -> Postgres
                                                     (raw, unparsed)
```

## Phase 1 scope

By the end of Phase 1 you can run a scripted attack, watch the log lines it
produces travel through Redpanda, and see them land as rows in Postgres,
unparsed. That's it. No rules, no parsing, no ML yet - this phase exists to
prove the data path is reliable before anything is built on top of it.

Everything in `pipeline/schema/001_init.sql`, `cmd/consumer/`,
`collector/vector.yaml`, and `lab/` is part of Phase 1.

## Prerequisites

- Docker and Docker Compose v2 (`docker compose version`)
- A running Redpanda container named `redpanda`, reachable at
  `localhost:9092` from the host, and permission to run `docker exec redpanda`
- Go 1.22+ (`go version`)
- `psql` client (optional, for `make psql` / debugging)
- `make`

## Quick start

```bash
git clone <this-repo>
cd project
cp .env.example .env

make up          # starts Postgres + Vector and creates topics in existing Redpanda
make attack SCENARIO=1   # run the SSH brute-force scenario
make consumer     # in a second terminal: starts the Go consumer (Ctrl+C to stop)
```

Give the consumer a few seconds, then in a third terminal:

```bash
make health
```

You should see rows under `source = auth` with a recent `latest` timestamp,
and a matching row in `ingest_watermarks`.
The project Postgres is published on `localhost:5433` to avoid colliding with
a Postgres service already using port 5432. Vector uses host networking to
connect to the existing Redpanda broker at `localhost:9092`.

## Step by step (what `make up` / `make attack` / `make consumer` actually do)

1. **`make up`** runs `docker compose up -d`, which starts:
   - The already-running `redpanda` container is reused, not created,
     restarted, or removed. `docker exec redpanda rpk` creates the three
     Phase 1 topics (`auth.raw`, `auditd.raw`, `dns.raw`) if missing.
   - `postgres` - Postgres 16, with `pipeline/schema/001_init.sql`
     auto-applied on first boot (via `/docker-entrypoint-initdb.d`), on host
     port 5433.
   - `vector` - tails the files under `lab/data/` and ships each line to the
     matching topic through `localhost:9092`.

2. **`make attack SCENARIO=1`** runs `lab/attacks/01_ssh_bruteforce.sh`,
   which appends realistic `sshd` log lines to `lab/data/auth.log` (12
   failed logins from one IP across several users, then one success). Vector
   is already tailing that file, so the lines flow into Redpanda within
   about a second.

3. **`make consumer`** runs `go run ./cmd/consumer`, which:
   - connects to Redpanda as consumer group `raw-ingest`,
   - reads batches of records from all three topics,
   - inserts each record into `raw_events` (source, host, the Kafka
     coordinates, the raw line, and a parsed JSON payload if the line was
     JSON),
   - commits Kafka offsets **only after** the batch is durably written to
     Postgres, so a crash between insert and commit just re-reads the same
     batch (the `UNIQUE(topic, partition, offset)` constraint plus
     `ON CONFLICT DO NOTHING` makes that replay a no-op).

4. **`make health`** is a couple of `SELECT`s: event counts per source, and
   the latest committed offset per partition, so you can tell at a glance
   whether the pipeline is keeping up.

Try the other scenarios too: `make attack SCENARIO=2` through `5`, and
`make benign SECONDS=30` for the false-positive baseline (see
`lab/attacks/` and `lab/benign/generate.sh` - each scenario is commented
with the ATT&CK techniques it represents).

## Repo layout

```
cmd/consumer/          Go consumer: Redpanda -> Postgres (raw_events)
pipeline/schema/        SQL schema, applied automatically to Postgres
collector/              Vector config (+ an OTel Collector alternative)
lab/                    Attack scenario scripts, benign generator, scratch data
docs/                   Design notes
.github/workflows/      CI: go vet/test, shellcheck
docker-compose.yml       Postgres + Vector (uses the existing Redpanda broker)
Makefile                 One-command workflows
```

## Exit criteria for Phase 1

Before moving to Phase 2 (normalization, entity extraction, schema v1),
confirm:

- [ ] All 6 attack/benign scenarios run without error and produce log lines
      (`make attack SCENARIO=1` .. `5`, `make benign SECONDS=10`).
- [ ] `make health` shows events for all three sources (`auth`, `auditd`,
      `dns`) after running all scenarios.
- [ ] Stopping and restarting the consumer (`Ctrl+C`, then `make consumer`
      again) does not create duplicate rows (check `count(*)` before and
      after; re-run `make health` and compare).
- [ ] Killing the consumer mid-batch (e.g. `kill -9` the `go run` process
      while `make attack` is producing data) and restarting it does not lose
      data: every line written to `lab/data/*.log` eventually appears in
      `raw_events`.
- [ ] `go test ./... ` passes locally (`TEST_DATABASE_URL=... make test`).
- [ ] `go vet ./...` and `shellcheck lab/**/*.sh` are clean (CI runs both).

## Troubleshooting

- **`make consumer` fails to connect**: make sure `make up` finished and
  `docker ps` shows the existing `redpanda` container running
  (`make topics` should list three topics). The
  consumer retries fetches but fails fast on an unreachable broker on
  startup - check `docker compose ps`.
- **No rows after running an attack script**: check `docker compose logs
  vector` - it should show lines being read and a Kafka ack. If Vector shows
  nothing, confirm `lab/data/auth.log` actually has new lines (the scripts
  must be run from the repo root or via `make attack`, not from inside
  `lab/attacks/`).
- **`go: github.com/... unrecognized import path`**: your network is
  blocking `proxy.golang.org`. Set `GOPROXY=direct GOSUMDB=off` and retry;
  see `go.mod`'s `replace` line for the one package (`golang.org/x/crypto`)
  that also needed redirecting to its GitHub mirror in a similarly
  restricted sandbox.

## What's next (Phase 2 preview)

Phase 2 adds a Go normalizer that parses `raw_events` into a common schema
(host/user/process/ip/domain entities with stable IDs), deduplicates, and
writes to a new `events` table that Phase 3's rule engine reads from. See
the full 6-week plan for the complete phase breakdown.
