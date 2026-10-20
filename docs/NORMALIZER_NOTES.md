# Normalizer design notes

## Why the normalizer reads from Postgres, not Kafka

The 6-week plan's original architecture has the normalizer as a Kafka
consumer, reading the same raw topics the Phase 1 consumer reads, with its
own consumer group and its own dead-letter *topic*.

This repo's normalizer instead polls `raw_events` directly: `SELECT ... FROM
raw_events WHERE id > $cursor ORDER BY id LIMIT $batch`, tracking progress in
`normalizer_cursor` (a single-row table holding the highest `raw_events.id`
processed).

Trade-offs, both ways:

- **What you lose**: this isn't how you'd want it to work at real scale -
  every normalizer restart does one query per poll interval against a
  growing table, and a single-row cursor means you can't easily run more
  than one normalizer instance in parallel (two instances would race on the
  same cursor row - `FOR UPDATE` in `normalizeBatch` prevents corruption but
  serializes them, not parallelizes them). At real log volumes you'd go back
  to consuming the Kafka topics directly, the way the Phase 1 consumer does,
  so the normalizer scales by adding partitions and consumer group members
  instead of racing on one row.
- **What you gain for this phase**: the normalizer's correctness - does
  parsing work, do entities resolve consistently, does a crash mid-batch
  replay safely, does cursor advancement skip past unparseable lines
  without getting stuck - is now testable with nothing but Postgres. No
  Kafka broker needs to be running to prove any of that. That's why
  `cmd/normalizer/main_test.go` can seed `raw_events` directly and assert on
  `events`/`entities`/`parse_failures` with ordinary SQL, in CI, without a
  Redpanda container.

If you want to match the original architecture exactly (and get Kafka
consumer-group experience on your resume in two places instead of one),
rewrite `normalizeBatch`'s input loop to consume `auth.raw`/`auditd.raw`/
`dns.raw` directly with `kgo.NewClient` the same way `cmd/consumer` does,
write to `events`/`entities` on a batch timer the same way, and drop
`normalizer_cursor` in favor of Kafka's own offset commits. The parsing and
entity-extraction logic in `internal/parse` doesn't change at all either
way - that separation is exactly why `internal/parse` has no Kafka or
Postgres imports.

## Why a dead-letter *table*, not a dead-letter *topic*

Same reasoning: a Postgres table (`parse_failures`) that any later tool can
`SELECT * FROM parse_failures ORDER BY created_at DESC` against is simpler
to inspect and simpler to test than a Kafka topic, and costs you nothing
functionally at this phase's volume. The property that matters - a line
that fails to parse never blocks or crashes the rest of the batch, and is
recorded with enough context to debug - holds either way.

## Why entity IDs are content hashes, not a sequence

`entities.id` is `sha256(entity_type | value)[:16]`
(`internal/parse.EntityID`), not a Postgres `SERIAL`. Three reasons:

1. **No read-before-write race.** With a sequence, two concurrent writers
   extracting the same entity ("admin") would both need to check "does this
   row exist?" before inserting, or risk two different IDs for the same
   value. With a content hash, both writers compute the same ID
   independently and `ON CONFLICT (id) DO UPDATE` just works.
2. **Replay safety.** Re-processing the same `raw_events` row (after a
   crash before the cursor advances) produces the exact same entity ID
   every time, not a new row.
3. **No coordination across processes.** A future second normalizer
   instance, or a one-off backfill script, can compute an entity's ID
   without querying anything first.

The cost: IDs aren't sequential or human-ordered, and you can't tell two
entities' insertion order from their IDs alone (`first_seen`/`last_seen`
carry that information instead).
