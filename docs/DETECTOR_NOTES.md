# Detector notes

The detector polls the Phase 2 `events` table rather than consuming Kafka.
It joins entity values for readable matching and alert context, evaluates the
configured rules, checks exact IP/domain IOC values, writes alerts, and
advances the single-row `alert_cursor`. Alert writes and cursor advancement
share one Postgres transaction; a failed batch therefore rolls back and can
be retried. Unique deduplication keys make repeated processing safe.

Aggregated rules use fixed UTC-aligned buckets, not a true sliding window.
The query counts events for the one validated `event_type` selection and
group entity. Rule alerts identify the triggering event and include up to 20
evidence IDs. IOC alerts are per matching event and indicator.

The cursor makes the service simple to restart but serializes detector
instances. Scale-out with independent partitions and consumer groups is
intentionally outside this phase. Apply `pipeline/schema/003_detect.sql`
before starting the detector against an existing database; fresh Compose
volumes apply it automatically.
