-- Phase 1 schema: raw events only.
-- Parsing into a normalized common schema, entity extraction, dedup, rules
-- and incidents are built in later phases, on top of this table.

CREATE TABLE IF NOT EXISTS raw_events (
    id              BIGSERIAL PRIMARY KEY,
    source          TEXT NOT NULL,           -- e.g. 'auth', 'auditd', 'dns'
    host            TEXT NOT NULL,           -- hostname that produced the log
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    kafka_topic     TEXT NOT NULL,
    kafka_partition INT NOT NULL,
    kafka_offset    BIGINT NOT NULL,
    raw_line        TEXT NOT NULL,           -- original log line, untouched
    payload         JSONB,                   -- structured version if the collector emits JSON
    UNIQUE (kafka_topic, kafka_partition, kafka_offset)
);

CREATE INDEX IF NOT EXISTS idx_raw_events_host_time ON raw_events (host, received_at);
CREATE INDEX IF NOT EXISTS idx_raw_events_source ON raw_events (source);

-- Consumer progress per partition, for an easy health check in the UI/CLI.
-- (Kafka consumer groups already track offsets; this table just makes
-- "is the pipeline keeping up" a one-line SQL query.)
CREATE TABLE IF NOT EXISTS ingest_watermarks (
    kafka_topic     TEXT NOT NULL,
    kafka_partition INT NOT NULL,
    last_offset     BIGINT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kafka_topic, kafka_partition)
);
