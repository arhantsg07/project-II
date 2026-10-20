-- Phase 2 schema: normalization output.
--
-- raw_events (Phase 1) is never modified by this migration - the normalizer
-- only reads from it. Everything here is new, additive state built on top.

-- One row per distinct real-world thing we've seen: a host, a user, a
-- process image (an executable path, not a single running process), an IP,
-- or a domain. id is a deterministic hash of (entity_type, value) - see
-- internal/parse.EntityID - so the same entity always gets the same id,
-- across restarts and across re-processing, with no shared sequence or
-- coordination needed.
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,            -- 'host' | 'user' | 'process_image' | 'ip' | 'domain'
    value       TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_entities_type_value ON entities (entity_type, value);

-- One row per successfully parsed event, in the common schema (see
-- docs/EVENT_SCHEMA_V1.md). Each *_entity column is a foreign key into
-- entities and is NULL when that role doesn't apply to this event
-- (e.g. a DNS query has no user_entity).
CREATE TABLE IF NOT EXISTS events (
    id                     BIGSERIAL PRIMARY KEY,
    raw_event_id           BIGINT NOT NULL REFERENCES raw_events(id),
    event_time             TIMESTAMPTZ NOT NULL,
    source                 TEXT NOT NULL,
    host                   TEXT NOT NULL,
    event_type             TEXT NOT NULL,     -- e.g. 'auth.login_failure', 'process.exec', 'dns.query'
    outcome                TEXT,              -- 'success' | 'failure' | NULL if not applicable
    user_entity            TEXT REFERENCES entities(id),
    process_entity         TEXT REFERENCES entities(id),
    parent_process_entity  TEXT REFERENCES entities(id),
    src_ip_entity          TEXT REFERENCES entities(id),
    domain_entity          TEXT REFERENCES entities(id),
    fields                 JSONB NOT NULL DEFAULT '{}',  -- event-type-specific extras (port, pid, argv, ...)
    dedup_key              TEXT NOT NULL,     -- content hash + time bucket; see internal/parse.DedupKey
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_events_host_time ON events (host, event_time);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events (event_type, event_time);
CREATE INDEX IF NOT EXISTS idx_events_user_entity ON events (user_entity);
CREATE INDEX IF NOT EXISTS idx_events_process_entity ON events (process_entity);
CREATE INDEX IF NOT EXISTS idx_events_src_ip_entity ON events (src_ip_entity);
CREATE INDEX IF NOT EXISTS idx_events_domain_entity ON events (domain_entity);

-- Anything the normalizer could not parse lands here instead of crashing
-- the batch or silently vanishing. This is this portfolio project's
-- dead-letter mechanism: a table, not a separate Kafka topic, because the
-- normalizer reads from Postgres (see docs/NORMALIZER_NOTES.md for why).
CREATE TABLE IF NOT EXISTS parse_failures (
    id            BIGSERIAL PRIMARY KEY,
    raw_event_id  BIGINT NOT NULL REFERENCES raw_events(id),
    source        TEXT NOT NULL,
    error         TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single-row progress marker: the highest raw_events.id the normalizer has
-- processed (successfully or not - a parse failure still advances the
-- cursor, so one bad line can never block the pipeline). This plays the
-- same role ingest_watermarks plays for the Phase 1 consumer, but keyed off
-- a Postgres primary key instead of a Kafka offset, since the normalizer's
-- input is raw_events, not a topic.
CREATE TABLE IF NOT EXISTS normalizer_cursor (
    id                SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- enforces exactly one row
    last_raw_event_id BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO normalizer_cursor (id, last_raw_event_id)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
