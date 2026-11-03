-- Phase 3 schema: detection output and threat indicators.
-- Events and entities remain owned by Phase 2; the detector reads them only.

CREATE TABLE IF NOT EXISTS iocs (
    id          BIGSERIAL PRIMARY KEY,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    confidence  TEXT NOT NULL DEFAULT 'medium'
                CHECK (confidence IN ('high', 'medium', 'low')),
    context     TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    UNIQUE (ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs (ioc_type, value);

CREATE TABLE IF NOT EXISTS alerts (
    id                  BIGSERIAL PRIMARY KEY,
    alert_time          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source              TEXT NOT NULL CHECK (source IN ('rule', 'ioc')),
    rule_id             TEXT,
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    attack_techniques   JSONB NOT NULL DEFAULT '[]',
    host                TEXT NOT NULL,
    event_id            BIGINT NOT NULL REFERENCES events(id),
    group_key           TEXT,
    evidence_event_ids  JSONB NOT NULL DEFAULT '[]',
    entities            JSONB NOT NULL DEFAULT '{}',
    confidence          TEXT,
    details             JSONB NOT NULL DEFAULT '{}',
    dedup_key           TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_host_time ON alerts (host, alert_time);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS alert_cursor (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_event_id   BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO alert_cursor (id, last_event_id)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
