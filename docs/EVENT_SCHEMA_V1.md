# Common event schema, v1

This is the contract every parser in `internal/parse` produces, and every
later phase (rules, correlation, the AI investigator) reads against. It's
documentation, not a validated JSON Schema file - see "Why not a .json
file" at the bottom if you want to add real validation.

## Event

| Field                    | Type               | Description |
|--------------------------|--------------------|-------------|
| `id`                     | bigint             | Surrogate key, `events.id` |
| `raw_event_id`            | bigint             | FK to the `raw_events` row this came from - always traceable back to the original line |
| `event_time`              | timestamptz        | See "On event_time" below |
| `source`                  | text               | `auth` \| `auditd` \| `dns` |
| `host`                    | text               | Hostname that produced the event |
| `event_type`              | text               | See "Event types" below |
| `outcome`                 | text, nullable     | `success` \| `failure` \| null if not applicable |
| `user_entity`             | text, nullable     | FK to `entities.id`, role = user |
| `process_entity`          | text, nullable     | FK to `entities.id`, role = the process that did this |
| `parent_process_entity`   | text, nullable     | FK to `entities.id`, role = that process's parent |
| `src_ip_entity`           | text, nullable     | FK to `entities.id`, role = source IP |
| `domain_entity`           | text, nullable     | FK to `entities.id`, role = DNS query target |
| `fields`                  | jsonb              | Event-type-specific extras: `pid`, `ppid`, `argv`, `port`, `auth_method`, `query_type`, `path`, ... |
| `dedup_key`               | text               | `sha256(source \| host \| raw_line \| event_time truncated to the minute)` - unique, collapses exact repeats |

## Entity

| Field         | Type        | Description |
|---------------|-------------|--------------|
| `id`          | text        | `sha256(entity_type \| value)[:16]` - deterministic, see `internal/parse.EntityID` |
| `entity_type` | text        | `host` \| `user` \| `process_image` \| `ip` \| `domain` |
| `value`       | text        | The raw value: a username, an exe path, an IP, a domain |
| `first_seen` / `last_seen` | timestamptz | Updated on every event that references this entity |

`process_image` identifies a *binary* (`/bin/bash`), not one running process
instance. Two different invocations of bash on the same host resolve to the
same entity. That's intentional for this phase - "has this host ever run
nc?" is a more useful question right now than "is this the same OS process
as five minutes ago". Per-invocation process identity (keyed by host + pid +
start time) is a reasonable Phase 3/4 extension once correlation needs it.

## Event types (v1)

| `event_type`           | Produced by | Key fields set |
|-------------------------|-------------|----------------|
| `auth.login_failure`    | auth        | user, src_ip, fields.port |
| `auth.login_success`    | auth        | user, src_ip, fields.auth_method, fields.port |
| `auth.session_opened`   | auth        | user |
| `auth.sudo`             | auth        | user, fields.command, fields.run_as |
| `auth.unrecognized`     | auth        | fields.message (line matched the syslog envelope but no known pattern) |
| `process.exec`          | auditd      | user, process, parent_process, fields.argv |
| `file.read`             | auditd      | user, process, fields.path |
| `file.write`            | auditd      | user, process, fields.path |
| `dns.query`             | dns         | src_ip, domain, fields.query_type |

Adding a new event type means adding a case to the relevant parser and a row
to this table - nothing downstream needs to change its schema, since
`fields` is JSONB.

## On `event_time`

Auth log lines carry a syslog-style timestamp with no year
(`Oct 18 10:27:08`). Rather than guess the year or require a trusted,
synced host clock (this is a lab), `ParseAuth` uses
`raw_events.received_at` - the time the Phase 1 consumer wrote the row - as
the event's time. DNS and auditd lines carry their own RFC3339 timestamp and
use that instead, falling back to `received_at` if it's missing or
unparseable. In a real deployment with properly configured, synced hosts,
swap this for the host's actual timestamp (with the year problem solved via
NTP-synced ingestion time proximity, which is the standard syslog fix).

## Why not a validated `.json` JSON Schema file

A real JSON Schema file (with `$schema`, `type: object`, `required`, etc.)
would let you validate events mechanically rather than just by reading this
doc and the Go structs. That's a reasonable thing to add once a second
consumer of this schema exists outside this repo (e.g. if the AI
investigator in Phase 5 calls an external service that wants to validate
its own tool-call outputs against it). For now, `internal/parse` and this
doc are the schema's two sources of truth, and the golden-file tests in
`internal/parse/testdata/` double as the schema's regression suite.
