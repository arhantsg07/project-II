# Detection rule notes

The rule package is pure Go: it loads top-level YAML rules, validates them,
and matches an in-memory projection of one normalized event. Rule conditions
within a selection are ANDed; selections in a rule are ORed. This keeps the
matcher fast and unit-testable without Postgres.

## Supported fields

`event_type`, `outcome`, `host`, `user`, `process`, `parent_process`,
`src_ip`, and `domain` compare exact strings. `argv_contains` looks for a
substring in any argument; `command_contains` looks within the event's
`command` field; `path` is an exact match; and `path_regex` applies a Go
regular expression to `fields.path`. `domain_entropy_gte` compares a numeric
threshold against Shannon entropy calculated over the DNS name's leftmost
label.

The loader rejects unknown YAML fields and selection keys, invalid regexes,
empty selections, invalid severity values, and malformed aggregation
settings before the detector starts.

## Aggregation boundary

Aggregation is intentionally a single event-type count over a fixed,
UTC-aligned time bucket, grouped by one of `src_ip`, `user`, `domain`,
`process`, or `host`. Only one selection containing only `event_type` is
allowed for an aggregated rule; this ensures the SQL count and in-memory
rule match have identical meaning. Alerts are deduplicated by rule, group
value, and bucket; evidence is capped at 20 event IDs.

This is not a sliding window, sequence correlation, or incident grouping.
Late-arriving events may not amend an alert already emitted for a bucket.
Those are deliberate limits for this phase; Phase 4 is where multi-event
correlation belongs.

## DNS entropy calibration

Entropy over an entire domain rises with label count and length and
incorrectly scores ordinary hosts such as `api.github.com` highly. The
shipped rule instead evaluates the leftmost label and uses a measured
threshold of 3.1 bits per character. Tests pin known benign hostnames below
that threshold and require at least 60% of a deterministic sample of random
20-character hex labels to exceed it. This remains a heuristic: it can miss
low-entropy or short tunnel labels and should be tuned against representative
local traffic before production use.
