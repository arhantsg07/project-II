# Replay tool notes

`cmd/replay` publishes recorded lines directly to the Redpanda/Kafka topics
used by the Phase 1 consumer: `auth.log` to `auth.raw`, `auditd.log` to
`auditd.raw`, and `dns.log` to `dns.raw`. It reads those files in a stable
order, skips absent files and blank lines, and rate-limits the combined
stream. The tool does not transform or sanitize the records.

Create a recording from the current lab files, then replay it:

```bash
mkdir -p lab/recordings/run1
cp lab/data/auth.log lab/data/auditd.log lab/data/dns.log lab/recordings/run1/
make replay DIR=lab/recordings/run1 RATE=20
```

Replaying into a consumer group already at the end of its offsets will not
cause that group to re-read old messages. Use a fresh group or reset offsets
when intentionally testing a replay, and remember that Kafka topic retention
and the database uniqueness key still apply.
