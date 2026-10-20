# Collector notes

Phase 1 uses [Vector](https://vector.dev) reading three flat files that the
lab scripts write to (`lab/data/auth.log`, `auditd.log`, `dns.log`), tagging
each line with `host` and `source`, and shipping it to a matching Redpanda
topic (`auth.raw`, `auditd.raw`, `dns.raw`).

In the local setup, Vector runs with host networking and connects to the
already-running Redpanda broker at `localhost:9092`. This matches the
broker's advertised Kafka address; pointing a containerized Vector at a
different bootstrap address would still send it back the advertised address
when it requests broker metadata.

## Why flat files instead of a real second host

The portfolio plan calls for 2 lab hosts. Running an actual second VM/
container with real auditd and sshd adds real setup cost (kernel audit
rules, syslog forwarding, SSH key provisioning) that doesn't change what the
rest of the pipeline looks like. Starting with files that *look like* real
log output lets you build and test the collector -> stream -> consumer path
in minutes, and the lab scripts double as your reproducible attack/eval
suite (see `lab/attacks/`).

## Swapping in a real second host later

When you're ready (or if you want the extra realism for your portfolio),
change only the `sources` block in `collector/vector.yaml`:

```yaml
sources:
  auth_log:
    type: file
    include:
      - /var/log/auth.log       # real sshd/sudo syslog on the host
  auditd_log:
    type: file
    include:
      - /var/log/audit/audit.log
  dns_log:
    type: file
    include:
      - /var/log/dnsmasq.log    # or wherever your DNS server logs queries
```

Run Vector as an agent on that host (not in the lab's Docker Compose),
pointing `bootstrap_servers` at wherever Redpanda is reachable from there.
Nothing downstream of Vector (the topics, the consumer, the schema) needs to
change - that's the point of putting Redpanda in the middle.

## Why Vector over the OpenTelemetry Collector

The original architecture diagram names OpenTelemetry Collector. Vector was
swapped in for the portfolio version because its config is shorter to read
and write for log-shipping specifically (OTel Collector is built around a
more general and more verbose receiver/processor/exporter pipeline meant for
traces and metrics too). If you'd rather match the diagram exactly, or you
want OTel Collector experience on your resume instead, see
`collector/otel-collector.yaml.example` for an equivalent starting point and
swap the `vector` service in `docker-compose.yml` for an
`otel/opentelemetry-collector-contrib` image.
