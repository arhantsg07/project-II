#!/usr/bin/env bash
# Shared helpers for lab scripts. Source this, don't run it directly.
set -euo pipefail

LAB_DATA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/data" && pwd)"
AUTH_LOG="$LAB_DATA_DIR/auth.log"
AUDITD_LOG="$LAB_DATA_DIR/auditd.log"
DNS_LOG="$LAB_DATA_DIR/dns.log"

mkdir -p "$LAB_DATA_DIR"
touch "$AUTH_LOG" "$AUDITD_LOG" "$DNS_LOG"

now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# log_auth <message>
# Appends an auth.log-style line (mimics sshd/sudo syslog format).
log_auth() {
  echo "$(date '+%b %e %H:%M:%S') lab-host-1 $1" >> "$AUTH_LOG"
}

# log_auditd <json>
# Appends one auditd-style JSON line. Keep these as single-line JSON so the
# Phase 2 normalizer can parse them directly.
log_auditd() {
  printf '%s\n' "$1" >> "$AUDITD_LOG"
}

# log_dns <query> <qtype>
log_dns() {
  printf '%s client=%s query=%s type=%s\n' "$(now)" "127.0.0.1" "$1" "${2:-A}" >> "$DNS_LOG"
}

label_run() {
  # label_run <scenario_id> <scenario_name>
  # Writes a label file so Phase 3+ evaluation scripts can line up ground
  # truth with what landed in Postgres.
  local id="$1" name="$2"
  local label_dir="$LAB_DATA_DIR/labels"
  mkdir -p "$label_dir"
  local start
  start="$(now)"
  cat > "$label_dir/scenario-${id}-$(date +%s).json" <<JSON
{
  "scenario_id": "$id",
  "scenario_name": "$name",
  "start_time": "$start",
  "host": "lab-host-1"
}
JSON
}
