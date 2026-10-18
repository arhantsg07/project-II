#!/usr/bin/env bash
# Scenario 4: DNS tunneling - many unique, high-entropy subdomain queries to
# one parent domain, consistent with data exfiltration over DNS.
# ATT&CK: T1071.004 (DNS)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./common.sh

label_run "4" "dns_tunnel"

PARENT_DOMAIN="exfil-example.net"

echo "[scenario 4] simulating DNS tunneling to *.${PARENT_DOMAIN} ..."

rand_label() {
  # 20 pseudo-random hex chars: high entropy, looks like encoded data chunks.
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-20
}

for _ in $(seq 1 25); do
  log_dns "$(rand_label).${PARENT_DOMAIN}" "TXT"
  sleep 0.1
done

echo "[scenario 4] done. Check lab/data/dns.log."
