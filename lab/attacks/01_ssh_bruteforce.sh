#!/usr/bin/env bash
# Scenario 1: SSH brute force followed by a successful login.
# ATT&CK: T1110 (Brute Force)
#
# Writes synthetic auth.log lines that look like real sshd/syslog output.
# Nothing here actually attempts an SSH connection - it simulates what the
# log lines would say, which is all the pipeline needs to detect it on.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./common.sh

label_run "1" "ssh_bruteforce"

USERS=(root admin deploy ubuntu postgres)
ATTACKER_IP="198.51.100.23"

echo "[scenario 1] simulating SSH brute force from $ATTACKER_IP ..."

for i in $(seq 1 12); do
  user="${USERS[$((RANDOM % ${#USERS[@]}))]}"
  log_auth "sshd[$((1000+i))]: Failed password for $user from $ATTACKER_IP port $((40000+i)) ssh2"
  sleep 0.2
done

# Attacker finally gets in.
log_auth "sshd[1099]: Accepted password for root from $ATTACKER_IP port 40099 ssh2"
log_auth "sshd[1099]: pam_unix(sshd:session): session opened for user root by (uid=0)"

echo "[scenario 1] done. Check lab/data/auth.log."
