#!/usr/bin/env bash
# Scenario 6: benign background noise - the traffic your rules must NOT
# alert on. Run this on its own (no attack scripts) and feed the resulting
# window into the eval harness in Phase 3+ as the false-positive check.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./common.sh

DURATION_SECONDS="${1:-60}"

label_run "6" "benign_noise"
echo "[scenario 6] generating ${DURATION_SECONDS}s of benign noise ..."

end=$((SECONDS + DURATION_SECONDS))
ADMIN_IP="203.0.113.10"

while [ $SECONDS -lt $end ]; do
  case $((RANDOM % 6)) in
    0)
      log_auth "sshd[$RANDOM]: Accepted publickey for ops from $ADMIN_IP port $((30000+RANDOM%9999)) ssh2"
      ;;
    1)
      log_auth "sudo: ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/apt-get upgrade -y"
      ;;
    2)
      log_auditd "$(cat <<JSON
{"type":"EXECVE","timestamp":"$(now)","host":"lab-host-1","uid":"ops","pid":$RANDOM,"ppid":$RANDOM,"exe":"/usr/bin/apt-get","argv":["apt-get","upgrade","-y"],"parent_exe":"/bin/bash"}
JSON
)"
      ;;
    3)
      log_auditd "$(cat <<JSON
{"type":"EXECVE","timestamp":"$(now)","host":"lab-host-1","uid":"root","pid":$RANDOM,"ppid":1,"exe":"/usr/bin/restic","argv":["restic","backup","/var/www"],"parent_exe":"/usr/sbin/cron"}
JSON
)"
      ;;
    4)
      log_dns "pypi.org" "A"
      ;;
    5)
      log_dns "deb.debian.org" "A"
      ;;
  esac
  sleep "0.$((RANDOM % 9 + 1))"
done

echo "[scenario 6] done."
