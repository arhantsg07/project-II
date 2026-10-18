#!/usr/bin/env bash
# Scenario 3: attacker creates a new user, adds it to sudoers, then plants a
# cron job for persistence.
# ATT&CK: T1136 (Create Account), T1053 (Scheduled Task/Job)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./common.sh

label_run "3" "persistence_newuser_cron"

echo "[scenario 3] simulating new user, sudoers edit, cron persistence ..."

log_auditd "$(cat <<JSON
{"type":"EXECVE","timestamp":"$(now)","host":"lab-host-1","uid":"root","pid":5201,"ppid":5100,"exe":"/usr/sbin/useradd","argv":["useradd","-m","svc-backup"],"parent_exe":"/bin/bash"}
JSON
)"

log_auditd "$(cat <<JSON
{"type":"PATH_WRITE","timestamp":"$(now)","host":"lab-host-1","uid":"root","pid":5202,"ppid":5100,"exe":"/usr/bin/vim","path":"/etc/sudoers.d/svc-backup","argv":["vim","/etc/sudoers.d/svc-backup"],"parent_exe":"/bin/bash"}
JSON
)"

log_auth "sudo: svc-backup : TTY=pts/0 ; PWD=/home/svc-backup ; USER=root ; COMMAND=/bin/bash"

log_auditd "$(cat <<JSON
{"type":"PATH_WRITE","timestamp":"$(now)","host":"lab-host-1","uid":"svc-backup","pid":5210,"ppid":5205,"exe":"/usr/bin/crontab","path":"/var/spool/cron/crontabs/svc-backup","argv":["crontab","-e"],"parent_exe":"/bin/bash"}
JSON
)"

echo "[scenario 3] done. Check lab/data/auditd.log and lab/data/auth.log."
