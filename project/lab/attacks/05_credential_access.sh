#!/usr/bin/env bash
# Scenario 5: attacker reads /etc/shadow, then moves laterally over SSH to
# another host using harvested credentials.
# ATT&CK: T1003 (OS Credential Dumping), T1021 (Remote Services)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./common.sh

label_run "5" "credential_access_lateral_ssh"

echo "[scenario 5] simulating /etc/shadow read + lateral SSH ..."

log_auditd "$(cat <<JSON
{"type":"PATH_READ","timestamp":"$(now)","host":"lab-host-1","uid":"www-data","pid":6001,"ppid":5999,"exe":"/bin/cat","path":"/etc/shadow","argv":["cat","/etc/shadow"],"parent_exe":"/bin/bash"}
JSON
)"

log_auth "sshd[6050]: Accepted publickey for root from 10.0.0.15 port 51322 ssh2"
log_auth "sshd[6050]: pam_unix(sshd:session): session opened for user root by (uid=0)"

echo "[scenario 5] done. Check lab/data/auditd.log and lab/data/auth.log."
