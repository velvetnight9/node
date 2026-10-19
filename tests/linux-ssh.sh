#!/bin/bash
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || exit 1
source /source/src/security.sh
export SSH_CONNECTION='10.99.0.77 43123 10.99.0.1 22'
logger -t sshd 'Accepted publickey for root from 10.99.0.77 port 43123 ssh2'
if rn_ssh_verified_key; then echo QA_FAIL_forged_sshd_tag_accepted; exit 1; fi
echo QA_PASS_forged_sshd_tag_rejected
install -d -m 700 /root/qa-ssh-test
install -d -m 755 /run/sshd
chmod 755 /run/sshd
if [[ ! -e /root/qa-ssh-test/key ]]; then ssh-keygen -q -t ed25519 -N '' -f /root/qa-ssh-test/key; fi
cp /root/qa-ssh-test/key.pub /root/qa-ssh-test/authorized_keys
chmod 600 /root/qa-ssh-test/authorized_keys
usermod -p "$(openssl rand -hex 24 | openssl passwd -6 -stdin)" root
/usr/sbin/sshd -p 24023 -o PidFile=/run/qa-key-sshd.pid -o AuthorizedKeysFile=/root/qa-ssh-test/authorized_keys -o PasswordAuthentication=no -o UsePAM=yes
trap 'kill "$(cat /run/qa-key-sshd.pid)" 2>/dev/null || true' EXIT
unset SSH_CONNECTION
ssh -i /root/qa-ssh-test/key -p 24023 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 'source /source/src/security.sh; rn_ssh_verified_key || exit 13; RN_BACKUP=$(mktemp -d /root/qa-ssh-backup.XXXXXX); mkdir -p "$RN_BACKUP/etc"; cp -a /etc/ssh "$RN_BACKUP/etc/"; rn_ssh_harden; sshd -T | grep -qx "passwordauthentication no"; echo QA_PASS_real_key_session_verified_and_password_disabled'
echo ALL_SSH_QA_PASSED
