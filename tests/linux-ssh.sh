#!/bin/bash
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || exit 1
source /source/src/security.sh
export SSH_CONNECTION='10.99.0.77 43123 10.99.0.1 22'
logger -t sshd 'Accepted publickey for root from 10.99.0.77 port 43123 ssh2'
if rn_ssh_verified_key; then echo QA_FAIL_forged_sshd_tag_accepted; exit 1; fi
echo QA_PASS_forged_sshd_tag_rejected
(
 unset SSH_PUBLIC_KEY RN_SSH_KEY_READY
 rn_ssh_verified_key() { return 1; }
 rn_ask() { return 1; }
 if rn_ssh_key_prepare; then echo QA_FAIL_missing_key_silently_accepted;exit 1;fi
 echo QA_PASS_missing_key_stops_installation
)
install -d -m 700 /root/qa-ssh-test
install -d -m 755 /run/sshd
chmod 755 /run/sshd
if [[ ! -e /root/qa-ssh-test/key ]]; then ssh-keygen -q -t ed25519 -N '' -f /root/qa-ssh-test/key; fi
cp /root/qa-ssh-test/key.pub /root/qa-ssh-test/authorized_keys
chmod 600 /root/qa-ssh-test/authorized_keys
usermod -p "$(openssl rand -hex 24 | openssl passwd -6 -stdin)" root
systemctl stop ssh.service
cat >/etc/ssh/sshd_config <<'EOF'
Port 24023
AuthorizedKeysFile /root/qa-ssh-test/authorized_keys
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
UsePAM yes
EOF
systemctl start ssh.service
unset SSH_CONNECTION SSH_PUBLIC_KEY RN_SSH_KEY_READY
ssh -i /root/qa-ssh-test/key -p 24023 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 'source /source/src/security.sh; rn_ssh_verified_key || exit 13; SSH_PORT=24024; RN_OLD_SSH_PORTS=24023; RN_ADMIN_IP=127.0.0.1; RN_BACKUP=$(mktemp -d /root/qa-ssh-backup.XXXXXX); mkdir -p "$RN_BACKUP/etc"; cp -a /etc/ssh "$RN_BACKUP/etc/"; ufw allow 24024/tcp; rn_ssh_harden; sshd -T | grep "passwordauthentication no" >/dev/null; echo QA_PASS_real_key_session_verified_and_port_moved'
ssh -i /root/qa-ssh-test/key -p 24024 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 'echo QA_PASS_new_key_session_on_requested_port'
if ssh -p 24024 -o BatchMode=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 true 2>/tmp/qa-password-rejected; then exit 1; fi
grep 'Permission denied (publickey)' /tmp/qa-password-rejected >/dev/null
echo QA_PASS_password_authentication_not_offered
echo ALL_SSH_QA_PASSED
