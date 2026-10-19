#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
source src/security.sh
if [[ -n "${QA_PYTHON:-}" ]]; then python3() { "$QA_PYTHON" "$@"; }; fi
unset SSH_CONNECTION
ss() {
 cat <<'EOF'
LISTEN 0 128 127.0.0.1:6010 0.0.0.0:* users:(("sshd",pid=20,fd=5))
LISTEN 0 4096 0.0.0.0:48522 0.0.0.0:* users:(("systemd",pid=1,fd=90))
LISTEN 0 4096 [::]:48522 [::]:* users:(("systemd",pid=1,fd=91))
EOF
}
sshd() { printf 'port 22\n'; }
systemctl() { printf 'Listen=[::]:48522 (Stream)\n'; }
actual="$(rn_ssh_ports)"
[[ "$actual" == 48522 ]] || { echo "FAIL expected SSH 48522, got $actual"; exit 1; }
echo PASS_ssh_socket_port_without_x11_or_inactive_22
