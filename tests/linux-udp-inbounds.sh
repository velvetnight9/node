#!/bin/bash
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || exit 1
source /source/src/security.sh
NODE_PORT=9744
cat >/tmp/qa-udp-config.json <<'EOF'
{"inbounds":[{"port":55101,"listen":"0.0.0.0","protocol":"hysteria","streamSettings":{"network":"hysteria"}}]}
EOF
cat >/tmp/qa-udp-inbounds.py <<'PY'
import ctypes,socket,time
ctypes.CDLL(None).prctl(15,b'rw-core',0,0,0)
sockets=[]
for port in (55101,55102):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port));sockets.append(s)
time.sleep(90)
PY
python3 /tmp/qa-udp-inbounds.py -config /tmp/qa-udp-config.json & CORE=$!
trap 'kill "$CORE" 2>/dev/null || true' EXIT
sleep 1
ports="$(rn_discover_public_inbounds)"
grep -qx 'udp 55101' <<<"$ports"
if grep -qx 'udp 55102' <<<"$ports"; then echo QA_FAIL_ephemeral_udp_accepted;exit 1;fi
echo QA_PASS_configured_udp_only_without_ephemeral_outbound_sockets
