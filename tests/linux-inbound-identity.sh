#!/bin/bash
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || exit 1
source /source/src/security.sh
NODE_PORT=9744
cat >/tmp/qa-inbound-identity.py <<'PY'
import ctypes,socket,sys,time
ctypes.CDLL(None).prctl(15,b'rw-core',0,0,0)
s=socket.socket();s.bind(('0.0.0.0',int(sys.argv[1])));s.listen()
time.sleep(90)
PY
chmod 644 /tmp/qa-inbound-identity.py
python3 /tmp/qa-inbound-identity.py 55202 & ROOT_CORE=$!
setpriv --reuid=65534 --regid=65534 --clear-groups python3 /tmp/qa-inbound-identity.py 55203 & UNTRUSTED=$!
trap 'kill "$ROOT_CORE" "$UNTRUSTED" 2>/dev/null || true' EXIT
sleep 1
ports="$(rn_discover_public_inbounds)"
grep -qx 'tcp 55202' <<<"$ports"
if grep -qx 'tcp 55203' <<<"$ports"; then echo QA_FAIL_unprivileged_process_accepted; exit 1; fi
echo QA_PASS_only_root_owned_xray_listener_accepted
