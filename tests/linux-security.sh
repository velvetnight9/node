#!/bin/bash
# Только для одноразовой привилегированной Linux QA-среды, не для production.
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || { echo 'Нужна отдельная QA VM'; exit 1; }
source /source/src/security.sh
fail() { echo "QA_FAIL $*"; exit 1; }
pass() { echo "QA_PASS $*"; }
mkdir -p /run/sshd
chmod 755 /run/sshd
chown root:root /run/sshd
ssh-keygen -A
systemctl stop ssh.service || true
cat >/etc/ssh/sshd_config <<'EOF'
Port 24022
ListenAddress 0.0.0.0
ListenAddress ::
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
EOF
systemctl start ssh.service
install -d -m 700 /root/qa-ssh-test
[[ -e /root/qa-ssh-test/key ]] || ssh-keygen -q -t ed25519 -N '' -f /root/qa-ssh-test/key
export SSH_PUBLIC_KEY="$(cat /root/qa-ssh-test/key.pub)" SSH_PORT=24022
ip netns add qa-peer
ip link add qa-node type veth peer name qa-client
ip link set qa-client netns qa-peer
ip addr add 10.77.0.1/24 dev qa-node
ip -6 addr add fd77::1/64 dev qa-node nodad
ip link set qa-node up
ip netns exec qa-peer ip link set lo up
ip netns exec qa-peer ip link set qa-client up
for n in 2 3 4 5; do
  ip netns exec qa-peer ip addr add "10.77.0.$n/24" dev qa-client
  ip netns exec qa-peer ip -6 addr add "fd77::$n/64" dev qa-client nodad
done
cat >/tmp/qa-listeners.py <<'PY'
import socket,threading,time
def listener(port):
 s=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);s.bind(('::',port));s.listen()
 while True:
  c,_=s.accept();c.close()
for port in (9744,18080):threading.Thread(target=listener,args=(port,),daemon=True).start()
time.sleep(3600)
PY
python3 /tmp/qa-listeners.py & LISTENER=$!
cleanup() {
 kill "$LISTENER" ${XRAY_FIXTURE:-} ${BACKEND_FIXTURE:-} 2>/dev/null || true
 if test -f /run/qa-sshd.pid; then kill "$(cat /run/qa-sshd.pid)" || true; fi
 nft delete table ip qa_dnat 2>/dev/null || true
 ip netns del qa-backend 2>/dev/null || true
 ip netns del qa-peer || true
}
trap cleanup EXIT
sleep 1
probe() {
 ip netns exec qa-peer python3 - "$1" "$2" "$3" "${4:-.7}" <<'PY'
import socket,sys
source,target,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
s=socket.socket(socket.AF_INET6 if ':' in source else socket.AF_INET);s.settimeout(float(sys.argv[4]));s.bind((source,0))
try:s.connect((target,port))
except OSError as e:
 print('PROBE',source,target,port,repr(e),file=sys.stderr);raise SystemExit(1)
finally:s.close()
PY
}
# Пакеты установлены образом QA; повторный apt не является частью проверки.
apt-get() { :; }; export -f apt-get
export NODE_PORT=9744 PANEL_IPS='10.77.0.2 fd77::2' SSH_CONNECTION='10.99.0.10 43210 10.77.0.1 24022'
export RN_ROLE=cdn
ufw allow 9744/tcp
ufw allow 3000/tcp
ufw allow 3001/tcp
ufw allow 18080/tcp
printf '[DEFAULT]\nbantime = 2h\n' >/etc/fail2ban/jail.local
original_jail=$(sha256sum /etc/fail2ban/jail.local)
rn_security
probe 10.77.0.2 10.77.0.1 9744 || fail panel_ipv4
! probe 10.77.0.3 10.77.0.1 9744 || fail outsider_ipv4
probe fd77::2 fd77::1 9744 || fail panel_ipv6
! probe fd77::3 fd77::1 9744 || fail outsider_ipv6
probe 10.77.0.3 10.77.0.1 24022 || fail ssh_retained
[[ "$original_jail" == "$(sha256sum /etc/fail2ban/jail.local)" ]] || fail jail_local_changed
sshd -T | grep 'passwordauthentication no' >/dev/null || fail password_not_disabled
pass panel_only_both_families_and_ssh_retained
cat >/tmp/qa-public-xray.py <<'PY'
import ctypes,socket,threading,time
ctypes.CDLL(None).prctl(15,b'rw-core',0,0,0)
def listener(host,port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((host,port));s.listen()
 while True:
  c,_=s.accept();c.close()
for host,port in [('0.0.0.0',24443),('127.0.0.1',7443)]:threading.Thread(target=listener,args=(host,port),daemon=True).start()
time.sleep(3600)
PY
python3 /tmp/qa-public-xray.py & XRAY_FIXTURE=$!
sleep 1
/usr/local/sbin/remnanode-sync-inbounds
probe 10.77.0.4 10.77.0.1 24443 || fail telegram_inbound_not_opened
! LC_ALL=C ufw status | grep -q '7443' || fail local_xhttp_exposed
pass public_telegram_24443_opened_without_local_xhttp
rules1=$(LC_ALL=C ufw status numbered | grep -c remnanode-managed)
rn_security
rules2=$(LC_ALL=C ufw status numbered | grep -c remnanode-managed)
[[ "$rules1" == "$rules2" ]] || fail duplicate_rules
pass repeat_is_idempotent
# Ранний ACCEPT UFW не должен обходить отдельный nft guard.
sed -i '/^COMMIT$/i -A ufw-before-input -p tcp --dport 9744 -j ACCEPT' /etc/ufw/before.rules
ufw reload
! probe 10.77.0.3 10.77.0.1 9744 || fail before_rules_bypass
pass ufw_before_rules_bypass_blocked
export PANEL_IPS='10.77.0.3 fd77::3'
rn_security
probe 10.77.0.3 10.77.0.1 9744 || fail new_panel_ipv4
! probe 10.77.0.2 10.77.0.1 9744 || fail old_panel_ipv4
probe fd77::3 fd77::1 9744 || fail new_panel_ipv6
! probe fd77::2 fd77::1 9744 || fail old_panel_ipv6
pass panel_ip_rotation
fail2ban-client set sshd banip 10.77.0.4
! probe 10.77.0.4 10.77.0.1 24022 || fail ssh_ban_not_active
probe 10.77.0.4 10.77.0.1 18080 || fail fail2ban_banned_other_ports
fail2ban-client set sshd unbanip 10.77.0.4
probe 10.77.0.4 10.77.0.1 24022 || fail ssh_unban
fail2ban-client set sshd banip fd77::4
! probe fd77::4 fd77::1 24022 || fail ssh_ipv6_ban
probe fd77::4 fd77::1 18080 || fail ipv6_ban_other_ports
fail2ban-client set sshd unbanip fd77::4
pass fail2ban_bans_ssh_only
# Проверяем published Docker-подобный DNAT, обходящий обычный UFW INPUT.
ip netns add qa-backend
ip link add qa-bridge type veth peer name qa-container
ip link set qa-container netns qa-backend
ip addr add 10.88.0.1/24 dev qa-bridge
ip link set qa-bridge up
ip netns exec qa-backend ip link set lo up
ip netns exec qa-backend ip link set qa-container up
ip netns exec qa-backend ip addr add 10.88.0.2/24 dev qa-container
ip netns exec qa-backend ip route add default via 10.88.0.1
ip netns exec qa-backend python3 -m http.server 19744 --bind 10.88.0.2 >/tmp/backend.log 2>&1 & BACKEND_FIXTURE=$!
sysctl -w net.ipv4.ip_forward=1
ufw route allow proto tcp from 10.77.0.0/24 to 10.88.0.2 port 19744
nft -f - <<'NFT'
table ip qa_dnat {
 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
  iifname "qa-node" tcp dport 9744 dnat to 10.88.0.2:19744
 }
}
NFT
for attempt in $(seq 1 30); do
 ip netns exec qa-backend ss -H -ltn 'sport = :19744' | grep -q . && break
 sleep .2
done
dnat_ready=0
for attempt in $(seq 1 10); do
 if probe 10.77.0.3 10.77.0.1 9744 3; then dnat_ready=1; break; fi
 sleep .2
done
[[ "$dnat_ready" == 1 ]] || fail dnat_panel
! probe 10.77.0.2 10.77.0.1 9744 || fail dnat_outsider
nft delete table ip qa_dnat
pass published_control_port_dnat_restricted_to_panel
# Ошибка применения новых правил должна вернуть предыдущую рабочую политику.
cp /etc/remnanode-security/control.nft /tmp/control-known-good.nft
rn_prepare
rn_backup
rn_control_config() { echo 'THIS IS INVALID NFT'; }
set +e
(rn_firewall)
repair_rc=$?
set -e
[[ "$repair_rc" != 0 ]] || fail invalid_nft_was_accepted
cmp -s /tmp/control-known-good.nft /etc/remnanode-security/control.nft || fail rollback_config
probe 10.77.0.3 10.77.0.1 9744 || fail rollback_panel
! probe 10.77.0.2 10.77.0.1 9744 || fail rollback_outsider
probe 10.77.0.4 10.77.0.1 24022 || fail rollback_ssh
pass apply_failure_rolls_back
unset -f rn_control_config
# Тот же механизм вызывается стандартным установщиком, без переустановки ноды.
bash /source/install.sh --repair
probe 10.77.0.3 10.77.0.1 9744 || fail standard_repair_panel
pass standard_existing_node_security_path
printf '\nALL_SECURITY_QA_PASSED\n'
