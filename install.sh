#!/usr/bin/env bash
#
# Развёртывание Remnawave-ноды:
#   Docker + нода + nginx-маскировка (127.0.0.1:8443)
#   + hardening (SSH-порт, UFW, fail2ban, traffic-guard)
#   + Psiphon SOCKS egress для Gemini/Google
#   + динамический eBPF-шейпинг трафика по IP
#
# ВСЕ данные спрашиваются в начале — дальше установка идёт без участия.
#
# Запуск:
#   curl -fsSL "RAW_URL" | sudo bash
#
set -Eeuo pipefail

# BEGIN SHARED SECURITY
# Общая часть трёх автономных установщиков. Собирается build.py.
rn_info() { printf '→ %s\n' "$*"; }
rn_die() { printf 'Ошибка: %s\n' "$*" >&2; return 1; }
rn_ask() {
  local key="$1" prompt="$2" default="${3:-}" answer
  [[ -n "${!key:-}" ]] && return 0
  [[ -r /dev/tty ]] || { rn_die "Задайте $key через окружение или запустите из терминала"; return 1; }
  printf '%s%s: ' "$prompt" "${default:+ [$default]}" >/dev/tty
  IFS= read -r answer </dev/tty
  printf -v "$key" '%s' "${answer:-$default}"
}
rn_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535)); }
rn_ensure_packages() {
  local package status missing=()
  for package in "$@"; do
    status="$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)"
    [[ "$status" == 'ii ' ]] || missing+=("$package")
  done
  if ((${#missing[@]})); then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=300 update
    apt-get -o DPkg::Lock::Timeout=300 install -y "${missing[@]}"
  fi
}
rn_ips() {
  python3 - "$1" <<'PY'
import ipaddress,sys
values=sys.argv[1].replace(',',' ').split()
if not values:raise SystemExit('Нужен хотя бы один IP панели')
result=[]
for value in values:
    value=str(ipaddress.ip_address(value))
    if value not in result:result.append(value)
print(' '.join(result))
PY
}
rn_node_info() {
  NODE_CONTAINER="${NODE_CONTAINER:-remnanode}"
  if command -v docker >/dev/null && ! docker inspect "$NODE_CONTAINER" >/dev/null 2>&1; then
    local candidates=()
    mapfile -t candidates < <(docker ps -a --format '{{.Names}} {{.Image}}' | awk '$2 ~ /^remnawave\/node(:|@)/ {print $1}')
    if ((${#candidates[@]}==1)); then NODE_CONTAINER="${candidates[0]}"; fi
  fi
  if command -v docker >/dev/null && docker inspect "$NODE_CONTAINER" >/dev/null 2>&1; then
    local detected
    detected="$(docker inspect "$NODE_CONTAINER" | python3 -c 'import sys,json; d=json.load(sys.stdin)[0]; print(next((v.split("=",1)[1] for v in d["Config"].get("Env",[]) if v.startswith("NODE_PORT=")),""))')"
    if [[ -n "$detected" ]]; then
      RN_RUNNING_NODE_PORT="$detected"
    fi
  fi
  if [[ -z "${RN_RUNNING_NODE_PORT:-}" ]]; then
    local control_ports=()
    mapfile -t control_ports < <(ss -H -ltnp | awk '/"rw-node"/ {n=split($4,a,":");print a[n]}' | sort -nu)
    if ((${#control_ports[@]}==1)); then RN_RUNNING_NODE_PORT="${control_ports[0]}"; fi
  fi
}
rn_ssh_ports() {
  {
    [[ -z "${SSH_CONNECTION:-}" ]] || printf '%s\n' "${SSH_CONNECTION##* }"
    ss -H -ltnp | python3 -c '
import ipaddress,re,sys
for line in sys.stdin:
 fields=line.split()
 if len(fields)<5 or not re.search(r"\(\"sshd(?:-session)?\"",line):continue
 host,port=fields[3].rsplit(":",1);host=host.strip("[]").split("%",1)[0]
 try:
  if ipaddress.ip_address(host).is_loopback:continue
 except ValueError:
  if host!="*":continue
 if port.isdigit():print(port)
'
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
      systemctl show ssh.socket -p Listen --value | sed -nE 's/.*:([0-9]+) \(Stream\).*/\1/p'
    fi
  } | awk '/^[0-9]+$/ && $1>0 && $1<=65535' | sort -nu | paste -sd, -
}
rn_ssh_context() {
  [[ -z "${SSH_CONNECTION:-}" ]] || return 0
  # sudo обычно удаляет SSH_CONNECTION. Читаем только её у предков процесса,
  # а не копируем окружение целиком и не выводим его в журнал.
  SSH_CONNECTION="$(python3 - "$$" <<'PY'
from pathlib import Path
import sys,ipaddress
pid=int(sys.argv[1])
for _ in range(64):
 if pid<=1:break
 try:
  for value in Path('/proc/'+str(pid)+'/environ').read_bytes().split(b'\0'):
   if value.startswith(b'SSH_CONNECTION='):
    text=value.split(b'=',1)[1].decode();parts=text.split()
    if len(parts)==4 and all(x.isdigit() and 0<int(x)<65536 for x in (parts[1],parts[3])):
     ipaddress.ip_address(parts[0]);ipaddress.ip_address(parts[2]);print(text);raise SystemExit
  pid=int(Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[1])
 except (FileNotFoundError,PermissionError,ProcessLookupError):break
PY
  )"
  export SSH_CONNECTION
}
rn_prepare() {
  [[ "$EUID" == 0 ]] || { rn_die 'Запустите от root'; return 1; }
  command -v python3 >/dev/null || { rn_die 'Установите python3'; return 1; }
  RN_STATE_DIR="${RN_STATE_DIR:-/var/lib/remnanode-hardening}"
  install -d -m 700 "$RN_STATE_DIR"
  if [[ -z "${PANEL_IPS:-}" && -s "$RN_STATE_DIR/panel-ips" ]]; then PANEL_IPS="$(cat "$RN_STATE_DIR/panel-ips")"; fi
  rn_ask PANEL_IPS 'IP панели (несколько IPv4/IPv6 — через пробел)'
  PANEL_IPS="$(rn_ips "$PANEL_IPS")"
  rn_node_info
  rn_ask NODE_PORT "Порт управления нодой из панели (сейчас ${RN_RUNNING_NODE_PORT:-не найден})" 9744
  rn_port "$NODE_PORT" || { rn_die 'Некорректный NODE_PORT'; return 1; }
  rn_ssh_context
  RN_OLD_SSH_PORTS="$(rn_ssh_ports)"
  rn_ask SSH_PORT "SSH-порт для входа на сервер (сейчас ${RN_OLD_SSH_PORTS:-не найден})" 48522
  rn_port "$SSH_PORT" || { rn_die 'Некорректный SSH_PORT'; return 1; }
  RN_SSH_PORTS="$(printf '%s\n%s\n' "${RN_OLD_SSH_PORTS//,/$'\n'}" "$SSH_PORT" | awk 'NF' | sort -nu | paste -sd, -)"
  case ",$RN_SSH_PORTS,80,443," in *",$NODE_PORT,"*) rn_die 'Порт управления совпадает с SSH/HTTP/HTTPS'; return 1;; esac
  RN_ADMIN_IP=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then RN_ADMIN_IP="$(rn_ips "${SSH_CONNECTION%% *}")"; fi
  RN_BACKUP="$(mktemp -d /root/remnanode-security-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX)"
  chmod 700 "$RN_BACKUP"
  rn_info "SSH: TCP/$SSH_PORT; управление: TCP/$NODE_PORT только с $PANEL_IPS"
}
rn_backup() {
  local item
  for item in etc/ufw etc/default/ufw etc/fail2ban etc/ssh etc/systemd/system/ssh.socket.d etc/systemd/system/ssh.service.d usr/local/sbin/remnanode-control-firewall etc/remnanode-security etc/systemd/system/remnanode-control-firewall.service; do
    [[ ! -e "/$item" ]] || { mkdir -p "$RN_BACKUP/$(dirname "$item")"; cp -a "/$item" "$RN_BACKUP/$item"; }
  done
  LC_ALL=C ufw status >"$RN_BACKUP/ufw-status"
  if nft list table inet remnanode_control >"$RN_BACKUP/control-before.nft" 2>/dev/null; then :; else : >"$RN_BACKUP/control-before.nft"; fi
}
rn_restore_firewall() {
  printf 'Откат правил из %s\n' "$RN_BACKUP" >&2
  if [[ -d "$RN_BACKUP/etc/ufw" ]]; then cp -a "$RN_BACKUP/etc/ufw/." /etc/ufw/; fi
  if [[ -f "$RN_BACKUP/etc/default/ufw" ]]; then cp -a "$RN_BACKUP/etc/default/ufw" /etc/default/ufw; fi
  if grep -q '^Status: active' "$RN_BACKUP/ufw-status"; then ufw reload; else ufw --force disable; fi
  local restore_batch
  restore_batch="$(mktemp)"
  if nft list table inet remnanode_control >/dev/null 2>&1; then printf 'delete table inet remnanode_control\n' >>"$restore_batch"; fi
  cat "$RN_BACKUP/control-before.nft" >>"$restore_batch"
  [[ ! -s "$restore_batch" ]] || nft -f "$restore_batch"
  rm -f "$restore_batch"
  if [[ -d "$RN_BACKUP/etc/remnanode-security" ]]; then cp -a "$RN_BACKUP/etc/remnanode-security/." /etc/remnanode-security/; fi
}
rn_control_config() {
  python3 - "$NODE_PORT" "$PANEL_IPS" <<'PY'
import ipaddress,sys
port=int(sys.argv[1]);ips=[ipaddress.ip_address(x) for x in sys.argv[2].split()]
print('table inet remnanode_control {')
for version in (4,6):
    values=', '.join(str(ip) for ip in ips if ip.version==version)
    print(' set panels%d { type ipv%d_addr; elements = { %s }; }'%(version,version,values) if values else ' set panels%d { type ipv%d_addr; }'%(version,version))
for hook in ('input','forward'):
    print(' chain guard_'+hook+' { type filter hook '+hook+' priority -200; policy accept;')
    if hook=='input':print('  iifname "lo" accept')
    match=('tcp dport %d'%port if hook=='input' else 'meta l4proto tcp ct direction original ct status dnat ct original proto-dst %d'%port)
    print('  '+match+' ip saddr @panels4 accept')
    print('  '+match+' ip6 saddr @panels6 accept')
    print('  '+match+' counter drop')
    print(' }')
print('}')
PY
}
rn_ufw_remove_owned() {
  local number
  while read -r number; do [[ -z "$number" ]] || ufw --force delete "$number"; done < <(
    LC_ALL=C ufw status numbered | sed -nE '/# remnanode-managed:/s/^\[[[:space:]]*([0-9]+)\].*/\1/p' | sort -rn
  )
}
rn_firewall() (
  set -Eeuo pipefail
  exec 8>/run/remnanode-firewall.lock
  flock -x 8
  trap 'r=$?; trap - ERR; rn_restore_firewall || true; exit "$r"' ERR
  local port ip batch
  # Сначала разрешаем все фактические SSH-порты, не удаляя старый доступ.
  IFS=, read -ra ports <<<"$RN_SSH_PORTS"
  for port in "${ports[@]}"; do ufw allow "$port/tcp"; done
  # UFW обслуживает обе семьи; IPv6/ICMPv6 системы не отключаем.
  if grep -q '^IPV6=' /etc/default/ufw; then sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw; else printf '\nIPV6=yes\n' >>/etc/default/ufw; fi
  rn_ufw_remove_owned
  ufw allow 80/tcp
  ufw allow 443/tcp
  if [[ "${RN_ROLE:-standard}" == standard ]]; then
    ufw allow 443/udp
  elif rn_discover_public_inbounds | grep -Fx 'udp 443' >/dev/null; then
    rn_info 'Обнаружен UDP/443: сохраняю работающий транспорт'
    ufw allow 443/udp
  else
    ufw --force delete allow 443/udp >/dev/null 2>&1 || true
  fi
  # Эти публичные разрешения оставлял старый installer. Удаляем только их.
  for port in "$NODE_PORT" 3000 3001; do
    if [[ "$port" != "$NODE_PORT" && -n "$(ss -H -ltn "sport = :$port")" ]]; then
      rn_info "TCP/$port занят: чужой сервис не закрываю"; continue
    fi
    ufw --force delete allow "$port/tcp" >/dev/null 2>&1 || true
  done
  ufw prepend deny proto tcp from any to any port "$NODE_PORT" comment 'remnanode-managed:control-deny'
  for ip in $PANEL_IPS; do ufw prepend allow proto tcp from "$ip" to any port "$NODE_PORT" comment 'remnanode-managed:panel'; done
  ufw default deny incoming
  # Не переписываем существующую политику исходящего трафика.
  ufw --force enable
  install -d -m 700 /etc/remnanode-security
  rn_control_config >/etc/remnanode-security/control.nft
  cat >/usr/local/sbin/remnanode-control-firewall <<'SH'
#!/bin/bash
set -euo pipefail
exec 9>/run/remnanode-control-firewall.lock
flock -x 9
batch=$(mktemp)
trap 'rm -f "$batch"' EXIT
if nft list table inet remnanode_control >/dev/null 2>&1; then echo 'delete table inet remnanode_control' >>"$batch"; fi
cat /etc/remnanode-security/control.nft >>"$batch"
nft -c -f "$batch"
nft -f "$batch"
SH
  chmod 700 /usr/local/sbin/remnanode-control-firewall
  /usr/local/sbin/remnanode-control-firewall
  cat >/etc/systemd/system/remnanode-control-firewall.service <<'UNIT'
[Unit]
Description=Panel-only RemnaWave control port
After=local-fs.target
Before=docker.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/remnanode-control-firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable remnanode-control-firewall.service
  systemctl restart remnanode-control-firewall.service
  nft list table inet remnanode_control >/dev/null
  ufw status numbered
  trap - ERR
)
rn_discover_public_inbounds() {
  { ss -H -ltnpe | sed 's/^/tcp /'; ss -H -lunpe | sed 's/^/udp /'; } |
    python3 -c '
import ipaddress,re,sys,json,socket,http.client
from pathlib import Path
excluded={int(sys.argv[1]),61000,61001}
found=set()
udp_cache={}
def configured_udp(pid):
    if pid in udp_cache:return udp_cache[pid]
    udp_cache[pid]=set()
    try:
        args=Path("/proc/"+str(pid)+"/cmdline").read_bytes().decode().split("\0")
        flag=next(x for x in ("-config","--config","-c") if x in args)
        filename=args[args.index(flag)+1]
        if filename.startswith("@"):
            address,target=filename.split(":",1)
            connection=socket.socket(socket.AF_UNIX);connection.settimeout(2)
            try:
                connection.connect("\0"+address[1:])
                connection.sendall(("GET "+target+" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").encode())
                response=http.client.HTTPResponse(connection);response.begin()
                if response.status!=200:return udp_cache[pid]
                conf=json.loads(response.read(8*1024*1024))
            finally:connection.close()
        else:
            path=Path("/proc/"+str(pid)+"/root")/filename.lstrip("/")
            conf=json.loads(path.read_text())
        for inbound in conf.get("inbounds",[]):
            transport=inbound.get("streamSettings",{}).get("network","")
            protocol=inbound.get("protocol","")
            is_udp=transport in ("hysteria","quic","kcp") or protocol=="hysteria"
            is_udp=is_udp or (protocol=="dokodemo-door" and "udp" in inbound.get("settings",{}).get("network","").split(","))
            if not is_udp:continue
            listen=inbound.get("listen") or "0.0.0.0"
            if listen not in ("*","0.0.0.0","::"):
                try:
                    if not ipaddress.ip_address(listen).is_global:continue
                except ValueError:continue
            for part in str(inbound.get("port","")).split(","):
                match=re.fullmatch(r"(\d+)(?:-(\d+))?",part.strip())
                if not match:continue
                a=int(match[1]);b=int(match[2] or match[1])
                if 0<a<=b<65536:udp_cache[pid].update(range(a,b+1))
    except (OSError,ValueError,KeyError,IndexError,StopIteration,http.client.HTTPException):pass
    return udp_cache[pid]
for line in sys.stdin:
    fields=line.split()
    if len(fields)<6 or not re.search(r"\(\"(?:rw-core|xray)\"",line):continue
    # comm можно поменять без root. uid сообщает ядро через ss -e:
    # непривилегированный процесс не должен открывать себе порт через таймер.
    uid=re.search(r"\buid:(\d+)\b",line)
    if uid and int(uid[1])!=0:continue
    endpoint=fields[4]
    try:host,rawport=endpoint.rsplit(":",1);port=int(rawport)
    except ValueError:continue
    host=host.strip("[]").split("%",1)[0]
    if port in excluded:continue
    if fields[0]=="udp":
        pids=[int(x) for x in re.findall(r"\bpid=(\d+)",line)]
        if not any(port in configured_udp(pid) for pid in pids):continue
    if host not in ("*","0.0.0.0","::"):
        try:
            address=ipaddress.ip_address(host)
            if not address.is_global:continue
        except ValueError:continue
    if 0<port<65536:found.add((fields[0],port))
for protocol,port in sorted(found):print(protocol,port)
' "$NODE_PORT"
}
rn_sync_public_inbounds() (
  set -Eeuo pipefail
  exec 9>/run/remnanode-firewall.lock
  flock -x 9
  LC_ALL=C ufw status | grep -q '^Status: active' || exit 0
  local desired current proto port number
  desired="$(rn_discover_public_inbounds)"
  # При остановленном ядре не удаляем разрешения во время его перезапуска.
  if [[ -z "$desired" ]] && ! ss -H -ltnp | grep -Eq '\("(rw-core|xray)"'; then exit 0; fi
  current="$(LC_ALL=C ufw status numbered | sed -nE 's/.*# remnanode-inbound:(tcp|udp):([0-9]+).*/\1 \2/p' | sort -k1,1 -k2,2n -u)"
  [[ "$desired" != "$current" ]] || exit 0
  while read -r number; do [[ -z "$number" ]] || ufw --force delete "$number"; done < <(
    LC_ALL=C ufw status numbered | sed -nE '/# remnanode-inbound:/s/^\[[[:space:]]*([0-9]+)\].*/\1/p' | sort -rn
  )
  while read -r proto port; do
    [[ -n "$proto" && -n "$port" ]] || continue
    ufw allow "$port/$proto" comment "remnanode-inbound:$proto:$port"
  done <<<"$desired"
  rn_info "Клиентские inbound Xray синхронизированы: $desired"
)
rn_install_inbound_sync() {
  {
    printf '#!/bin/bash\nset -Eeuo pipefail\nNODE_PORT=%q\n' "$NODE_PORT"
    declare -f rn_info rn_die rn_discover_public_inbounds rn_sync_public_inbounds
    printf '\nrn_sync_public_inbounds\n'
  } >/usr/local/sbin/remnanode-sync-inbounds
  chmod 700 /usr/local/sbin/remnanode-sync-inbounds
  cat >/etc/systemd/system/remnanode-sync-inbounds.service <<'UNIT'
[Unit]
Description=Synchronize public Xray client ports with UFW
After=docker.service ufw.service remnanode-control-firewall.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/remnanode-sync-inbounds
UNIT
  cat >/etc/systemd/system/remnanode-sync-inbounds.timer <<'UNIT'
[Unit]
Description=Watch active Xray client inbounds
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=remnanode-sync-inbounds.service
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  /usr/local/sbin/remnanode-sync-inbounds
  systemctl enable --now remnanode-sync-inbounds.timer
}
rn_fail2ban() {
  local ignore="127.0.0.0/8 ::1 $PANEL_IPS ${RN_ADMIN_IP:-}"
  install -d /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/99-remnanode-sshd.local <<EOF
# Блокируется только SSH, не трафик CDN/VPN.
[sshd]
enabled = true
port = $RN_SSH_PORTS
protocol = tcp
backend = systemd
filter = sshd[mode=normal]
maxretry = 5
findtime = 10m
bantime = 1h
banaction = nftables-multiport
action = %(action_)s
ignoreip = $ignore
EOF
  # Сохраняем jail.local и посторонние jails.
  if ! fail2ban-client -t; then
    rn_restore_fail2ban
    rn_die 'Fail2ban не принял конфигурацию; прежний файл восстановлен'; return 1
  fi
  if ! systemctl enable --now fail2ban || ! systemctl restart fail2ban; then
    rn_restore_fail2ban
    systemctl restart fail2ban || true
    rn_die 'Fail2ban не запустился; прежняя конфигурация восстановлена'; return 1
  fi
  local attempt
  for ((attempt=0;attempt<20;attempt++)); do
    if fail2ban-client status sshd >/dev/null 2>&1; then
      local trusted
      for trusted in $PANEL_IPS ${RN_ADMIN_IP:-}; do fail2ban-client set sshd unbanip "$trusted" >/dev/null; done
      fail2ban-client get sshd maxretry
      fail2ban-client status sshd
      return 0
    fi
    sleep .5
  done
  rn_restore_fail2ban
  systemctl restart fail2ban || true
  rn_die 'Fail2ban sshd jail не запустился; восстановлена прежняя конфигурация'
}
rn_restore_fail2ban() {
  local file=etc/fail2ban/jail.d/99-remnanode-sshd.local
  if [[ -f "$RN_BACKUP/$file" ]]; then cp -a "$RN_BACKUP/$file" "/$file"; else rm -f "/$file"; fi
}
rn_ssh_verified_key() {
  [[ -n "${SSH_CONNECTION:-}" ]] || return 1
  local source remote_port server server_port user="${SUDO_USER:-root}"
  read -r source remote_port server server_port <<<"$SSH_CONNECTION"
  # PID и UID берутся из доверенных полей journal. Одного тега sshd недостаточно:
  # его можно подделать через logger. Проверяем только SSH-предков текущей сессии.
  local ssh_pid started
  while read -r ssh_pid started; do
    if journalctl -b _UID=0 "_PID=$ssh_pid" --since "@$started" --no-pager -o cat 2>/dev/null |
        grep -F "Accepted publickey for $user from $source port $remote_port " >/dev/null; then return 0; fi
  done < <(python3 - "$$" <<'PY'
from pathlib import Path
import os,sys
pid=int(sys.argv[1]);ticks=os.sysconf('SC_CLK_TCK')
boot=int(next(x.split()[1] for x in Path('/proc/stat').read_text().splitlines() if x.startswith('btime ')))
for _ in range(64):
    if pid<=1:break
    try:
        fields=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        name=Path('/proc/'+str(pid)+'/comm').read_text().strip()
        if name in ('sshd','sshd-session'):print(pid,int(boot+int(fields[19])/ticks)-1)
        pid=int(fields[1])
    except (FileNotFoundError,ProcessLookupError):break
PY
  )
  return 1
}
rn_ssh_key_prepare() {
  [[ "${RN_SSH_KEY_READY:-0}" == 0 ]] || return 0
  if rn_ssh_verified_key; then RN_SSH_KEY_READY=1; return 0; fi
  rn_ask SSH_PUBLIC_KEY 'Публичный SSH-ключ для root (ssh-ed25519/ssh-rsa/ecdsa, не приватный ключ)' || return 1
  [[ "$SSH_PUBLIC_KEY" =~ ^(ssh-|ecdsa-|sk-) && "$SSH_PUBLIC_KEY" != *$'\n'* ]] || { rn_die 'Нужен один публичный SSH-ключ'; return 1; }
  printf '%s\n' "$SSH_PUBLIC_KEY" | ssh-keygen -lf /dev/stdin >/dev/null || { rn_die 'Некорректный публичный SSH-ключ'; return 1; }
  install -d -m 700 /root/.ssh
  [[ ! -e /root/.ssh/authorized_keys ]] || cp -a /root/.ssh/authorized_keys "$RN_BACKUP/authorized_keys-before"
  touch /root/.ssh/authorized_keys
  grep -Fx "$SSH_PUBLIC_KEY" /root/.ssh/authorized_keys >/dev/null || printf '\n%s\n' "$SSH_PUBLIC_KEY" >>/root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  RN_SSH_KEY_READY=1
}
rn_restore_ssh() {
  local item
  for item in etc/ssh/sshd_config etc/ssh/remnanode-access.conf etc/ssh/sshd_config.d/00-remnanode-auth.conf etc/systemd/system/ssh.socket.d/zz-remnanode-listen.conf etc/systemd/system/ssh.service.d/zz-remnanode-session.conf; do
    if [[ -f "$RN_BACKUP/$item" ]]; then cp -a "$RN_BACKUP/$item" "/$item"; else rm -f "/$item"; fi
  done
  systemctl daemon-reload
  if [[ "${RN_SSH_SOCKET_ACTIVE:-0}" == 1 ]]; then systemctl restart ssh.socket ssh.service; else systemctl reload ssh.service; fi
}
rn_ssh_harden() {
  # Подготовка ключа обязательна до изменений firewall: тихого пропуска больше нет.
  rn_ssh_key_prepare
  # Вне *.conf drop-in: повторный Include иначе складывает директивы Port.
  local dropin=/etc/ssh/remnanode-access.conf
  RN_SSH_SOCKET_ACTIVE=0
  systemctl is-active --quiet ssh.socket && RN_SSH_SOCKET_ACTIVE=1
  install -d /etc/ssh/sshd_config.d
  cat >"$dropin" <<EOF
# Вход только по ключу; SSH и NODE_PORT являются разными портами.
Port $SSH_PORT
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin prohibit-password
PermitEmptyPasswords no
EOF
  if [[ "$(head -n 1 /etc/ssh/sshd_config)" != "Include $dropin" ]]; then
    sed -i "1i Include $dropin" /etc/ssh/sshd_config
  fi
  sed -i '\#^Include /etc/ssh/sshd_config.d/00-remnanode-auth.conf$#d' /etc/ssh/sshd_config
  rm -f /etc/ssh/sshd_config.d/00-remnanode-auth.conf
  if ! sshd -t; then
    rn_restore_ssh
    rn_die 'sshd не принял настройки; конфиг восстановлен'; return 1
  fi
  # Старые глобальные Port складываются с Include. Убираем только глобальные
  # Port, Match-блоки остаются на месте; наш единственный Port — в drop-in.
  python3 - /etc/ssh/sshd_config <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]);lines=p.read_text().splitlines(True);inside=False;result=[]
for line in lines:
 if re.match(r'\s*Match\s',line,re.I):inside=True
 if not inside and re.match(r'\s*Port\s',line,re.I):continue
 result.append(line)
p.write_text(''.join(result))
PY
  # Проверяем эффективную политику, включая Match для текущего администратора.
  local effective
  effective="$(sshd -T -C "user=${SUDO_USER:-root},host=localhost,addr=${RN_ADMIN_IP:-127.0.0.1}")"
  if ! grep -qx 'authenticationmethods publickey' <<<"$effective" || ! grep -qx 'passwordauthentication no' <<<"$effective" || ! grep -qx 'kbdinteractiveauthentication no' <<<"$effective"; then
    rn_restore_ssh; rn_die 'Match переопределяет key-only политику; конфиг восстановлен'; return 1
  fi
  if [[ "$RN_SSH_SOCKET_ACTIVE" == 1 ]]; then
    install -d /etc/systemd/system/ssh.socket.d /etc/systemd/system/ssh.service.d
    {
      printf '[Socket]\nListenStream=\nListenStream=0.0.0.0:%s\n' "$SSH_PORT"
      [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" == 1 ]] || printf 'ListenStream=[::]:%s\nBindIPv6Only=ipv6-only\n' "$SSH_PORT"
    } >/etc/systemd/system/ssh.socket.d/zz-remnanode-listen.conf
    printf '[Service]\nKillMode=process\n' >/etc/systemd/system/ssh.service.d/zz-remnanode-session.conf
    systemctl daemon-reload
    if ! systemctl restart ssh.socket ssh.service; then rn_restore_ssh; rn_die 'SSH socket не применён; настройки восстановлены'; return 1; fi
  elif systemctl is-active --quiet ssh.service; then
    if ! systemctl reload ssh.service; then rn_restore_ssh; rn_die 'SSH reload не удался; настройки восстановлены'; return 1; fi
  else
    rn_restore_ssh; rn_die 'Не найдена активная ssh.service'; return 1
  fi
  if ! python3 - "$SSH_PORT" <<'PY'
import socket,sys,time
for _ in range(30):
 try:
  with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1) as s:
   s.settimeout(1)
   if s.recv(120).startswith(b'SSH-'):raise SystemExit(0)
 except OSError:time.sleep(.2)
raise SystemExit(1)
PY
  then rn_restore_ssh; rn_die 'Новый SSH-порт не отвечает; восстановлен предыдущий'; return 1; fi
  local port
  for port in ${RN_OLD_SSH_PORTS//,/ }; do
    [[ "$port" == "$SSH_PORT" ]] || ufw --force delete allow "$port/tcp" >/dev/null 2>&1 || true
  done
  # Старый скрипт ошибочно открывал локальные X11 forwarding 6010, 6011, ...
  for port in $(ss -H -ltnp | awk '/sshd/ && $4 ~ /^(127\.|\[::1\])/ {n=split($4,a,":");if(a[n]>=6000 && a[n]<=6099)print a[n]}' | sort -nu); do
    [[ "$port" == "$SSH_PORT" ]] || ufw --force delete allow "$port/tcp" >/dev/null 2>&1 || true
  done
  RN_SSH_PORTS="$SSH_PORT"
  rn_info "SSH TCP/$SSH_PORT: только публичный ключ; пароль и keyboard-interactive отключены."
}
rn_security() {
  rn_prepare
  export DEBIAN_FRONTEND=noninteractive
  rn_ensure_packages ufw nftables fail2ban python3-systemd iproute2 util-linux
  rn_backup
  rn_ssh_key_prepare
  rn_firewall
  rn_ssh_harden
  rn_install_inbound_sync
  rn_fail2ban
  printf '%s\n' "$PANEL_IPS" >"$RN_STATE_DIR/panel-ips"
  chmod 600 "$RN_STATE_DIR/panel-ips"
  rn_info "Безопасность проверена. SSH TCP/$SSH_PORT — только ключ. Копия: $RN_BACKUP"
}
rn_existing_repair() {
  rn_security
  if command -v docker >/dev/null && docker inspect "$NODE_CONTAINER" >/dev/null 2>&1; then
    local mode
    mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$NODE_CONTAINER")"
    if [[ "$(docker inspect -f '{{.State.Running}}' "$NODE_CONTAINER")" != true ]]; then docker start "$NODE_CONTAINER"; fi
    rn_change_node_port
    rn_info "Сеть ноды: $mode"
    if [[ "$mode" != host ]]; then rn_info 'Bridge-сеть сохранена; control guard действует и на FORWARD. Другие опубликованные порты проверьте отдельно.'; fi
    docker inspect -f 'Нода: {{.State.Status}}; перезапуски: {{.RestartCount}}; журнал: {{.HostConfig.LogConfig.Type}}' "$NODE_CONTAINER"
  fi
  rn_info 'Домены, SECRET_KEY и профили панели сохранены; NODE_PORT изменяется только по выбранному значению.'
}
rn_change_node_port() {
  [[ -n "${RN_RUNNING_NODE_PORT:-}" && "$RN_RUNNING_NODE_PORT" != "$NODE_PORT" ]] || return 0
  local directory="${NODE_DIR:-/opt/remnanode}" file service
  [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$NODE_CONTAINER")" == host ]] || { rn_die 'Смена NODE_PORT для bridge требует отдельной проверки published ports'; return 1; }
  file="$directory/docker-compose.yml"
  [[ -f "$file" ]] || file="$directory/compose.yaml"
  [[ -f "$file" ]] || { rn_die 'Не найден compose: порт контейнера не изменён'; return 1; }
  local image_id local_image
  image_id="$(docker inspect -f '{{.Image}}' "$NODE_CONTAINER")"
  local_image="$(docker image inspect -f '{{.Id}}' "$(docker inspect -f '{{.Config.Image}}' "$NODE_CONTAINER")")"
  [[ "$image_id" == "$local_image" ]] || { rn_die 'Локальный тег образа изменился: не пересоздаю ноду с другим ядром'; return 1; }
  rn_ensure_packages python3-yaml
  cp -a "$file" "$RN_BACKUP/node-compose-before.yml"
  if ! service="$(python3 - "$file" "$NODE_CONTAINER" "$NODE_PORT" <<'PY'
from pathlib import Path
import json,os,stat,sys,tempfile,yaml
p=Path(sys.argv[1]);conf=yaml.safe_load(p.read_text());services=conf.get('services',{})
names=[name for name,value in services.items() if value.get('container_name')==sys.argv[2]]
if not names:names=[name for name,value in services.items() if str(value.get('image','')).startswith('remnawave/node')]
if len(names)!=1:raise SystemExit('Неоднозначный сервис ноды: compose сохранён')
service=services[names[0]];env=service.setdefault('environment',{})
if isinstance(env,dict):env['NODE_PORT']=sys.argv[3]
elif isinstance(env,list):service['environment']=[v for v in env if not str(v).startswith('NODE_PORT=') and v!='NODE_PORT']+['NODE_PORT='+sys.argv[3]]
else:raise SystemExit('Нестандартный environment: compose сохранён')
content=json.dumps(conf,ensure_ascii=False,indent=2)+'\n'
fd,tmp=tempfile.mkstemp(dir=p.parent)
try:
 os.fchmod(fd,stat.S_IMODE(p.stat().st_mode))
 with os.fdopen(fd,'w') as f:f.write(content)
 os.replace(tmp,p)
finally:
 if os.path.exists(tmp):os.unlink(tmp)
print(names[0])
PY
  )"; then rn_die 'Не удалось безопасно изменить NODE_PORT'; return 1; fi
  if ! (cd "$directory"; docker compose config --quiet && docker compose up -d --no-deps --pull never "$service"); then
    cp -a "$RN_BACKUP/node-compose-before.yml" "$file"
    (cd "$directory"; docker compose up -d --no-deps --pull never "$service") || true
    rn_restore_firewall
    rn_die 'Не удалось применить NODE_PORT; compose и firewall восстановлены'; return 1
  fi
  local attempt
  for ((attempt=0;attempt<30;attempt++)); do
    if [[ -n "$(ss -H -ltn "sport = :$NODE_PORT")" ]]; then
      RN_RUNNING_NODE_PORT="$NODE_PORT"
      rn_info "Управление нодой переведено на TCP/$NODE_PORT. Такой же порт должен быть указан в панели."
      return 0
    fi
    sleep 1
  done
  cp -a "$RN_BACKUP/node-compose-before.yml" "$file"
  (cd "$directory"; docker compose up -d --no-deps --pull never "$service") || true
  rn_restore_firewall
  rn_die 'Новый NODE_PORT не слушает; предыдущие compose и firewall восстановлены'
}

# END SHARED SECURITY
RN_ROLE=standard
RN_MODE="${1:-auto}"
case "$RN_MODE" in
  --help)
    printf 'Запуск: bash install.sh [--repair|--check|--resume]\nPANEL_IPS="IPv4 IPv6" — адреса панели. SSH_PORT=48522 — вход с любого IP только по ключу.\nNODE_PORT=9744 — управление только с IP панели; такой же порт укажите в панели.\n'; exit 0;;
  --check)
    rn_node_info
    [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="${RN_RUNNING_NODE_PORT:-}"
    printf 'SSH: %s\nNODE_PORT: %s\n' "$(rn_ssh_ports)" "${NODE_PORT:-не определён}"
    ufw status numbered; nft list table inet remnanode_control; fail2ban-client status sshd; exit;;
  auto|--repair|--resume) ;;
  *) rn_die "Неизвестный аргумент $RN_MODE"; exit 1;;
esac
[[ "$EUID" == 0 ]] || { rn_die 'Запустите от root'; exit 1; }
exec 7>/run/remnanode-installer.lock
flock -n 7 || { rn_die 'Уже работает другой установщик ноды'; exit 1; }
if [[ "$RN_MODE" != --resume ]] && {
    [[ "$RN_MODE" == --repair || -f /opt/remnanode/docker-compose.yml || -f /opt/remnanode/compose.yaml ]] ||
    { command -v docker >/dev/null && docker inspect remnanode >/dev/null 2>&1; }
}; then
    [[ "$EUID" == 0 ]] || { rn_die 'Запустите от root'; exit 1; }
    rn_ensure_packages python3 iproute2 openssh-server
    rn_existing_repair
    printf 'Проверка маскировки: '; systemctl is-active nginx || true
    printf 'Проверьте также inbound и доступность TCP/UDP из подписки.\n'
    exit 0
fi


# ------------------------------------------------------------
# БАЗОВЫЕ НАСТРОЙКИ
# ------------------------------------------------------------

TTY=/dev/tty

[[ -e "$TTY" ]] || {
  echo "Нет терминала — задай параметры переменными окружения" >&2
  exit 1
}

# Запоминаем именно значения, переданные через окружение ДО загрузки state.env.
# Это нужно, чтобы явные параметры могли переопределить сохранённое состояние.
DOMAIN_EXPLICIT="${DOMAIN+x}"
DOMAIN_INPUT="${DOMAIN:-}"

SSH_PORT_EXPLICIT="${SSH_PORT+x}"
SSH_PORT_INPUT="${SSH_PORT:-}"

SECRET_KEY_EXPLICIT="${SECRET_KEY+x}"
SECRET_KEY_INPUT="${SECRET_KEY:-}"

NODE_PORT_EXPLICIT="${NODE_PORT+x}"
NODE_PORT_INPUT="${NODE_PORT:-}"

SHAPER_ENABLED_EXPLICIT="${SHAPER_ENABLED+x}"
SHAPER_ENABLED_INPUT="${SHAPER_ENABLED:-}"

DOMAIN="${DOMAIN:-}"
SSH_PORT="${SSH_PORT:-}"
SECRET_KEY="${SECRET_KEY:-}"

# API-порт RemnaNode.
# ЭТО НЕ SSH-ПОРТ.
NODE_PORT="${NODE_PORT:-9744}"

NODE_DIR="/opt/remnanode"
SSL_DIR="$NODE_DIR/ssl"

XHTTP_PATH="${XHTTP_PATH:-/media/hls/segment.ts}"
XHTTP_PORT="${XHTTP_PORT:-7443}"

PSIPHON_IMAGE="swarupsengupta2007/psiphon@sha256:40ea22d78c0631c3a0f7550db8dd33bc8365b4693617b70a1ea87ad795a978a6"
PSIPHON_REGION="${PSIPHON_REGION:-DE}"
PSIPHON_SOCKS_HOST="172.17.0.1"
PSIPHON_SOCKS_PORT="1080"

PSIPHON_INSTALLER_COMMIT="2740efa0e60e8dd12a836492b2097fcd3202b4ce"
PSIPHON_INSTALLER_SHA256="43c64795ed441cebcb1053ba2d6e5bc7063c3b9bc2cabddf85c51a06b8fabbcc"
PSIPHON_INSTALLER_URL="https://raw.githubusercontent.com/Chara-Freedom/vps-psiphon/$PSIPHON_INSTALLER_COMMIT/psiphon_install.sh"

STATE_DIR="/var/lib/remnanode-installer"
STATE_FILE="$STATE_DIR/state.env"

BACKUP_DIR="/root/remnanode-installer-backups"

NGX="/etc/nginx/sites-available/default"
SSHD="/etc/ssh/sshd_config"

STANDARD_SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"

# ------------------------------------------------------------
# ШЕЙПИНГ
# ------------------------------------------------------------

SHAPER_ENABLED="${SHAPER_ENABLED:-}"
SHAPER_PORTS="${SHAPER_PORTS:-443}"

# Все значения скорости — МБ/с, НЕ Мбит/с.
SHAPER_DOWN_MBPS="${SHAPER_DOWN_MBPS:-100}"
SHAPER_UP_MBPS="${SHAPER_UP_MBPS:-100}"
SHAPER_PENALTY_MBPS="${SHAPER_PENALTY_MBPS:-8}"

SHAPER_BURST_MB="${SHAPER_BURST_MB:-1500}"
SHAPER_WINDOW_SEC="${SHAPER_WINDOW_SEC:-60}"
SHAPER_PENALTY_SEC="${SHAPER_PENALTY_SEC:-60}"

SHAPER_IFACE="${SHAPER_IFACE:-}"

SHAPER_DIR="$NODE_DIR/shaper"
SHAPER_CONFIG_DIR="/etc/remnanode/shaper"
SHAPER_PIN_DIR="/sys/fs/bpf/remnanode-shaper"

SHAPER_SERVICE="remnanode-dynamic-shaper.service"

RESHALA_COMMIT="921212bce0a913b05c2406a24501a00b6dce9eac"

SHAPER_BPF_SHA256="7ba92af3e35fa3b86702941082877e4a460f1ca5b1bfae8d2470f63f5c53832f"
SHAPER_CTRL_SHA256="013980ef503e27d51bdeeec646429734fa4f2798b038d07b34934d50d630beea5"

# ------------------------------------------------------------
# ВЫВОД
# ------------------------------------------------------------

STEP=0
TOTAL=10
INSTALLER_VERSION="2026-10-19.4"
STEP_STARTED=0
LOG_FILE=""
APT_CONFIG_TMP=""
PROGRESS_PID=""
STEP_LABEL="Подготовка"
FAILURE_LINE=""
FAILURE_COMMAND=""
INSTALLER_PID="$BASHPID"
exec 3>&1 4>&2

stop_progress() {
  if [[ -n "${PROGRESS_PID:-}" ]]; then
    kill "$PROGRESS_PID" 2>/dev/null || true
    wait "$PROGRESS_PID" 2>/dev/null || true
    PROGRESS_PID=""
  fi
}

draw_progress() {
  local completed="$1" elapsed="$2" mark="$3" bar="" i
  for ((i=0; i<TOTAL; i++)); do
    if ((i < completed)); then bar+="#"; else bar+="-"; fi
  done
  printf '\r\033[2K[%s] %3d%%  %s %s/%s · %s · %s с' \
    "$bar" "$((completed * 100 / TOTAL))" "$mark" "$STEP" "$TOTAL" "$STEP_LABEL" "$elapsed" >&3
}

step() {
  stop_progress
  STEP=$((STEP + 1))
  STEP_STARTED=$SECONDS
  STEP_LABEL="$*"
  if [[ -n "$LOG_FILE" ]]; then
    draw_progress "$((STEP - 1))" 0 '…'
    (
      # Не запускаем основной обработчик EXIT в процессе индикатора.
      trap - EXIT ERR INT TERM
      while sleep 1; do
        draw_progress "$((STEP - 1))" "$((SECONDS - STEP_STARTED))" '…'
      done
    ) &
    PROGRESS_PID=$!
  fi
  echo
  echo -e "\e[1;44m  ЭТАП $STEP/$TOTAL  \e[0m \e[1m$*\e[0m"
  info "Начало: $(date '+%F %T')"
  case "$STEP" in
    1) info "Репозиторий Docker → пакеты → запуск службы → проверка Compose" ;;
    2) info "Загрузка образа → создание контейнера → проверка каталогов и состояния" ;;
    3) info "nginx/certbot/logrotate → HTML → ACME на порту 80 → сертификат и автопродление" ;;
    4) info "Конфигурация nginx → проверка синтаксиса → перезагрузка → проверка HTTPS" ;;
    5) info "SSH-ключ → резервная копия → настройки порта → проверка службы и слушателя" ;;
    6) info "Пакет UFW → разрешающие правила → включение → список правил" ;;
    7) info "Пакет fail2ban → SSH jail → запуск → проверка состояния" ;;
    8) info "Загрузка traffic-guard → установка → списки блокировки → проверка SSH" ;;
    9) info "Проверка SHA256 → образ Psiphon → /config и службы → SOCKS → регион и HTTP" ;;
    10) info "Настройка выбранного режима шейпинга → проверка правил → сохранение результата" ;;
  esac
}

ok() {
  echo -e "  \e[32m✔\e[0m $*"
}

info() {
  echo -e "  \e[36m→\e[0m $*"
}

warn() {
  echo -e "  \e[33m!\e[0m $*"
}

err() {
  echo -e "  \e[31m✗\e[0m $*" >&2
}

on_error() {
  local rc="$1" line="$2"
  FAILURE_LINE="$line"
  FAILURE_COMMAND="${3:-не определена}"
  exit "$rc"
}

cleanup() {
  local rc="$1" report secret
  [[ "$BASHPID" == "$INSTALLER_PID" ]] || return 0
  trap - ERR
  stop_progress
  if ((rc != 0)); then
    report="$(
      printf '\nУстановка прервана. Диагностика для отправки в чат:\n'
      printf '%s\n' '--- НАЧАЛО ДИАГНОСТИКИ ---'
      printf 'Версия: %s\nЭтап:    %s/%s — %s\nКод:     %s\n' "$INSTALLER_VERSION" "$STEP" "$TOTAL" "$STEP_LABEL" "$rc"
      printf 'Строка:  %s\nКоманда: %s\nЖурнал:  %s\n' "${FAILURE_LINE:-явный выход}" "${FAILURE_COMMAND:-смотрите последние сообщения}" "${LOG_FILE:-ещё не создан}"
      if [[ -n "$LOG_FILE" && -r "$LOG_FILE" ]]; then
        printf '\nПоследние сообщения:\n'
        tail -n 40 "$LOG_FILE"
      fi
      printf '\n%s\n' '--- КОНЕЦ ДИАГНОСТИКИ ---'
      printf 'Повторите запуск и выберите продолжение с незавершённого этапа.\n'
    )"
    for secret in "${SECRET_KEY:-}" "${SECRET_KEY_INPUT:-}"; do
      [[ -z "$secret" ]] || report="${report//"$secret"/[ключ скрыт]}"
    done
    printf '\r\033[2K%s\n' "$report" >&4
  fi
  rm -f -- "${APT_CONFIG_TMP:-}" "${PSIPHON_INSTALLER_TMP:-}"
}

trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap 'cleanup "$?"' EXIT
trap 'FAILURE_COMMAND="Прервано пользователем (Ctrl+C)"; exit 130' INT
trap 'FAILURE_COMMAND="Получен сигнал TERM"; exit 143' TERM

# После ввода параметров подробности пишутся только в закрытый журнал.
start_install_log() {
  install -d -m 700 /var/log/remnanode-installer
  LOG_FILE="$(mktemp /var/log/remnanode-installer/install-$(date +%Y%m%d-%H%M%S).XXXXXX.log)"
  chmod 600 "$LOG_FILE"
  printf 'Подробности записываются в %s\n' "$LOG_FILE" >&3
  exec >>"$LOG_FILE" 2>&1
  info "Журнал установки: $LOG_FILE"
  info "Версия установщика: $INSTALLER_VERSION"

  # Настройка наследуется дочерними установщиками и удаляется при выходе.
  APT_CONFIG_TMP="$(mktemp /tmp/remnanode-apt.XXXXXX)"
  if [[ -n "${APT_CONFIG:-}" && -r "$APT_CONFIG" ]]; then
    cat "$APT_CONFIG" >"$APT_CONFIG_TMP"
  fi
  printf '\nDPkg::Lock::Timeout "1800";\nDpkg::Use-Pty "0";\n' >>"$APT_CONFIG_TMP"
  export APT_CONFIG="$APT_CONFIG_TMP"
  export DEBIAN_FRONTEND=noninteractive
  info "Если apt занят автообновлением Ubuntu, ждём до 30 минут."
}

apt_run() {
  local rc
  info "apt-get $* (ожидание блокировки до 30 минут)"
  if apt-get -o DPkg::Lock::Timeout=1800 -o Dpkg::Use-Pty=0 "$@" </dev/null; then
    return 0
  else
    rc=$?
    err "apt-get завершился с кодом $rc; причина указана выше. Этап не отмечен завершённым."
    return "$rc"
  fi
}

# Меняется только подробность вывода официального Docker installer.
prepare_docker_installer() {
  sed -i -e 's/ -qq/ /g' -e '/apt-get /s@>/dev/null@@g' "$1"
  sh -n "$1"
}

run_with_progress() {
  local label="$1" rc
  shift
  info "$label"
  if "$@" </dev/null; then rc=0; else rc=$?; fi
  return "$rc"
}

# ------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ------------------------------------------------------------

# ВАЖНО:
#
# Основной installer запускается как:
#
#   curl ... | bash
#
# Поэтому нельзя делать внутри:
#
#   curl ... | sh
#
# Вложенный shell может начать читать stdin внешнего bash и съесть
# остаток install.sh.
#
# Вместо этого скачиваем дочерний installer в файл.
# stdout/stderr сохраняются в журнал установки.
run_remote_script() {
  local shell_bin="$1"
  local url="$2"

  local tmp
  local rc

  tmp="$(mktemp /tmp/remnanode-remote-installer.XXXXXX)"

  info "Загружаю: $url"

  if curl -fsSL "$url" -o "$tmp"; then
    :
  else
    rc=$?
    rm -f "$tmp"
    return "$rc"
  fi

  chmod 700 "$tmp"
  if [[ "$url" == "https://get.docker.com" ]]; then
    prepare_docker_installer "$tmp"
  fi

  # Дочерний installer не должен читать основной curl-pipe.
  if run_with_progress "$url" "$shell_bin" "$tmp"; then
    rc=0
  else
    rc=$?
  fi

  rm -f "$tmp"

  return "$rc"
}


stop_stale_ssh_listeners() {
  local pid main_pid service_group ssh_binary owners attempt
  main_pid="$(systemctl show ssh.service -p MainPID --value)"
  service_group="$(systemctl show ssh.service -p ControlGroup --value)"
  ssh_binary="$(readlink -f "$(command -v sshd)")"
  [[ "$main_pid" =~ ^[1-9][0-9]*$ && -n "$service_group" ]] || return 1
  owners="$(ss -H -ltnp 'sport = :22')"
  owners="$(sed -nE 's/.*pid=([0-9]+),.*/\1/p' <<<"$owners" | sort -u)"
  [[ -n "$owners" ]] || return 1
  for pid in $owners; do
    # Завершаем только старый слушатель этой службы, сохраняя текущие сессии.
    [[ "$pid" != "$main_pid" ]] || return 1
    [[ "$(readlink -f "/proc/$pid/exe")" == "$ssh_binary" ]] || return 1
    ps -p "$pid" -o args= | grep -Fq '[listener]' || return 1
    awk -F: -v group="$service_group" '$3 == group {found=1} END {exit !found}' \
      "/proc/$pid/cgroup" || return 1
    info "Завершаю старый слушатель sshd PID $pid на TCP/22"
    kill -TERM "$pid" || return 1
  done
  for ((attempt=0; attempt<10; attempt++)); do
    [[ -n "$(ss -H -ltn 'sport = :22')" ]] || return 0
    sleep 0.2
  done
  return 1
}

ensure_ufw_rules() { rn_firewall; }


default_interface() {
  ip -4 route show default 2>/dev/null |
    awk '
      $1 == "default" && iface == "" {
        for (i = 1; i <= NF; i++) {
          if ($i == "dev" && i < NF) {
            iface = $(i + 1)
            break
          }
        }
      }

      END {
        if (iface != "")
          print iface
      }
    '
}


save_state() {
  local completed="$1"
  local tmp

  install -d -m 700 "$STATE_DIR"

  tmp="$STATE_FILE.tmp"

  umask 077

  {
    printf 'LAST_COMPLETED_STEP=%q\n' "$completed"

    for state_var in \
      DOMAIN \
      SSH_PORT \
      SECRET_KEY \
      NODE_PORT \
      PANEL_IPS \
      XHTTP_PATH \
      XHTTP_PORT \
      PSIPHON_REGION \
      SHAPER_ENABLED \
      SHAPER_PORTS \
      SHAPER_DOWN_MBPS \
      SHAPER_UP_MBPS \
      SHAPER_PENALTY_MBPS \
      SHAPER_BURST_MB \
      SHAPER_WINDOW_SEC \
      SHAPER_PENALTY_SEC \
      SHAPER_IFACE
    do
      printf '%s=%q\n' "$state_var" "${!state_var:-}"
    done
  } >"$tmp"

  chmod 600 "$tmp"

  mv -f "$tmp" "$STATE_FILE"
  if ((completed > 0)); then
    ok "Этап $completed/$TOTAL завершён за $((SECONDS - STEP_STARTED)) с; результат сохранён"
    if [[ -n "$LOG_FILE" ]]; then
      stop_progress
      draw_progress "$completed" "$((SECONDS - STEP_STARTED))" '✓'
      printf '\n' >&3
    fi
  fi
}


reapply_explicit_inputs() {
  if [[ -n "$DOMAIN_EXPLICIT" ]]; then
    DOMAIN="$DOMAIN_INPUT"
  fi

  if [[ -n "$SSH_PORT_EXPLICIT" ]]; then
    SSH_PORT="$SSH_PORT_INPUT"
  fi

  if [[ -n "$SECRET_KEY_EXPLICIT" ]]; then
    SECRET_KEY="$SECRET_KEY_INPUT"
  fi

  if [[ -n "$NODE_PORT_EXPLICIT" ]]; then
    NODE_PORT="$NODE_PORT_INPUT"
  fi

  if [[ -n "$SHAPER_ENABLED_EXPLICIT" ]]; then
    SHAPER_ENABLED="$SHAPER_ENABLED_INPUT"
  fi
}


recover_legacy_state() {
  local compose="$NODE_DIR/docker-compose.yml"
  local cert_path=""
  local legacy_node_port=""
  local sshd_effective=""
  local recovered_ssh_port=""
  local psiphon_logs=""

  # ----------------------------------------------------------
  # Старый docker-compose
  # ----------------------------------------------------------

  if [[ -f "$compose" ]]; then

    legacy_node_port="$(
      awk '
        /^[[:space:]]*NODE_PORT:[[:space:]]*"/ && value == "" {
          line=$0

          sub(/^[[:space:]]*NODE_PORT:[[:space:]]*"/, "", line)
          sub(/".*$/, "", line)

          value=line
        }

        END {
          if (value != "")
            print value
        }
      ' "$compose" 2>/dev/null || true
    )"

    if [[ -z "${LAST_COMPLETED_STEP:-}" &&
          -z "$NODE_PORT_EXPLICIT" &&
          -n "$legacy_node_port" ]]; then
      NODE_PORT="$legacy_node_port"
    fi

    if [[ -z "$SECRET_KEY" ]]; then
      SECRET_KEY="$(
        awk '
          /^[[:space:]]*SECRET_KEY:[[:space:]]*"/ && value == "" {
            line=$0

            sub(/^[[:space:]]*SECRET_KEY:[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)

            value=line
          }

          END {
            if (value != "")
              print value
          }
        ' "$compose" 2>/dev/null || true
      )"
    fi

  fi

  # ----------------------------------------------------------
  # Домен из сертификата
  # ----------------------------------------------------------

  if [[ -z "$DOMAIN" && -e "$SSL_DIR/fullchain.pem" ]]; then

    cert_path="$(
      readlink -f "$SSL_DIR/fullchain.pem" 2>/dev/null || true
    )"

    if [[ "$cert_path" == /etc/letsencrypt/archive/*/* ]]; then
      DOMAIN="${cert_path#/etc/letsencrypt/archive/}"
      DOMAIN="${DOMAIN%%/*}"
    fi

  fi

  # ----------------------------------------------------------
  # SSH-ПОРТ
  #
  # КРИТИЧНО:
  #
  # На НОВОМ сервере sshd -T возвращает:
  #
  #   port 22
  #
  # Это НЕ желаемый новый порт.
  #
  # Поэтому 22 НИКОГДА не восстанавливается как SSH_PORT.
  #
  # Если это старая установка и реально уже используется нестандартный
  # порт, можно восстановить только НЕ-22.
  # ----------------------------------------------------------

  if [[ -z "$SSH_PORT" &&
        -f "$compose" &&
        -x "$(command -v sshd 2>/dev/null || true)" ]]; then

    sshd_effective="$(
      sshd -T 2>/dev/null || true
    )"

    recovered_ssh_port="$(
      awk '
        $1 == "port" && $2 != "22" && port == "" {
          port=$2
        }

        END {
          if (port != "")
            print port
        }
      ' <<<"$sshd_effective"
    )"

    if [[ -n "$recovered_ssh_port" ]]; then
      SSH_PORT="$recovered_ssh_port"
    fi

  fi

  # ----------------------------------------------------------
  # Старый проблемный Psiphon
  # ----------------------------------------------------------

  if [[ -z "${LAST_COMPLETED_STEP:-}" ]] &&
     command -v docker >/dev/null 2>&1 &&
     docker inspect vps-psiphon >/dev/null 2>&1
  then

    psiphon_logs="$(
      docker logs --tail 100 vps-psiphon 2>&1 || true
    )"

    if grep -F \
      '/config directory not mounted' \
      <<<"$psiphon_logs" >/dev/null
    then
      LAST_COMPLETED_STEP=8
    fi

  fi
}


backup_and_reset_components() {
  local stamp
  local archive
  local shaper_iface_old=""
  local p

  local -a backup_items=()

  stamp="$(date +%Y%m%d-%H%M%S)"

  install -d -m 700 "$BACKUP_DIR"

  archive="$BACKUP_DIR/remnanode-before-reinstall-$stamp.tar.gz"

  for p in \
    "$NODE_DIR" \
    /opt/vps-psiphon \
    "$STATE_DIR" \
    "$SHAPER_CONFIG_DIR" \
    "/etc/systemd/system/$SHAPER_SERVICE" \
    /etc/systemd/system/vps-psiphon.service \
    /etc/systemd/system/vps-psiphon-watchdog.service \
    /etc/systemd/system/vps-psiphon-watchdog.timer \
    /etc/default/vps-psiphon \
    /usr/local/sbin/vps-psiphon \
    /usr/local/sbin/vps-psiphon-run \
    /usr/local/sbin/vps-psiphon-watchdog \
    /var/lib/vps-psiphon-watchdog.state \
    /var/log/vps-psiphon-watchdog.log \
    /etc/letsencrypt/renewal-hooks/deploy/restart-remnanode.sh \
    /etc/logrotate.d/remnanode
  do

    if [[ -e "$p" ]]; then
      backup_items+=("$p")
    fi

  done

  if ((${#backup_items[@]})); then

    tar \
      --absolute-names \
      -czf "$archive" \
      "${backup_items[@]}"

    chmod 600 "$archive"

    ok "Резервная копия компонентов: $archive"

  fi

  if [[ -f "$SHAPER_CONFIG_DIR/settings.conf" ]]; then

    shaper_iface_old="$(
      awk -F= '
        $1 == "SHAPER_IFACE" && iface == "" {
          iface=$2
        }

        END {
          if (iface != "")
            print iface
        }
      ' "$SHAPER_CONFIG_DIR/settings.conf" 2>/dev/null || true
    )"

  fi

  systemctl disable --now \
    "$SHAPER_SERVICE" \
    2>/dev/null || true

  if [[ -n "$shaper_iface_old" &&
        -d "/sys/class/net/$shaper_iface_old" ]] &&
     command -v tc >/dev/null 2>&1
  then

    tc qdisc del \
      dev "$shaper_iface_old" \
      root \
      2>/dev/null || true

    tc qdisc del \
      dev "$shaper_iface_old" \
      clsact \
      2>/dev/null || true

  fi

  if command -v vps-psiphon >/dev/null 2>&1; then
    vps-psiphon uninstall >/dev/null 2>&1 || true
  fi

  systemctl disable --now \
    vps-psiphon-watchdog.timer \
    vps-psiphon.service \
    2>/dev/null || true

  if [[ -f "$NODE_DIR/docker-compose.yml" ]] &&
     command -v docker >/dev/null 2>&1
  then

    (
      cd "$NODE_DIR"
      docker compose down --remove-orphans
    ) || true

  elif command -v docker >/dev/null 2>&1; then

    docker rm \
      -f \
      remnanode \
      vps-psiphon \
      >/dev/null 2>&1 || true

  fi

  [[ "$NODE_DIR" == /opt/remnanode &&
     "$STATE_DIR" == /var/lib/remnanode-installer &&
     "$SHAPER_CONFIG_DIR" == /etc/remnanode/shaper ]] || {

    err "Внутренняя проверка путей очистки не пройдена"
    exit 1

  }

  rm -rf -- \
    "$NODE_DIR" \
    /opt/vps-psiphon \
    "$STATE_DIR" \
    "$SHAPER_CONFIG_DIR" \
    "$SHAPER_PIN_DIR"

  rm -f -- \
    "/etc/systemd/system/$SHAPER_SERVICE" \
    /etc/systemd/system/vps-psiphon.service \
    /etc/systemd/system/vps-psiphon-watchdog.service \
    /etc/systemd/system/vps-psiphon-watchdog.timer \
    /etc/letsencrypt/renewal-hooks/deploy/restart-remnanode.sh \
    /etc/logrotate.d/remnanode

  systemctl daemon-reload

  LAST_COMPLETED_STEP=0

  ok "Компоненты ноды, Psiphon и шейпера очищены"
}


# ask VARNAME "Приглашение: " [default]
ask() {
  local __v="$1"
  local __p="$2"
  local __d="${3:-}"
  local __in

  printf '%s' "$__p" >"$TTY"

  IFS= read -r __in <"$TTY" || true

  if [[ -z "$__in" && -n "$__d" ]]; then
    __in="$__d"
  fi

  printf -v "$__v" '%s' "$__in"
}


ask_secret() {
  local __v="$1"
  local __p="$2"
  local __in

  printf '%s' "$__p" >"$TTY"

  IFS= read -r -s __in <"$TTY" || true

  printf '\n' >"$TTY"

  printf -v "$__v" '%s' "$__in"
}


install_standard_ssh_key() {
  install -d -m 700 /root/.ssh

  touch /root/.ssh/authorized_keys

  chmod 600 /root/.ssh/authorized_keys

  if ! grep -Fqx \
    "$STANDARD_SSH_PUBLIC_KEY" \
    /root/.ssh/authorized_keys
  then

    printf '%s\n' \
      "$STANDARD_SSH_PUBLIC_KEY" \
      >>/root/.ssh/authorized_keys

  fi

  grep -Fqx \
    "$STANDARD_SSH_PUBLIC_KEY" \
    /root/.ssh/authorized_keys || {

    err "Не удалось записать стандартный SSH-ключ"
    exit 1

  }
}


# ------------------------------------------------------------
# PREFLIGHT
# ------------------------------------------------------------

[[ $EUID -eq 0 ]] || {
  err "Запусти от root"
  exit 1
}

[[ "$(uname -m)" == "x86_64" ]] || {
  err "Образ Psiphon рассчитан на x86_64 (сейчас $(uname -m))"
  exit 1
}

[[ "$PSIPHON_REGION" =~ ^[A-Z]{2}$ ]] || {
  err "PSIPHON_REGION должен быть двухбуквенным кодом, например DE"
  exit 1
}

# ------------------------------------------------------------
# ВСЕ ВОПРОСЫ — В НАЧАЛЕ
# ------------------------------------------------------------

echo -e "\e[1m=== Установка Remnawave-ноды ===\e[0m"
echo "Сначала задам все вопросы. После этого можно отойти —"
echo "установка пройдёт до конца без участия."
echo

LAST_COMPLETED_STEP=""

if [[ -f "$STATE_FILE" ]]; then

  # Файл root:root 600.
  # shellcheck disable=SC1090
  source "$STATE_FILE"

fi

# Явно переданные переменные важнее state.env.
reapply_explicit_inputs

recover_legacy_state

START_STEP=1

if [[ -e "$STATE_FILE" ||
      -e "$NODE_DIR/docker-compose.yml" ]] ||
   {
     command -v docker >/dev/null 2>&1 &&
     docker inspect vps-psiphon >/dev/null 2>&1
   }
then

  echo -e "  \e[1mНайдена предыдущая установка.\e[0m" >"$TTY"

  echo "  1 — продолжить с первого незавершённого этапа (рекомендуется)" >"$TTY"
  echo "  2 — переустановить компоненты ноды с нуля" >"$TTY"
  echo "      (SSH, сертификаты и системные пакеты сохранятся)" >"$TTY"
  echo "  3 — выйти без изменений" >"$TTY"

  ask install_choice "Выбери действие [1]: " 1

  case "$install_choice" in

    1)

      LAST_COMPLETED_STEP="${LAST_COMPLETED_STEP:-0}"

      if [[ ! "$LAST_COMPLETED_STEP" =~ ^([0-9]|10)$ ]]; then

        warn "Состояние предыдущего запуска повреждено; начинаю с этапа 1"

        LAST_COMPLETED_STEP=0

      fi

      if ((LAST_COMPLETED_STEP >= TOTAL)); then

        # Позволяем явно переданным параметрам всё-таки
        # переприменить соответствующий этап.

        FORCED_STEP=999

        if [[ -n "$DOMAIN_EXPLICIT" ]]; then
          FORCED_STEP=3
        fi

        if [[ -n "$SSH_PORT_EXPLICIT" &&
              "$FORCED_STEP" -gt 5 ]]; then
          FORCED_STEP=5
        fi

        if [[ ( -n "$NODE_PORT_EXPLICIT" ||
                -n "$SECRET_KEY_EXPLICIT" ) &&
              "$FORCED_STEP" -gt 2 ]]; then
          FORCED_STEP=2
        fi

        if [[ -n "$SHAPER_ENABLED_EXPLICIT" &&
              "$FORCED_STEP" -gt 10 ]]; then
          FORCED_STEP=10
        fi

        if ((FORCED_STEP <= TOTAL)); then

          START_STEP="$FORCED_STEP"

          info "Явные параметры требуют повторного запуска с этапа $START_STEP/$TOTAL"

        else

          ok "Все $TOTAL этапов уже были успешно завершены"

          exit 0

        fi

      else

        START_STEP=$((LAST_COMPLETED_STEP + 1))

        info "Продолжаю с этапа $START_STEP/$TOTAL"

      fi
      ;;


    2)

      warn "Очищаю компоненты RemnaNode/Psiphon/шейпера; SSH и сертификаты сохраняются"

      backup_and_reset_components

      if [[ -n "$DOMAIN_EXPLICIT" ]]; then
        DOMAIN="$DOMAIN_INPUT"
      else
        DOMAIN=""
      fi

      if [[ -n "$SSH_PORT_EXPLICIT" ]]; then
        SSH_PORT="$SSH_PORT_INPUT"
      else
        SSH_PORT=""
      fi

      if [[ -n "$SECRET_KEY_EXPLICIT" ]]; then
        SECRET_KEY="$SECRET_KEY_INPUT"
      else
        SECRET_KEY=""
      fi

      if [[ -n "$NODE_PORT_EXPLICIT" ]]; then
        NODE_PORT="$NODE_PORT_INPUT"
      else
        NODE_PORT=9744
      fi

      if [[ -n "$SHAPER_ENABLED_EXPLICIT" ]]; then
        SHAPER_ENABLED="$SHAPER_ENABLED_INPUT"
      else
        SHAPER_ENABLED=""
      fi

      START_STEP=1
      ;;


    3)

      exit 0
      ;;


    *)

      err "Нужно выбрать 1, 2 или 3"

      exit 1
      ;;

  esac

fi

# ------------------------------------------------------------
# 1. ДОМЕН
# ------------------------------------------------------------

while [[ -z "$DOMAIN" ]]; do
  ask DOMAIN "Домен ноды (напр. node.example.com): "
done

# ------------------------------------------------------------
# 2. SSH
#
# На чистой машине SSH_PORT здесь ПУСТОЙ.
# Поэтому 22 НЕ подхватывается.
#
# Enter => 48522.
# ------------------------------------------------------------

if [[ -z "$SSH_PORT" ]]; then
  ask SSH_PORT "SSH-порт [48522]: " 48522
fi

# ------------------------------------------------------------
# 3. SECRET_KEY
# ------------------------------------------------------------

while [[ -z "$SECRET_KEY" ]]; do

  ask_secret \
    SECRET_KEY \
    "SECRET_KEY ноды (ввод скрыт): "

done

# ------------------------------------------------------------
# 4. ШЕЙПИНГ
# ------------------------------------------------------------

if [[ -z "$SHAPER_ENABLED" ]]; then

  echo "  Шейпинг ограничивает только массовую закачку (игры, огромные файлы)." >"$TTY"
  echo "  Стриминг, соцсети и обновления приложений под лимит не попадают." >"$TTY"

  ask \
    shaper_answer \
    "Включить шейпинг? [y/N]: " \
    "n"

  case "${shaper_answer,,}" in

    n|no|н|нет)
      SHAPER_ENABLED=0
      ;;

    *)
      SHAPER_ENABLED=1
      ;;

  esac

fi

# ------------------------------------------------------------
# ВАЛИДАЦИЯ
# ------------------------------------------------------------

[[ "$SHAPER_ENABLED" =~ ^[01]$ ]] || {
  err "SHAPER_ENABLED должен быть 0 или 1"
  exit 1
}

[[ "$SSH_PORT" =~ ^[0-9]+$ &&
   "$SSH_PORT" -ge 1 &&
   "$SSH_PORT" -le 65535 ]] || {

  err "Некорректный SSH-порт: $SSH_PORT"
  exit 1

}

[[ "$NODE_PORT" =~ ^[0-9]+$ &&
   "$NODE_PORT" -ge 1 &&
   "$NODE_PORT" -le 65535 ]] || {

  err "Некорректный NODE_PORT: $NODE_PORT"
  exit 1

}

[[ "$SSH_PORT" != "$NODE_PORT" ]] || {

  err "SSH_PORT и NODE_PORT не должны совпадать ($SSH_PORT)"
  exit 1

}

if [[ "$SHAPER_ENABLED" == 1 ]]; then

  for shaper_value in \
    SHAPER_DOWN_MBPS \
    SHAPER_UP_MBPS \
    SHAPER_PENALTY_MBPS \
    SHAPER_BURST_MB
  do

    [[ "${!shaper_value}" =~ ^[0-9]+([.][0-9]+)?$ ]] &&
      awk \
        -v value="${!shaper_value}" \
        'BEGIN { exit !(value > 0) }' || {

      err "$shaper_value должен быть положительным числом"
      exit 1

    }

  done

  for shaper_value in \
    SHAPER_WINDOW_SEC \
    SHAPER_PENALTY_SEC
  do

    [[ "${!shaper_value}" =~ ^[0-9]+$ &&
       "${!shaper_value}" -gt 0 ]] || {

      err "$shaper_value должен быть положительным целым числом"
      exit 1

    }

  done

  IFS=',' read -r -a shaper_ports_array <<<"$SHAPER_PORTS"

  [[ ${#shaper_ports_array[@]} -gt 0 ]] || {

    err "SHAPER_PORTS не задан"
    exit 1

  }

  for shaper_port in "${shaper_ports_array[@]}"; do

    [[ "$shaper_port" =~ ^[0-9]+$ &&
       "$shaper_port" -ge 0 &&
       "$shaper_port" -le 65535 ]] || {

      err "Некорректный порт шейпера: $shaper_port"
      exit 1

    }

  done

fi

[[ "$SECRET_KEY" != *[[:space:]]* ]] || {

  err "SECRET_KEY содержит пробел или перенос строки"
  exit 1

}

printf '%s' "$SECRET_KEY" |
  base64 -d >/dev/null 2>&1 || {

  err "SECRET_KEY не похож на корректный base64-ключ Remnawave"
  exit 1

}

# ------------------------------------------------------------
# docker-compose
# ------------------------------------------------------------

command -v python3 >/dev/null || apt-get -o DPkg::Lock::Timeout=300 install -y python3
rn_ask PANEL_IPS 'IP панели (IPv4/IPv6 через пробел)'
PANEL_IPS="$(rn_ips "$PANEL_IPS")"

mkdir -p "$NODE_DIR"
mkdir -p /var/log/remnanode
mkdir -p "$SSL_DIR"

if [[ -e "$NODE_DIR/docker-compose.yml" ]]; then

  cp -a \
    "$NODE_DIR/docker-compose.yml" \
    "$NODE_DIR/docker-compose.yml.bak.$(date +%Y%m%d-%H%M%S)"

fi

if [[ ! -e "$NODE_DIR/docker-compose.yml" ]]; then
OLD_UMASK="$(umask)"

umask 077

cat >"$NODE_DIR/docker-compose.yml" <<EOF
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    network_mode: host
    restart: always
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"

    cap_add:
      - NET_ADMIN

    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576

    environment:
      NODE_PORT: "$NODE_PORT"
      SECRET_KEY: "$SECRET_KEY"

    volumes:
      - "/var/log/remnanode:/var/log/remnanode"
      - "/etc/letsencrypt:/etc/letsencrypt:ro"
      - "$SSL_DIR:$SSL_DIR:ro"
EOF

chmod 600 "$NODE_DIR/docker-compose.yml"

umask "$OLD_UMASK"
else
  info "Существующий compose сохранён"
fi


# ------------------------------------------------------------
# Итог параметров
# ------------------------------------------------------------

echo

echo -e "  \e[1mБудет установлено со следующими параметрами:\e[0m"

info "Домен:            $DOMAIN"

info "SSH порт:         $SSH_PORT"

if [[ "$NODE_PORT" == 2222 ]]; then

  info "Порт API ноды:    $NODE_PORT (дефолт Remnawave)"

else

  info "Порт API ноды:    $NODE_PORT  \e[1;33m← В ПАНЕЛИ УКАЗАТЬ ТОТ ЖЕ ПОРТ\e[0m"

fi

info "SECRET_KEY:       получен (значение скрыто)"

info "compose:          сгенерирован скриптом"

info "Psiphon:          $PSIPHON_REGION, SOCKS $PSIPHON_SOCKS_HOST:$PSIPHON_SOCKS_PORT"

info "XHTTP:            $XHTTP_PATH → 127.0.0.1:$XHTTP_PORT"

info "Hysteria2:        UDP/443, сертификат $SSL_DIR/"

if [[ "$SHAPER_ENABLED" == 1 ]]; then

  info "Шейпинг:          динамический, порты $SHAPER_PORTS"

  info "Скорость:         $SHAPER_DOWN_MBPS/$SHAPER_UP_MBPS МБ/с"

  info "После $SHAPER_BURST_MB МБ за $SHAPER_WINDOW_SEC с: $SHAPER_PENALTY_MBPS МБ/с на $SHAPER_PENALTY_SEC с"

else

  info "Шейпинг:          ОТКЛЮЧЁН"

fi

echo -e "  \e[33mВвод данных завершён. Дальше можно не вмешиваться.\e[0m"

sleep 2

start_install_log

STEP=$((START_STEP - 1))

# ============================================================
# ЭТАП 1
# ============================================================

if ((START_STEP <= 1)); then

  step "Docker"

  if ! command -v docker >/dev/null 2>&1; then

    info "Устанавливаю Docker..."

    # НЕ curl | sh.
    # Иначе вложенный sh способен читать основной install.sh из stdin.
    run_remote_script \
      sh \
      https://get.docker.com

  else

    ok "Docker уже установлен"

  fi

  systemctl enable --now docker

  info "Проверяю Docker Engine и Compose..."
  docker version
  docker compose version
  docker info --format 'Driver={{.Driver}}; Containers={{.Containers}}'

  cd "$NODE_DIR"

  info "Проверяю Compose без вывода SECRET_KEY..."
  docker compose config --quiet

  ok "docker-compose.yml прошёл проверку"
  ok "Docker запущен"

  save_state 1

fi

# ============================================================
# ЭТАП 2
# ============================================================

if ((START_STEP <= 2)); then

  step "Запуск ноды"

  cd "$NODE_DIR"

  info "Загружаю образ и поднимаю контейнер..."

  docker compose \
    up \
    -d \
    --no-recreate

  REMNA_MOUNTS="$(
    docker inspect \
      remnanode \
      --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
  )"

  grep -F \
    '/var/log/remnanode -> /var/log/remnanode' \
    <<<"$REMNA_MOUNTS" >/dev/null || {

    err "Каталог /var/log/remnanode не смонтирован в контейнер"
    exit 1

  }

  docker inspect \
    -f '{{.State.Running}}' \
    remnanode |
    grep -qx true || {

    err "Контейнер remnanode не запущен"
    exit 1

  }

  printf '%s\n' "$REMNA_MOUNTS"
  docker compose ps
  ok "Нода запущена"

  save_state 2

fi

# ============================================================
# ЭТАП 3
# ============================================================

if ((START_STEP <= 3)); then

  step "nginx + certbot + сертификат"

  info "Устанавливаю nginx, certbot и logrotate..."

  apt_run update

  apt_run install -y \
    nginx \
    certbot \
    logrotate

  install -d -m 755 /var/www/html

  # ----------------------------------------------------------
  # HTML-заглушка
  # ----------------------------------------------------------

  cat >/var/www/html/index.html <<'HTML'
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Доступ к серверу</title>

<style>
* {
  box-sizing: border-box;
}

html,
body {
  height: 100%;
}

body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;

  font-family:
    ui-sans-serif,
    system-ui,
    -apple-system,
    "Segoe UI",
    Roboto,
    Arial,
    "Noto Sans",
    "Liberation Sans",
    sans-serif;

  color: #4a5568;
  background: #e3e8ef;
}

.stage {
  position: relative;
  z-index: 1;
  display: flex;
  width: min(460px, 94vw);
}

.card {
  position: relative;
  flex: 1;
  min-width: 0;

  background: #e3e8ef;
  border: 0;
  border-radius: 22px;
  overflow: hidden;

  box-shadow:
    9px 9px 20px #bcc4d0,
    -9px -9px 20px #ffffff;
}

.card-head {
  display: none;
}

.card-body {
  padding: 32px 30px 28px;
}

.eyebrow {
  display: block;
  margin: 0 0 10px;

  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    Consolas,
    "Liberation Mono",
    monospace;

  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 2px;

  color: #5b7cfa;
}

h1 {
  margin: 0 0 8px;

  font-size: 26px;
  font-weight: 650;
  letter-spacing: .2px;

  color: #4a5568;
}

.subtitle {
  margin: 0 0 24px;

  color: #717c91;
  line-height: 1.45;
  font-size: 14px;
}

.field {
  margin: 16px 0;
}

label {
  display: block;
  margin: 0 0 8px;

  font-size: 12px;
  font-weight: 600;
  color: #717c91;
}

.input {
  display: flex;
  align-items: center;
  gap: 11px;

  padding: 12px 14px;

  background: #e3e8ef;
  border: 0;
  border-radius: 14px;

  box-shadow:
    inset 4px 4px 9px #bcc4d0,
    inset -4px -4px 9px #ffffff;

  transition:
    box-shadow .15s ease,
    background .15s ease;
}

.input:focus-within {
  box-shadow:
    inset 3px 3px 7px #bcc4d0,
    inset -3px -3px 7px #ffffff,
    0 0 0 2px rgba(91,124,250,.12);
}

.icon {
  width: 18px;
  height: 18px;
  flex: 0 0 auto;

  color: #9aa3b5;
}

.input:focus-within .icon {
  color: #5b7cfa;
}

input {
  width: 100%;
  border: 0;
  outline: none;

  background: transparent;
  color: #4a5568;

  font-size: 14px;
  font-family: inherit;
}

input::placeholder {
  color: #a7afbf;
}

.btn {
  margin-top: 22px;
  width: 100%;

  border: 0;
  padding: 13px 14px;

  border-radius: 14px;

  color: #ffffff;
  background: #5b7cfa;

  font-weight: 700;
  font-size: 14px;
  letter-spacing: .3px;

  cursor: pointer;

  box-shadow:
    6px 6px 14px #bcc4d0,
    -6px -6px 14px #ffffff;

  transition:
    transform .06s ease,
    filter .15s ease,
    box-shadow .15s ease;
}

.btn:hover {
  filter: brightness(1.04);
}

.btn:active {
  transform: translateY(1px);

  box-shadow:
    3px 3px 8px #bcc4d0,
    -3px -3px 8px #ffffff;
}

.captcha-box {
  padding: 15px;

  border-radius: 14px;
  background: #e3e8ef;
  border: 1px dashed #bcc4d0;

  box-shadow:
    inset 3px 3px 7px #ccd3dd,
    inset -3px -3px 7px #ffffff;
}

.captcha-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.captcha-label {
  margin-bottom: 6px;

  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    Consolas,
    "Liberation Mono",
    monospace;

  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;

  color: #717c91;
}

.captcha-q {
  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    Consolas,
    "Liberation Mono",
    monospace;

  font-size: 16px;
  font-weight: 700;
  color: #4a5568;
}

.btn-ghost {
  border: 0;

  background: #e3e8ef;
  color: #717c91;

  padding: 9px 12px;
  border-radius: 14px;

  font-weight: 600;
  font-size: 13px;
  cursor: pointer;

  box-shadow:
    4px 4px 10px #bcc4d0,
    -4px -4px 10px #ffffff;
}

.btn-ghost:hover {
  color: #5b7cfa;
}

.hint {
  margin: 16px 0 0;

  font-size: 12px;
  color: #9aa3b5;
  text-align: center;
}

.toast {
  position: fixed;
  left: 50%;
  bottom: 24px;

  transform: translateX(-50%) translateY(8px);

  display: flex;
  align-items: center;
  gap: 9px;

  background: #e3e8ef;
  border: 1px solid #bcc4d0;
  border-left: 3px solid #e5746e;

  color: #4a5568;

  padding: 11px 15px;
  border-radius: 14px;

  box-shadow:
    0 18px 40px -12px rgba(0,0,0,.25);

  font-size: 13px;

  opacity: 0;
  pointer-events: none;

  transition:
    opacity .2s ease,
    transform .2s ease;
}

.toast::before {
  content: "";

  width: 7px;
  height: 7px;

  border-radius: 50%;
  background: #e5746e;

  flex: 0 0 auto;
}

.toast.show {
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}
</style>
</head>

<body>

<div class="stage">
  <main class="card" role="main" aria-label="Форма доступа">

    <div class="card-body">

      <p class="eyebrow">Авторизация</p>

      <h1>Доступ к серверу</h1>

      <p class="subtitle">
        Для доступа к серверу, введите логин и пароль.
      </p>

      <form id="fakeLoginForm" autocomplete="off">

        <div class="field">
          <label for="login">Логин</label>

          <div class="input">
            <svg
              class="icon"
              viewBox="0 0 24 24"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M12 12a4.5 4.5 0 1 0-4.5-4.5A4.5 4.5 0 0 0 12 12Z"
                stroke="currentColor"
                stroke-width="1.7"
              />
              <path
                d="M4 20c1.6-3.5 5-5.5 8-5.5s6.4 2 8 5.5"
                stroke="currentColor"
                stroke-width="1.7"
                stroke-linecap="round"
              />
            </svg>

            <input
              id="login"
              name="login"
              placeholder="Введите логин"
            />
          </div>
        </div>

        <div class="field">
          <label for="password">Пароль</label>

          <div class="input">
            <svg
              class="icon"
              viewBox="0 0 24 24"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M7.5 11V8.5a4.5 4.5 0 0 1 9 0V11"
                stroke="currentColor"
                stroke-width="1.7"
                stroke-linecap="round"
              />
              <path
                d="M6.5 11h11a1.5 1.5 0 0 1 1.5 1.5v6A1.5 1.5 0 0 1 17.5 20h-11A1.5 1.5 0 0 1 5 18.5v-6A1.5 1.5 0 0 1 6.5 11Z"
                stroke="currentColor"
                stroke-width="1.7"
              />
              <path
                d="M12 15v2"
                stroke="currentColor"
                stroke-width="1.7"
                stroke-linecap="round"
              />
            </svg>

            <input
              id="password"
              name="password"
              type="password"
              placeholder="Введите пароль"
            />
          </div>
        </div>

        <button class="btn" type="submit">
          Войти
        </button>

        <div
          id="captchaWrap"
          style="display:none;margin-top:16px;"
        >
          <div class="captcha-box">

            <div class="captcha-top">
              <div>
                <div class="captcha-label">
                  Проверка безопасности
                </div>

                <div
                  id="captchaQuestion"
                  class="captcha-q"
                >
                  —
                </div>
              </div>

              <button
                id="captchaRefresh"
                type="button"
                class="btn-ghost"
              >
                Обновить
              </button>
            </div>

            <div style="margin-top:16px;">
              <label for="captchaAnswer">
                Ответ
              </label>

              <div class="input">
                <input
                  id="captchaAnswer"
                  inputmode="numeric"
                  placeholder="Введите число"
                />
              </div>
            </div>

            <p class="hint">
              После 2 неверных попыток входа нужно решить пример.
            </p>

          </div>
        </div>

      </form>

    </div>
  </main>
</div>

<div
  class="toast"
  id="toast"
  role="status"
  aria-live="polite"
></div>

<script>
const form = document.getElementById('fakeLoginForm');
const toast = document.getElementById('toast');

const captchaWrap =
  document.getElementById('captchaWrap');

const captchaQuestion =
  document.getElementById('captchaQuestion');

const captchaAnswer =
  document.getElementById('captchaAnswer');

const captchaRefresh =
  document.getElementById('captchaRefresh');

let attempts = 0;

let captcha = {
  a: 0,
  b: 0,
  op: '+',
  result: 0
};

function showToast(text) {
  toast.textContent = text;
  toast.classList.add('show');

  clearTimeout(showToast._t);

  showToast._t = setTimeout(() => {
    toast.classList.remove('show');
  }, 2600);
}

function randInt(min, max) {
  return Math.floor(
    Math.random() * (max - min + 1)
  ) + min;
}

function newCaptcha() {
  const mode = randInt(1, 3);

  if (mode === 1) {
    captcha.a = randInt(12, 98);
    captcha.b = randInt(11, 97);
    captcha.op = '+';
    captcha.result = captcha.a + captcha.b;
  }

  else if (mode === 2) {
    captcha.a = randInt(30, 99);
    captcha.b = randInt(10, 29);
    captcha.op = '−';
    captcha.result = captcha.a - captcha.b;
  }

  else {
    captcha.a = randInt(4, 12);
    captcha.b = randInt(6, 14);
    captcha.op = '×';
    captcha.result = captcha.a * captcha.b;
  }

  captchaQuestion.textContent =
    `Решите: ${captcha.a} ${captcha.op} ${captcha.b} = ?`;

  captchaAnswer.value = '';
}

function captchaIsRequired() {
  return attempts >= 2;
}

function captchaIsSolved() {
  const value = (captchaAnswer.value || '').trim();

  if (!value) {
    return false;
  }

  const number = Number(value);

  return Number.isFinite(number) &&
    number === captcha.result;
}

function showCaptchaIfNeeded() {
  if (captchaIsRequired()) {
    captchaWrap.style.display = 'block';

    if (
      !captchaQuestion.textContent ||
      captchaQuestion.textContent === '—'
    ) {
      newCaptcha();
    }
  }
}

captchaRefresh.addEventListener('click', () => {
  newCaptcha();
  showToast('Капча обновлена.');
});

form.addEventListener('submit', (event) => {
  event.preventDefault();

  if (captchaIsRequired()) {
    showCaptchaIfNeeded();

    if (!captchaIsSolved()) {
      showToast(
        'Неверная капча. Попробуйте ещё раз.'
      );

      return;
    }
  }

  attempts += 1;

  showCaptchaIfNeeded();

  showToast(
    'Неверный логин или пароль.'
  );
});
</script>

</body>
</html>
HTML

  chmod 644 /var/www/html/index.html

  grep -Fq \
    '<h1>Доступ к серверу</h1>' \
    /var/www/html/index.html || {

    err "HTML-заглушка не записана"
    exit 1

  }

  ok "HTML-заглушка установлена"

  # ----------------------------------------------------------
  # logrotate
  # ----------------------------------------------------------

  cat >/etc/logrotate.d/remnanode <<'EOF'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF

  chmod 644 /etc/logrotate.d/remnanode

  logrotate \
    -d \
    /etc/logrotate.d/remnanode

  ok "Ротация логов RemnaNode настроена"

  # ----------------------------------------------------------
  # ACME
  #
  # Certbot НЕ трогает 443.
  #
  # Сертификат получается через webroot на TCP/80.
  # Поэтому RemnaNode/Xray может спокойно занимать TCP/443.
  # ----------------------------------------------------------

  systemctl enable --now nginx

  if command -v ufw >/dev/null 2>&1; then

    UFW_STATUS="$(
      ufw status 2>/dev/null || true
    )"

    if [[ "$UFW_STATUS" == *"Status: active"* ]]; then
      ufw allow 80/tcp
    fi

  fi

  cat >/etc/nginx/conf.d/remnanode-acme.conf <<EOF
server {
    listen 80;
    listen [::]:80;

    server_name $DOMAIN;

    root /var/www/html;

    location ^~ /.well-known/acme-challenge/ {
        try_files \$uri =404;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

  nginx -t

  systemctl reload nginx

  info "Получаю сертификат Let's Encrypt для $DOMAIN..."

  certbot \
    certonly \
    --webroot \
    --webroot-path /var/www/html \
    --cert-name "$DOMAIN" \
    -d "$DOMAIN" \
    --non-interactive \
    --agree-tos \
    --register-unsafely-without-email \
    --keep-until-expiring

  [[ -r "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" &&
     -r "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]] || {

    err "Let's Encrypt не создал сертификат"
    exit 1

  }

  ok "Сертификат получен"

  ln -sfn \
    "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" \
    "$SSL_DIR/fullchain.pem"

  ln -sfn \
    "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
    "$SSL_DIR/privkey.pem"

  ok "Сертификат доступен по общему пути $SSL_DIR/"

  mkdir -p \
    /etc/letsencrypt/renewal-hooks/deploy

  cat >/etc/letsencrypt/renewal-hooks/deploy/restart-remnanode.sh <<'EOF'
#!/bin/sh
set -e

nginx -t
systemctl reload nginx
docker restart remnanode
EOF

  chmod +x \
    /etc/letsencrypt/renewal-hooks/deploy/restart-remnanode.sh

  ok "Хук автопродления настроен"

  # Контейнер стартовал до появления сертификата.
  cd "$NODE_DIR"

  docker compose restart

  docker exec \
    remnanode \
    test -r "$SSL_DIR/fullchain.pem" || {

    err "Контейнер не видит $SSL_DIR/fullchain.pem"
    exit 1

  }

  docker exec \
    remnanode \
    test -r "$SSL_DIR/privkey.pem" || {

    err "Контейнер не видит $SSL_DIR/privkey.pem"
    exit 1

  }

  ok "Контейнер видит сертификат — Hysteria2 готова"

  save_state 3

fi

# ============================================================
# ЭТАП 4
# ============================================================

if ((START_STEP <= 4)); then

  step "Маскировка nginx"
  info "Формирую $NGX для домена $DOMAIN и XHTTP $XHTTP_PATH"

  if [[ -e "$NGX" ]]; then

    cp \
      "$NGX" \
      "${NGX}.bak.$(date +%s)"

  fi

  NGINX_VER="$(
    nginx -v 2>&1 |
      sed 's#.*nginx/##; s#[^0-9.].*##'
  )"

  if dpkg \
    --compare-versions \
    "$NGINX_VER" \
    ge \
    1.25.1
  then

    TLS_LISTEN="listen 127.0.0.1:8443 ssl;"
    HTTP2_DIRECTIVE="    http2 on;"

  else

    TLS_LISTEN="listen 127.0.0.1:8443 ssl http2;"
    HTTP2_DIRECTIVE=""

  fi

  # Управляем конфигом целиком.
  #
  # Это надёжнее sed-замены строк Certbot:
  # разные версии nginx/certbot генерируют разные варианты listen.
  cat >"$NGX" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name $DOMAIN;

    root /var/www/html;
    index index.html;

    location ^~ /.well-known/acme-challenge/ {
        try_files \$uri =404;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}

server {
    $TLS_LISTEN
$HTTP2_DIRECTIVE

    server_name $DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    root /var/www/html;
    index index.html;

    location $XHTTP_PATH {
        proxy_pass http://127.0.0.1:$XHTTP_PORT;

        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

        proxy_redirect off;

        proxy_buffering off;
        proxy_request_buffering off;

        proxy_read_timeout 300s;
        proxy_send_timeout 300s;

        chunked_transfer_encoding on;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

  rm -f \
    /etc/nginx/conf.d/remnanode-acme.conf

  nginx -t

  systemctl reload nginx

  sleep 1

  NGINX_LISTEN="$(
    ss -H -ltnp 2>/dev/null || true
  )"

  grep -E \
    '127\.0\.0\.1:8443([[:space:]]|$)' \
    <<<"$NGINX_LISTEN" >/dev/null || {

    err "nginx не слушает 127.0.0.1:8443"
    exit 1

  }

  if grep -E \
    '(:|\])443[[:space:]].*nginx' \
    <<<"$NGINX_LISTEN" >/dev/null
  then

    err "nginx ошибочно слушает внешний TCP/443"
    exit 1

  fi

  curl \
    -kfsS \
    --connect-timeout 5 \
    --max-time 10 \
    --resolve "$DOMAIN:8443:127.0.0.1" \
    "https://$DOMAIN:8443/" \
    -o /dev/null || {

    err "HTTPS-маскировка на 127.0.0.1:8443 не отвечает"
    exit 1

  }

  ok "nginx $NGINX_VER: HTTP/2 включён"
  ok "nginx слушает только 127.0.0.1:8443 для TLS"
  ok "XHTTP: $XHTTP_PATH → 127.0.0.1:$XHTTP_PORT"

  save_state 4

fi

# ============================================================
# ЭТАП 5
# ============================================================

if ((START_STEP <= 5)); then
  step "SSH: проверка существующего доступа"
  if [[ -n "$STANDARD_SSH_PUBLIC_KEY" ]]; then
    printf '%s\n' "$STANDARD_SSH_PUBLIC_KEY" | ssh-keygen -lf /dev/stdin >/dev/null
    install_standard_ssh_key
  fi
  RN_SSH_PORTS="$(rn_ssh_ports)"
  [[ -n "$RN_SSH_PORTS" ]] || { err 'Не найден SSH-порт'; exit 1; }
  sshd -t
  ok "SSH-порт $SSH_PORT выбран; key-only политика применяется следующим этапом"
  save_state 5
fi

# ============================================================
# ЭТАП 6
# ============================================================

if ((START_STEP <= 6)); then
  step "Файрвол: порт управления только для панели"
  rn_security
  save_state 6
fi

# ============================================================
# ЭТАП 7
# ============================================================

if ((START_STEP <= 7)); then
  step "Проверка Fail2ban SSH"
  fail2ban-client -t
  fail2ban-client status sshd
  ok "SSH jail запущен; баны не затрагивают VPN"
  save_state 7
fi

# ============================================================
# ЭТАП 8
# ============================================================

if ((START_STEP <= 8)); then
  step "Проверка защиты доступа"
  # Списки третьих лиц не применяются автоматически к действующему серверу.
  nft list table inet remnanode_control >/dev/null
  ok "Panel-only guard активен; traffic-guard автоматически не устанавливается"
  save_state 8
fi

# ============================================================
# ЭТАП 9
# ============================================================

if ((START_STEP <= 9)); then

  step "Psiphon для Gemini/Google"

  DOCKER_GATEWAY="$(
    docker network inspect \
      bridge \
      -f '{{(index .IPAM.Config 0).Gateway}}'
  )"

  [[ "$DOCKER_GATEWAY" == "$PSIPHON_SOCKS_HOST" ]] || {

    err "Docker gateway = $DOCKER_GATEWAY, ожидался $PSIPHON_SOCKS_HOST"
    exit 1

  }

  PSIPHON_INSTALLER_TMP="$(
    mktemp /tmp/vps-psiphon-installer.XXXXXX
  )"


  info "Загружаю зафиксированный installer Psiphon..."

  curl \
    -fsSL \
    "$PSIPHON_INSTALLER_URL" \
    -o "$PSIPHON_INSTALLER_TMP"

  echo \
    "$PSIPHON_INSTALLER_SHA256  $PSIPHON_INSTALLER_TMP" |
    sha256sum \
      --check \
      --status || {

    rm -f "$PSIPHON_INSTALLER_TMP"

    err "SHA256 installer Psiphon не совпала"

    exit 1

  }

  grep \
    -Fq \
    -- '-v "${CONF_DIR}:/config"' \
    "$PSIPHON_INSTALLER_TMP" || {

    rm -f "$PSIPHON_INSTALLER_TMP"

    err "Installer Psiphon не содержит bind-mount /config"

    exit 1

  }

  ok "SHA256 и обязательный bind-mount /config проверены"
  info "Загружаю образ Psiphon с отображением слоёв..."
  docker pull "$PSIPHON_IMAGE"
  info "Настраиваю Psiphon: регион $PSIPHON_REGION, SOCKS $PSIPHON_SOCKS_HOST:$PSIPHON_SOCKS_PORT, HTTP отключён"
  info "Upstream создаст /opt/vps-psiphon/config, службу и watchdog"

  # stdin закрыт специально:
  # installer не должен читать основной curl | bash.
  run_with_progress "Установка Psiphon" bash "$PSIPHON_INSTALLER_TMP" \
    --region "$PSIPHON_REGION" \
    --device-region "$PSIPHON_REGION" \
    --socks-port "$PSIPHON_SOCKS_PORT" \
    --no-http \
    --bind "$PSIPHON_SOCKS_HOST" \
    --image "$PSIPHON_IMAGE" \
    </dev/null

  rm -f "$PSIPHON_INSTALLER_TMP"

  PSIPHON_INSTALLER_TMP=""

  info "Проверяю автозапуск Psiphon и watchdog..."
  for psiphon_unit in vps-psiphon.service vps-psiphon-watchdog.timer; do
    info "$psiphon_unit: автозапуск и состояние"
    systemctl is-enabled "$psiphon_unit"
    systemctl is-active "$psiphon_unit"
  done
  PSIPHON_MOUNTS="$(docker inspect -f '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}' vps-psiphon)"
  printf '%s\n' "$PSIPHON_MOUNTS"
  grep -Fxq '/opt/vps-psiphon/config -> /config' <<<"$PSIPHON_MOUNTS" || {
    err "Psiphon не получил постоянный /config"
    exit 1
  }
  info "Для использования Psiphon профиль Xray должен направлять нужный трафик в SOCKS $PSIPHON_SOCKS_HOST:$PSIPHON_SOCKS_PORT."

  PSIPHON_HEALTH="$(
    docker inspect \
      -f '{{.State.Health.Status}}' \
      vps-psiphon \
      2>/dev/null || true
  )"

  if [[ "$PSIPHON_HEALTH" != "healthy" ]]; then

    info "Жду готовности Psiphon..."

    for psiphon_attempt in {1..30}; do

      sleep 2

      PSIPHON_HEALTH="$(
        docker inspect \
          -f '{{.State.Health.Status}}' \
          vps-psiphon \
          2>/dev/null || true
      )"

      info "Psiphon: ${PSIPHON_HEALTH:-контейнер пока недоступен}, проверка $psiphon_attempt/30"
      if [[ "$PSIPHON_HEALTH" == "healthy" ]]; then
        break
      fi

    done

  fi

  PSIPHON_HEALTH="$(
    docker inspect \
      -f '{{.State.Health.Status}}' \
      vps-psiphon \
      2>/dev/null || true
  )"

  [[ "$PSIPHON_HEALTH" == "healthy" ]] || {

    docker logs \
      --tail 100 \
      vps-psiphon >&2 || true

    err "Psiphon не перешёл в healthy"

    exit 1

  }

  PSIPHON_TRACE=""
  PSIPHON_GEMINI_OK=0

  for psiphon_attempt in {1..6}; do

    info "Проверяю регион и HTTP через SOCKS: попытка $psiphon_attempt/6"

    PSIPHON_TRACE="$(
      curl \
        -fsS \
        --connect-timeout 5 \
        --max-time 20 \
        --socks5-hostname "$PSIPHON_SOCKS_HOST:$PSIPHON_SOCKS_PORT" \
        https://www.cloudflare.com/cdn-cgi/trace || true
    )"

    if grep \
         -qx \
         "loc=$PSIPHON_REGION" \
         <<<"$PSIPHON_TRACE" &&
       curl \
         -L \
         -fsS \
         --connect-timeout 5 \
         --max-time 20 \
         --socks5-hostname "$PSIPHON_SOCKS_HOST:$PSIPHON_SOCKS_PORT" \
         -o /dev/null \
         -w 'Gemini HTTP: %{http_code}\n' \
         https://gemini.google.com/app
    then

      PSIPHON_GEMINI_OK=1

      break

    fi

    sleep 5

  done

  grep \
    -qx \
    "loc=$PSIPHON_REGION" \
    <<<"$PSIPHON_TRACE" || {

    err "Psiphon exit не соответствует региону $PSIPHON_REGION"
    exit 1

  }

  [[ "$PSIPHON_GEMINI_OK" == 1 ]] || {

    err "Gemini не открывается через Psiphon"
    exit 1

  }

  ok "Psiphon healthy"
  ok "SOCKS: $PSIPHON_SOCKS_HOST:$PSIPHON_SOCKS_PORT"
  ok "Exit: $PSIPHON_REGION"
  ok "Gemini через SOCKS отвечает"

  save_state 9

fi

# ============================================================
# ЭТАП 10
# ============================================================

if ((START_STEP <= 10)); then

  if [[ "$SHAPER_ENABLED" == 1 ]]; then

    step "Динамический шейпинг"

    KERNEL_VERSION="$(
      uname -r |
        cut -d- -f1
    )"

    dpkg \
      --compare-versions \
      "$KERNEL_VERSION" \
      ge \
      5.4 || {

      err "Нужно ядро Linux 5.4+ (сейчас $KERNEL_VERSION)"
      exit 1

    }

    if [[ -z "$SHAPER_IFACE" ]]; then
      SHAPER_IFACE="$(default_interface)"
    fi

    [[ -n "$SHAPER_IFACE" &&
       -d "/sys/class/net/$SHAPER_IFACE" ]] || {

      err "Не удалось определить основной интерфейс"
      exit 1

    }

    [[ ! "$SHAPER_IFACE" =~ ^(lo|docker.*|br-.*|veth.*)$ ]] || {

      err "Интерфейс $SHAPER_IFACE нельзя использовать"
      exit 1

    }

    info "Основной интерфейс: $SHAPER_IFACE"

    apt_run install -y \
      clang \
      llvm \
      libbpf-dev \
      python3 \
      iproute2

    # Ubuntu иногда не даёт установить "bpftool" напрямую
    # и требует linux-tools для текущего ядра.
    if ! command -v bpftool >/dev/null 2>&1; then

      info "Устанавливаю bpftool..."

      if apt_run install -y bpftool; then
        :
      else

        warn "Пакет bpftool напрямую недоступен — пробую linux-tools"

        apt_run install -y \
          linux-tools-common \
          linux-tools-generic || true

        apt_run install -y \
          "linux-tools-$(uname -r)" || true

      fi

    fi

    BPFTOOL_BIN="$(
      command -v bpftool 2>/dev/null || true
    )"

    [[ -n "$BPFTOOL_BIN" ]] || {

      err "bpftool не удалось установить"
      exit 1

    }

    mkdir -p \
      "$SHAPER_DIR" \
      "$SHAPER_CONFIG_DIR" \
      /sys/fs/bpf

    mountpoint \
      -q \
      /sys/fs/bpf ||
      mount \
        -t bpf \
        bpf \
        /sys/fs/bpf

    info "Загружаю зафиксированные исходники eBPF..."

    curl \
      -fsSL \
      "https://raw.githubusercontent.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga/$RESHALA_COMMIT/modules/local/shaper.bpf.c" \
      -o "$SHAPER_DIR/shaper.bpf.c"

    curl \
      -fsSL \
      "https://raw.githubusercontent.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga/$RESHALA_COMMIT/modules/local/reshala_ctrl.py" \
      -o "$SHAPER_DIR/reshala_ctrl.py"

    echo \
      "$SHAPER_BPF_SHA256  $SHAPER_DIR/shaper.bpf.c" |
      sha256sum \
        --check \
        --status || {

      err "SHA256 shaper.bpf.c не совпала"
      exit 1

    }

    echo \
      "$SHAPER_CTRL_SHA256  $SHAPER_DIR/reshala_ctrl.py" |
      sha256sum \
        --check \
        --status || {

      err "SHA256 reshala_ctrl.py не совпала"
      exit 1

    }

    chmod 644 \
      "$SHAPER_DIR/shaper.bpf.c"

    chmod 755 \
      "$SHAPER_DIR/reshala_ctrl.py"

    ARCH_INCLUDE=""

    for include_dir in \
      "/usr/include/$(uname -m)-linux-gnu" \
      /usr/include/aarch64-linux-gnu \
      /usr/include/x86_64-linux-gnu \
      /usr/include/arm-linux-gnueabihf
    do

      if [[ -f "$include_dir/asm/types.h" ]]; then

        ARCH_INCLUDE="-I$include_dir"

        break

      fi

    done

    [[ -n "$ARCH_INCLUDE" ]] || {

      err "Не найден asm/types.h"
      exit 1

    }

    info "Компилирую eBPF..."

    clang \
      -O2 \
      -g \
      -target bpf \
      "$ARCH_INCLUDE" \
      -c "$SHAPER_DIR/shaper.bpf.c" \
      -o "$SHAPER_DIR/shaper.bpf.o"

    [[ -s "$SHAPER_DIR/shaper.bpf.o" ]] || {

      err "eBPF-объект не собран"
      exit 1

    }

    if [[ -e "/etc/systemd/system/$SHAPER_SERVICE" ]]; then

      cp -a \
        "/etc/systemd/system/$SHAPER_SERVICE" \
        "/etc/systemd/system/$SHAPER_SERVICE.bak.$(date +%Y%m%d-%H%M%S)"

    fi

    if [[ -e "$SHAPER_CONFIG_DIR/rules.json" ]]; then

      cp -a \
        "$SHAPER_CONFIG_DIR/rules.json" \
        "$SHAPER_CONFIG_DIR/rules.json.bak.$(date +%Y%m%d-%H%M%S)"

    fi

    systemctl stop \
      "$SHAPER_SERVICE" \
      2>/dev/null || true

    TC_BIN="$(
      command -v tc
    )"

    PYTHON_BIN="$(
      command -v python3
    )"

    cat >"/etc/systemd/system/$SHAPER_SERVICE" <<EOF
[Unit]
Description=RemnaNode dynamic eBPF traffic shaper
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStartPre=-/usr/bin/mount -t bpf bpf /sys/fs/bpf
ExecStartPre=-$TC_BIN qdisc del dev $SHAPER_IFACE root
ExecStartPre=-$TC_BIN qdisc del dev $SHAPER_IFACE clsact
ExecStartPre=-/usr/bin/rm -rf $SHAPER_PIN_DIR

ExecStartPre=/usr/bin/mkdir -p $SHAPER_PIN_DIR/progs $SHAPER_PIN_DIR/maps

ExecStartPre=$BPFTOOL_BIN --debug prog loadall $SHAPER_DIR/shaper.bpf.o $SHAPER_PIN_DIR/progs type classifier pinmaps $SHAPER_PIN_DIR/maps

ExecStartPre=$TC_BIN qdisc add dev $SHAPER_IFACE root fq
ExecStartPre=$TC_BIN qdisc add dev $SHAPER_IFACE clsact

ExecStartPre=/bin/bash -c 'p=\$(find $SHAPER_PIN_DIR/progs -maxdepth 1 -type f -name "*down*" -print -quit); test -n "\$p" && exec $TC_BIN filter add dev $SHAPER_IFACE egress bpf direct-action pinned "\$p"'

ExecStartPre=/bin/bash -c 'p=\$(find $SHAPER_PIN_DIR/progs -maxdepth 1 -type f -name "*up*" -print -quit); test -n "\$p" && exec $TC_BIN filter add dev $SHAPER_IFACE ingress bpf direct-action pinned "\$p"'

ExecStart=$PYTHON_BIN $SHAPER_DIR/reshala_ctrl.py --pin-dir $SHAPER_PIN_DIR/maps --rules-file $SHAPER_CONFIG_DIR/rules.json restore

ExecStop=-$TC_BIN qdisc del dev $SHAPER_IFACE root
ExecStop=-$TC_BIN qdisc del dev $SHAPER_IFACE clsact
ExecStop=-/usr/bin/rm -rf $SHAPER_PIN_DIR

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 \
      "/etc/systemd/system/$SHAPER_SERVICE"

    cat >"$SHAPER_CONFIG_DIR/settings.conf" <<EOF
SHAPER_IFACE=$SHAPER_IFACE
SHAPER_PORTS=$SHAPER_PORTS
SHAPER_DOWN_MBPS=$SHAPER_DOWN_MBPS
SHAPER_UP_MBPS=$SHAPER_UP_MBPS
SHAPER_PENALTY_MBPS=$SHAPER_PENALTY_MBPS
SHAPER_BURST_MB=$SHAPER_BURST_MB
SHAPER_WINDOW_SEC=$SHAPER_WINDOW_SEC
SHAPER_PENALTY_SEC=$SHAPER_PENALTY_SEC
RESHALA_COMMIT=$RESHALA_COMMIT
EOF

    chmod 600 \
      "$SHAPER_CONFIG_DIR/settings.conf"

    systemctl daemon-reload

    if systemctl enable \
      --now \
      "$SHAPER_SERVICE"
    then
      :
    else

      journalctl \
        -u "$SHAPER_SERVICE" \
        --no-pager \
        -n 100 >&2 || true

      err "Служба eBPF-шейпера не запустилась"

      exit 1

    fi

    [[ -e "$SHAPER_PIN_DIR/maps/config_map" ]] || {

      journalctl \
        -u "$SHAPER_SERVICE" \
        --no-pager \
        -n 100 >&2 || true

      err "eBPF maps не созданы"

      exit 1

    }

    # stdin закрыт:
    # если вдруг в rules.json конфликт портов, Python не имеет права
    # начать читать остаток основного curl | bash.
    if "$PYTHON_BIN" \
      "$SHAPER_DIR/reshala_ctrl.py" \
      --pin-dir "$SHAPER_PIN_DIR/maps" \
      --rules-file "$SHAPER_CONFIG_DIR/rules.json" \
      set \
      --rule-id 0 \
      --mode 2 \
      --ports "$SHAPER_PORTS" \
      --down "$SHAPER_DOWN_MBPS" \
      --up "$SHAPER_UP_MBPS" \
      --pen "$SHAPER_PENALTY_MBPS" \
      --burst "$SHAPER_BURST_MB" \
      --win "$SHAPER_WINDOW_SEC" \
      --pen-sec "$SHAPER_PENALTY_SEC" \
      </dev/null
    then
      :
    else

      err "Не удалось применить правило шейпера"
      exit 1

    fi

    systemctl is-active \
      --quiet \
      "$SHAPER_SERVICE" || {

      err "Служба шейпера не active"
      exit 1

    }

    TC_EGRESS="$(
      "$TC_BIN" \
        filter show \
        dev "$SHAPER_IFACE" \
        egress \
        2>/dev/null || true
    )"

    grep \
      -F \
      'bpf' \
      <<<"$TC_EGRESS" >/dev/null || {

      err "Download-фильтр eBPF не подключён"
      exit 1

    }

    TC_INGRESS="$(
      "$TC_BIN" \
        filter show \
        dev "$SHAPER_IFACE" \
        ingress \
        2>/dev/null || true
    )"

    grep \
      -F \
      'bpf' \
      <<<"$TC_INGRESS" >/dev/null || {

      err "Upload-фильтр eBPF не подключён"
      exit 1

    }

    ok "Динамический шейпинг активен"
    ok "DL/UL: $SHAPER_DOWN_MBPS/$SHAPER_UP_MBPS МБ/с"
    ok "Штраф: $SHAPER_PENALTY_MBPS МБ/с"

  else

    step "Отключение шейпинга"

    SHAPER_IFACE_OLD=""

    if [[ -f "$SHAPER_CONFIG_DIR/settings.conf" ]]; then

      SHAPER_IFACE_OLD="$(
        awk -F= '
          $1 == "SHAPER_IFACE" && iface == "" {
            iface=$2
          }

          END {
            if (iface != "")
              print iface
          }
        ' "$SHAPER_CONFIG_DIR/settings.conf" 2>/dev/null || true
      )"

    fi

    if systemctl cat \
      "$SHAPER_SERVICE" \
      >/dev/null 2>&1
    then

      systemctl disable \
        --now \
        "$SHAPER_SERVICE" \
        2>/dev/null || true

      ok "Служба шейпера остановлена"

    fi

    SHAPER_IFACE_NOW="$(
      default_interface
    )"

    LAST_CLEAN_IFACE=""

    for cleanup_iface in \
      "$SHAPER_IFACE_OLD" \
      "$SHAPER_IFACE_NOW"
    do

      [[ -n "$cleanup_iface" ]] || continue

      [[ "$cleanup_iface" != "$LAST_CLEAN_IFACE" ]] || continue

      LAST_CLEAN_IFACE="$cleanup_iface"

      [[ -d "/sys/class/net/$cleanup_iface" ]] || continue

      if command -v tc >/dev/null 2>&1; then

        tc qdisc del \
          dev "$cleanup_iface" \
          clsact \
          2>/dev/null || true

        tc qdisc del \
          dev "$cleanup_iface" \
          root \
          2>/dev/null || true

        ok "eBPF/qdisc сняты с $cleanup_iface"

      fi

    done

    rm -rf "$SHAPER_PIN_DIR"

    ok "Скорость не ограничивается"

  fi

  save_state 10

fi

# ============================================================
# ФИНИШ
# ============================================================

echo

echo -e "\e[1;42m  ГОТОВО  \e[0m \e[1mНода развёрнута.\e[0m"

echo
echo "  • SSH:                    ssh -p $SSH_PORT root@$DOMAIN"
echo "  • SSH-порт:               $SSH_PORT (существующий SSH-доступ сохранён)"
echo "  • API-порт RemnaNode:     $NODE_PORT"
echo "  • Журнал установки:       $LOG_FILE"
echo "  • Логи ноды:              cd $NODE_DIR && docker compose logs -f -t"
echo "  • Сертификат:             /etc/letsencrypt/live/$DOMAIN/"
echo "  • Общий путь сертификата: $SSL_DIR/"
echo "  • Psiphon:                docker inspect -f '{{.State.Health.Status}}' vps-psiphon"

if [[ "$SHAPER_ENABLED" == 1 ]]; then

  echo "  • Статус шейпера:         systemctl status $SHAPER_SERVICE"

  echo "  • Правила шейпера:        python3 $SHAPER_DIR/reshala_ctrl.py --pin-dir $SHAPER_PIN_DIR/maps --rules-file $SHAPER_CONFIG_DIR/rules.json rules"

else

  echo "  • Шейпинг:                отключён"

fi

echo
echo -e "  \e[1mЧто указать в Remnawave:\e[0m"

echo
echo -e "  0) \e[1;33mПорт ноды: $NODE_PORT\e[0m"
echo "     Это API-порт RemnaNode, НЕ SSH."

echo
echo "  1) VLESS REALITY"
echo "     TCP/443"
echo "     dest: 127.0.0.1:8443"

echo
echo "  2) Hysteria2"
echo "     UDP/443"
echo "     certificateFile: $SSL_DIR/fullchain.pem"
echo "     keyFile:         $SSL_DIR/privkey.pem"

echo
echo "     up/down задавать строкой вида:"
echo '       "200mbps"'
echo "     либо не задавать."

echo
echo "  3) XHTTP"
echo "     listen: 127.0.0.1"
echo "     port:   $XHTTP_PORT"
echo "     path:   $XHTTP_PATH"
echo "     securityLayer: TLS"

echo
echo -e "  \e[1;33mВАЖНО:\e[0m"
echo "  SSH         = $SSH_PORT (сохранён)"
echo "  RemnaNode   = $NODE_PORT"
echo "  Reality     = TCP/443"
echo "  Hysteria2   = UDP/443"
echo "  nginx       = только 127.0.0.1:8443"
echo
printf '\nГотово: все %s этапов завершены.\nSSH: ssh -p %s root@%s\nAPI ноды: %s\nПолный журнал и параметры: %s\n' \
  "$TOTAL" "$SSH_PORT" "$DOMAIN" "$NODE_PORT" "$LOG_FILE" >&3
