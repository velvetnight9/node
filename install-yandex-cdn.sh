#!/usr/bin/env bash
set -Eeuo pipefail
# Автоматическая установка и ремонт CDN-ноды.
# Общая часть трёх автономных установщиков. Собирается build.py.
rn_info() { printf '→ %s\n' "$*"; }
rn_die() { printf 'Ошибка: %s\n' "$*" >&2; return 1; }
rn_ask() {
  local key="$1" prompt="$2" default="${3:-}" answer
  [[ -n "${!key:-}" ]] && return 0
  [[ -r /dev/tty ]] || { rn_die "Задайте $key через окружение или запустите из терминала"; return 1; }
  if declare -F stop_progress >/dev/null; then
    stop_progress
    printf '\n' >/dev/tty
  fi
  printf '%s%s: ' "$prompt" "${default:+ [$default]}" >/dev/tty
  IFS= read -r answer </dev/tty || return 1
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
  rn_network_access || return 1
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
rn_network_access() {
  # Отключение IPv6 требует IPv4 для SSH и связи панели с нодой.
  local panel ipv4=0
  for panel in $PANEL_IPS; do [[ "$panel" == *:* ]] || ipv4=1; done
  ((ipv4)) || { rn_die 'Для отключения IPv6 укажите IPv4 панели в PANEL_IPS'; return 1; }
  rn_ssh_context
  if [[ "${SSH_CONNECTION:-}" == *:* ]]; then
    rn_die 'Текущий SSH использует IPv6. Подключитесь к IPv4 сервера и повторите запуск.'; return 1
  fi
}
rn_network() {
  rn_network_access || return 1
  rn_ensure_packages procps kmod
  # Встроенный BBR работает и без отдельного загружаемого модуля.
  modprobe tcp_bbr 2>/dev/null || true
  modprobe sch_fq 2>/dev/null || true
  local available conf modules tmp before key path value
  available="$(sysctl -n net.ipv4.tcp_available_congestion_control)" || return 1
  if [[ " $available " != *' bbr '* ]]; then
    rn_die 'Ядро не поддерживает TCP BBR. Нужны ядро/модули с CONFIG_TCP_CONG_BBR; сетевые настройки не изменены.'; return 1
  fi
  conf=/etc/sysctl.d/99-remnanode-network.conf
  modules=/etc/modules-load.d/remnanode-network.conf
  tmp="$RN_BACKUP/network-new.conf"
  before="$RN_BACKUP/network-runtime-before.conf"
  # all не отражает реальное состояние отдельных интерфейсов.
  : >"$before"
  for key in net.core.default_qdisc net.ipv4.tcp_congestion_control; do
    value="$(sysctl -n "$key")" || return 1
    printf '%s = %s\n' "$key" "$value" >>"$before"
  done
  for path in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -f "$path" ]] || continue
    key="net/ipv6/conf/$(basename "$(dirname "$path")")/disable_ipv6"
    printf '%s = %s\n' "$key" "$(cat "$path")" >>"$before"
  done
  cat >"$tmp" <<'EOF'
# Managed by remnanode installer. Applied now and on boot.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# Missing keys are allowed when IPv6 is disabled in the kernel already.
-net.ipv6.conf.all.disable_ipv6 = 1
-net.ipv6.conf.default.disable_ipv6 = 1
-net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  if ! sysctl -p "$tmp" || ! rn_network_verify; then
    sysctl -p "$before" || true
    rn_die 'Не удалось применить IPv6/BBR; выполнен возврат сохранённых sysctl, постоянные файлы не изменены.'; return 1
  fi
  install -d -m 755 /etc/sysctl.d /etc/modules-load.d
  [[ ! -e "$conf" ]] || cp -a "$conf" "$RN_BACKUP/network-sysctl-before.conf"
  [[ ! -e "$modules" ]] || cp -a "$modules" "$RN_BACKUP/network-modules-before.conf"
  install -m 644 "$tmp" "$conf"
  printf 'tcp_bbr\nsch_fq\n' >"$RN_BACKUP/network-modules-new.conf"
  install -m 644 "$RN_BACKUP/network-modules-new.conf" "$modules"
  rn_info 'IPv6 отключён; TCP BBR включён, default_qdisc=fq. Настройки сохранены для перезагрузки.'
}
rn_network_verify() {
  [[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == bbr ]] || return 1
  [[ "$(sysctl -n net.core.default_qdisc)" == fq ]] || return 1
  local path
  for path in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -f "$path" ]] || continue
    [[ "$(cat "$path")" == 1 ]] || return 1
  done
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
maxretry = 6
findtime = 10m
bantime = 24h
bantime.increment = false
bantime.rndtime = 0
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
      fail2ban-client get sshd bantime
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
rn_ssh_key_input() {
  [[ "${RN_SSH_KEY_READY:-0}" == 0 ]] || return 0
  if [[ -z "${SSH_PUBLIC_KEY:-}" ]] && rn_ssh_verified_key; then return 0; fi
  rn_ask SSH_PUBLIC_KEY 'Публичный SSH-ключ для root (ssh-ed25519/ssh-rsa/ecdsa, не приватный ключ)' || return 1
  [[ "$SSH_PUBLIC_KEY" =~ ^(ssh-|ecdsa-|sk-) && "$SSH_PUBLIC_KEY" != *$'\n'* ]] || { rn_die 'Нужен один публичный SSH-ключ'; return 1; }
  printf '%s\n' "$SSH_PUBLIC_KEY" | ssh-keygen -lf /dev/stdin >/dev/null || { rn_die 'Некорректный публичный SSH-ключ'; return 1; }
}
rn_ssh_key_prepare() {
  [[ "${RN_SSH_KEY_READY:-0}" == 0 ]] || return 0
  rn_ssh_key_input || return 1
  if [[ -z "${SSH_PUBLIC_KEY:-}" ]]; then RN_SSH_KEY_READY=1; return 0; fi
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
  rn_network
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

# PROVIDER заменяется при сборке: два отдельных автономных файла.
CDN_PROVIDER=yandex
RN_ROLE=cdn
rn_cdn_options() {
  MODE=auto
  while (($#)); do
    case "$1" in
      --repair|--check|--security-only) MODE="${1#--}"; shift;;
      --panel-ip) PANEL_IPS="${2:?Нужен IP}"; shift 2;;
      --node-port) NODE_PORT="${2:?Нужен порт}"; shift 2;;
      --ssh-port) SSH_PORT="${2:?Нужен порт}"; shift 2;;
      --ssh-key) SSH_PUBLIC_KEY="${2:?Нужен публичный ключ}"; shift 2;;
      --origin) ORIGIN_DOMAIN="${2:?Нужен домен}"; shift 2;;
      --xhttp-port) XHTTP_PORT="${2:?Нужен порт}"; shift 2;;
      --help) printf 'Запуск: bash install-%s-cdn.sh [--repair|--check|--security-only] [--panel-ip IP] [--ssh-port 48522] [--node-port 9744]\nSSH доступен с любого IP только по ключу; управление только с IP панели.\nСвой публичный SSH-ключ: SSH_PUBLIC_KEY или --ssh-key. SECRET_KEY ноды сохраняется.\n' "$CDN_PROVIDER"; exit 0;;
      *) rn_die "Неизвестный аргумент $1"; exit 1;;
    esac
  done
}
rn_domain() {
  python3 - "$1" <<'PY'
import re,sys
v=sys.argv[1]
assert len(v)<=253 and len(v.split('.'))>=2 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',s) for s in v.split('.')), 'Нужен DNS-домен без пути/порта'
PY
}
rn_cdn_detect() {
  ORIGIN_MODE=native
  RN_NGINX_CONTAINER=""
  if command -v docker >/dev/null && [[ "$(docker inspect -f '{{.State.Running}}' cdn-nginx 2>/dev/null || true)" == true ]]; then
    ORIGIN_MODE=docker; RN_NGINX_CONTAINER=cdn-nginx
  fi
  if [[ -z "${NGINX_CONFIG:-}" ]]; then
    if [[ -f /etc/nginx/sites-available/remnanode-cdn.conf ]] && grep -q '^# remnanode-managed:cdn-origin:' /etc/nginx/sites-available/remnanode-cdn.conf; then
      NGINX_CONFIG=/etc/nginx/sites-available/remnanode-cdn.conf
    fi
  fi
  if [[ -z "${NGINX_CONFIG:-}" ]]; then
    local files=()
    if [[ "$ORIGIN_MODE" == docker ]]; then
      mapfile -t files < <(docker inspect cdn-nginx | python3 -c 'import sys,json,os;d=json.load(sys.stdin)[0];print("\n".join(m["Source"] for m in d["Mounts"] if os.path.isfile(m["Source"]) and m["Destination"].endswith(".conf")))')
    else
      shopt -s nullglob
      files=(/etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf)
      shopt -u nullglob
    fi
    local candidates=() file
    for file in "${files[@]}"; do
      [[ -f "$file" ]] || continue
      if grep -Eq 'proxy_pass[[:space:]]+http://(127\.0\.0\.1|[A-Za-z0-9_-]*[Xx][Hh][Tt][Tt][Pp]|xray)' "$file"; then candidates+=("$file"); fi
    done
    if ((${#candidates[@]}==1)); then NGINX_CONFIG="$(readlink -f "${candidates[0]}")";
    elif ((${#candidates[@]}>1)); then rn_die 'Найдено несколько сайтов CDN. Укажите NGINX_CONFIG=/путь/к/его/конфигу'; return 1; fi
  fi
  if [[ -n "${NGINX_CONFIG:-}" && -f "$NGINX_CONFIG" ]]; then
    NGINX_CONFIG="$(readlink -f "$NGINX_CONFIG")"
    [[ -n "${ORIGIN_DOMAIN:-}" ]] || ORIGIN_DOMAIN="$(awk '$1=="server_name" {gsub(/;/,"",$2); if ($2!="_") {print $2;exit}}' "$NGINX_CONFIG")"
    if [[ "$CDN_PROVIDER" == timeweb && -z "${XHTTP_PATH:-}" ]]; then
      XHTTP_PATH="$(python3 - "$NGINX_CONFIG" <<'PY'
from pathlib import Path
import re,sys
s=Path(sys.argv[1]).read_text()
matches=re.findall(r'location\s+(?:\^~\s+)?([^\s{}]+)\s*\{[^{}]*proxy_pass',s)
if len(matches)==1:print(matches[0])
PY
      )"
    fi
  fi
  if [[ -z "${XHTTP_PORT:-}" ]]; then
    local ports=()
    mapfile -t ports < <(ss -H -ltnp | awk '/rw-core|xray/ && $4 ~ /^127\.0\.0\.1:/ {n=split($4,a,":");if(a[n]!=61000)print a[n]}' | sort -nu)
    if ((${#ports[@]}==1)); then XHTTP_PORT="${ports[0]}"; fi
  fi
}
rn_nginx_test() {
  if [[ "$ORIGIN_MODE" == docker ]]; then docker exec "$RN_NGINX_CONTAINER" nginx -t; else nginx -t; fi
}
rn_nginx_reload() {
  if [[ "$ORIGIN_MODE" == docker ]]; then docker exec "$RN_NGINX_CONTAINER" nginx -s reload; else systemctl reload nginx; fi
}
rn_cdn_tune_native_nginx() {
  # Каждый проксируемый поток использует клиентский и upstream-сокет.
  # В Docker лимиты задаются самим контейнером; его не пересоздаём скрытно.
  if [[ "$ORIGIN_MODE" != native ]]; then
    rn_info 'Лимиты Docker nginx сохранены; проверьте worker_connections и nofile в его compose.'
    return 0
  fi
  local file=/etc/nginx/nginx.conf copy="$RN_BACKUP/nginx-main-before.conf"
  cp -a "$file" "$copy"
  python3 - "$file" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]);s=p.read_text()
events=list(re.finditer(r'(?m)^(\s*events\s*\{)([^{}]*)(\})',s))
if len(events)!=1:raise SystemExit('Неоднозначный events в nginx.conf: лимиты не изменены')
m=events[0];body=m[2]
connection=re.compile(r'(?m)^(\s*worker_connections\s+)(\d+)(\s*;)')
if len(connection.findall(body))>1:raise SystemExit('Повторный worker_connections: лимиты не изменены')
if connection.search(body):body=connection.sub(lambda x:x[1]+str(max(8192,int(x[2])))+x[3],body)
else:body='\n    worker_connections 8192;'+body
s=s[:m.start()]+m[1]+body+m[3]+s[m.end():]
limit=re.compile(r'(?m)^(\s*worker_rlimit_nofile\s+)(\d+)(\s*;)')
if len(limit.findall(s))>1:raise SystemExit('Повторный worker_rlimit_nofile: лимиты не изменены')
if limit.search(s):s=limit.sub(lambda x:x[1]+str(max(65535,int(x[2])))+x[3],s)
else:s='worker_rlimit_nofile 65535;\n'+s
if s!=p.read_text():p.write_text(s)
PY
  if ! nginx -t; then cp -a "$copy" "$file"; rn_die 'nginx не принял лимиты; основной конфиг восстановлен'; return 1; fi
  if ! systemctl reload nginx; then
    cp -a "$copy" "$file"; systemctl reload nginx || true
    rn_die 'Reload nginx не удался; лимиты восстановлены'; return 1
  fi
}
rn_cdn_wait_core() {
  local ports=() attempt
  for ((attempt=0;attempt<30;attempt++)); do
    mapfile -t ports < <(ss -H -ltnp | awk '/rw-core|xray/ && $4 ~ /^127\.0\.0\.1:/ {n=split($4,a,":");if(a[n]!=61000 && a[n]!=61001)print a[n]}' | sort -nu)
    if ((${#ports[@]}==1)); then
      if [[ "$XHTTP_PORT" != "${ports[0]}" ]]; then rn_info "Ядро слушает ${ports[0]}, использую этот фактический XHTTP-порт вместо $XHTTP_PORT"; fi
      XHTTP_PORT="${ports[0]}"; return 0
    fi
    if ((${#ports[@]}>1)); then
      local port
      for port in "${ports[@]}"; do [[ "$port" != "$XHTTP_PORT" ]] || return 0; done
      rn_die 'В ядре несколько локальных inbound. Укажите --xhttp-port из своего профиля'; return 1
    fi
    sleep 1
  done
  rn_die 'Не найден локальный inbound Xray. Проверьте Online ноды и включите inbound в панели'; return 1
}
rn_cdn_checks() {
  rn_node_info
  [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="${RN_RUNNING_NODE_PORT:-}"
  rn_cdn_detect
  printf 'CDN: %s\nNODE_PORT: %s\nOrigin: %s\nXHTTP: %s\nnginx: %s (%s)\n' "$CDN_PROVIDER" "${NODE_PORT:-не найден}" "${ORIGIN_DOMAIN:-не найден}" "${XHTTP_PORT:-не найден}" "${NGINX_CONFIG:-не найден}" "$ORIGIN_MODE"
  rn_nginx_test
  [[ -n "${ORIGIN_DOMAIN:-}" && -n "${XHTTP_PORT:-}" ]] || return 1
  local status
  status="$(curl --silent --show-error --max-time 12 --resolve "$ORIGIN_DOMAIN:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$ORIGIN_DOMAIN${XHTTP_PATH:-/}")"
  printf 'Origin HTTP %s\n' "$status"
  [[ "$status" == 400 || "$status" == 404 ]] || { rn_die 'Origin не вернул ответ Xray. Проверьте upstream, path и состояние ноды'; return 1; }
  printf 'Ответ 400/404 без сессии допустим; 502 — неправильный upstream. Проверяйте также подписку в приложении.\n'
}
rn_cdn_repair_nginx() {
  [[ -n "${NGINX_CONFIG:-}" && -f "$NGINX_CONFIG" ]] || { rn_die 'Не найден конфиг origin; автоматический ремонт не будет создавать второй сайт'; return 1; }
  rn_port "$XHTTP_PORT" || { rn_die 'Некорректный XHTTP-порт'; return 1; }
  [[ -n "$(ss -H -ltn "sport = :$XHTTP_PORT")" ]] || { rn_die "Xray ещё не слушает $XHTTP_PORT; включите inbound у ноды в панели"; return 1; }
  local copy
  copy="$RN_BACKUP/nginx-before.conf"
  cp -a "$NGINX_CONFIG" "$copy"
  python3 - "$NGINX_CONFIG" "$XHTTP_PORT" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]);port=int(sys.argv[2]);s=p.read_text();matches=[]
for pattern in (r'(?m)^(\s*server\s+127\.0\.0\.1:)\d+(\s*;)',r'(?m)^(\s*proxy_pass\s+http://127\.0\.0\.1:)\d+(\s*;)'):
    for m in re.finditer(pattern,s):matches.append(m)
if len(matches)!=1:raise SystemExit('Несколько upstream или нестандартный конфиг: ничего не меняю')
m=matches[0];new=s[:m.start()]+m[1]+str(port)+m[2]+s[m.end():]
if new!=s:p.write_text(new);print('Исправлен upstream на 127.0.0.1:'+str(port))
else:print('Upstream уже совпадает с Xray; конфиг сохранён')
PY
  if rn_nginx_test; then rn_nginx_reload; else cp -a "$copy" "$NGINX_CONFIG"; rn_die 'nginx не принял конфиг; восстановлена копия'; return 1; fi
}
rn_cdn_start_node() {
  if command -v docker >/dev/null && docker inspect "$NODE_CONTAINER" >/dev/null 2>&1; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "$NODE_CONTAINER")" != true ]]; then docker start "$NODE_CONTAINER"; fi
    rn_change_node_port
    rn_info 'Образ и ключ существующей ноды сохранены; NODE_PORT сверён с выбранным значением'
    return
  fi
  if ! command -v docker >/dev/null; then
    local installer; installer="$(mktemp)"
    curl -fsSL https://get.docker.com -o "$installer"
    sh "$installer" </dev/null
    rm -f "$installer"
  fi
  systemctl enable --now docker
  docker compose version
  NODE_DIR="${NODE_DIR:-/opt/remnanode}"
  install -d -m 700 "$NODE_DIR"
  if [[ -e "$NODE_DIR/docker-compose.yml" || -e "$NODE_DIR/compose.yaml" ]]; then
    (cd "$NODE_DIR"; docker compose config --quiet; docker compose up -d)
    rn_info 'Запущен ранее созданный compose'; return
  fi
  if [[ -z "${SECRET_KEY:-}" ]]; then
    printf 'SECRET_KEY из compose вашей панели (ввод скрыт): ' >/dev/tty
    IFS= read -rs SECRET_KEY </dev/tty; printf '\n' >/dev/tty
  fi
  [[ -n "$SECRET_KEY" && "$SECRET_KEY" != *[[:space:]]* ]] || { rn_die 'Некорректный SECRET_KEY'; return 1; }
  printf '%s' "$SECRET_KEY" | base64 -d >/dev/null || { rn_die 'SECRET_KEY не является base64'; return 1; }
  (umask 077
   NODE_SECRET="$SECRET_KEY" NODE_CONTROL="$NODE_PORT" python3 - "$NODE_DIR/docker-compose.yml" <<'PY'
from pathlib import Path
import os,json,sys
# JSON является допустимым синтаксисом Compose/YAML. Секрет не попадает в stdout.
config={'services':{'remnanode':{'image':'remnawave/node:latest','container_name':'remnanode','hostname':'remnanode','network_mode':'host','restart':'always','environment':{'NODE_PORT':os.environ['NODE_CONTROL'],'SECRET_KEY':os.environ['NODE_SECRET']},'ulimits':{'nofile':{'soft':65535,'hard':65535}},'logging':{'driver':'json-file','options':{'max-size':'20m','max-file':'3'}}}}}
Path(sys.argv[1]).write_text(json.dumps(config,indent=2))
PY
  )
  unset SECRET_KEY
  (cd "$NODE_DIR"; docker compose config --quiet; docker compose up -d)
}
rn_cdn_nginx_config() {
  local tls="$1"
  printf '# remnanode-managed:cdn-origin:%s\n' "$CDN_PROVIDER"
  if [[ "$CDN_PROVIDER" == yandex && "$tls" == 1 ]]; then printf 'large_client_header_buffers 8 64k;\n'; fi
  if [[ "$tls" == 1 ]]; then
    cat <<EOF
upstream cdn_xhttp {
    server 127.0.0.1:$XHTTP_PORT;
    keepalive 512;
    keepalive_requests 1000000;
    keepalive_timeout 300s;
}
EOF
  fi
  cat <<EOF
server {
    listen 80;
    server_name $ORIGIN_DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/cdn-acme; try_files \$uri =404; }
EOF
  if [[ "$tls" == 1 ]]; then printf '    location / { return 301 https://$host$request_uri; }\n'; else printf '    location / { return 200 "ok\\n"; }\n'; fi
  printf '}\n'
  [[ "$tls" == 1 ]] || return 0
  cat <<EOF
server {
    listen 443 ssl http2;
    server_name $ORIGIN_DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$ORIGIN_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$ORIGIN_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location ^~ /.well-known/acme-challenge/ { root /var/www/cdn-acme; try_files \$uri =404; }
EOF
  if [[ "$CDN_PROVIDER" == timeweb ]]; then printf '    location / { return 200 "ok\\n"; }\n'; fi
  cat <<EOF
    location $XHTTP_PATH {
        proxy_pass http://cdn_xhttp;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
EOF
  if [[ "$CDN_PROVIDER" == yandex ]]; then printf '        proxy_set_header X-Forwarded-For "";\n'; else printf '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'; fi
  cat <<'EOF'
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        client_max_body_size 0;
        client_body_timeout 3600s;
        proxy_connect_timeout 10s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        send_timeout 3600s;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        add_header X-Accel-Buffering "no" always;
    }
}
EOF
}
rn_cdn_install_nginx() {
  [[ "$ORIGIN_MODE" == native ]] || { rn_die 'Найден Docker nginx: сохраняю его. Для ремонта нужен конфиг существующего origin.'; return 1; }
  rn_ask ORIGIN_DOMAIN 'Домен origin (A-запись уже должна вести на эту VPS)'
  rn_domain "$ORIGIN_DOMAIN"
  rn_ask EMAIL 'Почта для сертификата origin'
  [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || { rn_die 'Некорректная почта'; return 1; }
  rn_ensure_packages nginx certbot dnsutils
  NGINX_CONFIG=/etc/nginx/sites-available/remnanode-cdn.conf
  if [[ -e "$NGINX_CONFIG" ]]; then
    grep -q '^# remnanode-managed:cdn-origin:' "$NGINX_CONFIG" || { rn_die 'Существующий конфиг создан другим инструментом; не перезаписываю'; return 1; }
    cp -a "$NGINX_CONFIG" "$RN_BACKUP/nginx-resume-before.conf"
  fi
  install -d /var/www/cdn-acme
  rn_cdn_nginx_config 0 >"$NGINX_CONFIG"
  if [[ ! -e /etc/nginx/sites-enabled/remnanode-cdn.conf ]]; then ln -s "$NGINX_CONFIG" /etc/nginx/sites-enabled/remnanode-cdn.conf; fi
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  certbot certonly --webroot -w /var/www/cdn-acme -d "$ORIGIN_DOMAIN" --email "$EMAIL" --agree-tos --non-interactive
  cp -a "$NGINX_CONFIG" "$RN_BACKUP/nginx-http.conf"
  rn_cdn_nginx_config 1 >"$NGINX_CONFIG"
  if nginx -t; then systemctl reload nginx; else cp -a "$RN_BACKUP/nginx-http.conf" "$NGINX_CONFIG"; return 1; fi
  install -d /etc/letsencrypt/renewal-hooks/deploy
  printf '#!/bin/sh\nset -eu\nnginx -t\nsystemctl reload nginx\n' >/etc/letsencrypt/renewal-hooks/deploy/remnanode-cdn-nginx
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/remnanode-cdn-nginx
  certbot renew --dry-run
}
rn_cdn_main() {
  rn_cdn_options "$@"
  [[ "$EUID" == 0 ]] || { rn_die 'Запустите от root'; return 1; }
  if [[ "$MODE" == check ]]; then rn_cdn_checks; return; fi
  exec 7>/run/remnanode-installer.lock
  flock -n 7 || { rn_die 'Уже работает другой установщик ноды'; return 1; }
  export DEBIAN_FRONTEND=noninteractive
  rn_ensure_packages python3 curl ca-certificates iproute2 openssh-server
  rn_node_info
  rn_cdn_detect
  if [[ "$MODE" != security-only && -z "${NGINX_CONFIG:-}" && "$ORIGIN_MODE" == native ]]; then
    if ss -H -ltnp '( sport = :80 or sport = :443 )' | awk '/nginx/ {next} NF {found=1} END {exit !found}'; then
      rn_die '80/443 заняты другим сервисом. Сохраняю его; сначала подготовьте отдельный CDN origin.'; return 1
    fi
  fi
  # Сначала собираем все данные, затем запускаем установку без новых вопросов.
  rn_info 'Защита CDN: SSH только по ключу, Fail2ban только для SSH, управление только с IP панели.'
  rn_info 'Общие IP-списки traffic-guard не применяются: блокировка CDN edge может отключить пользователей.'
  rn_prepare
  if [[ "$MODE" == security-only && -n "${RN_RUNNING_NODE_PORT:-}" && "$NODE_PORT" != "$RN_RUNNING_NODE_PORT" ]]; then
    rn_die '--security-only не меняет порт контейнера. Для смены NODE_PORT используйте --repair и выставьте тот же порт в панели.'; return 1
  fi
  if [[ "$MODE" != security-only ]]; then
    rn_ask XHTTP_PORT 'Локальный XHTTP-порт из профиля панели' 4443
    if [[ "$CDN_PROVIDER" == timeweb ]]; then
      rn_ask XHTTP_PATH 'XHTTP path из профиля панели' /assets/stream.ts
    else XHTTP_PATH=/; fi
    if [[ -z "${NGINX_CONFIG:-}" && "$MODE" != repair ]]; then
      rn_ask ORIGIN_DOMAIN 'Домен origin'
      rn_ask EMAIL 'Почта для сертификата origin'
    fi
    if [[ -n "${NGINX_CONFIG:-}" ]] && grep -q '^# remnanode-managed:cdn-origin:' "$NGINX_CONFIG" && ! grep -q 'ssl_certificate ' "$NGINX_CONFIG"; then
      rn_ask EMAIL 'Почта для сертификата origin (продолжение установки)'
    fi
    if ! command -v docker >/dev/null || ! docker inspect "$NODE_CONTAINER" >/dev/null 2>&1; then
      if [[ ! -e /opt/remnanode/docker-compose.yml && ! -e /opt/remnanode/compose.yaml && -z "${SECRET_KEY:-}" ]]; then
        printf 'SECRET_KEY из compose панели (ввод скрыт): ' >/dev/tty
        IFS= read -rs SECRET_KEY </dev/tty; printf '\n' >/dev/tty
      fi
    fi
    rn_port "$XHTTP_PORT" || { rn_die 'Неверный XHTTP-порт'; return 1; }
    case ",$RN_SSH_PORTS,$NODE_PORT,80,443," in *",$XHTTP_PORT,"*) rn_die 'XHTTP-порт совпадает с SSH/управлением/HTTP'; return 1;; esac
    if [[ -n "${ORIGIN_DOMAIN:-}" ]]; then rn_domain "$ORIGIN_DOMAIN"; fi
  fi
  rn_security
  rn_network
  if [[ "$MODE" == security-only ]]; then return; fi
  if [[ "$MODE" == repair && -z "${NGINX_CONFIG:-}" ]]; then rn_die 'nginx origin не найден; ничего не переустанавливаю'; return 1; fi
  rn_cdn_start_node
  rn_cdn_detect
  rn_ask XHTTP_PORT 'Локальный XHTTP-порт из профиля панели' 4443
  rn_port "$XHTTP_PORT" || { rn_die 'Неверный XHTTP-порт'; return 1; }
  rn_cdn_wait_core
  if [[ "$CDN_PROVIDER" == timeweb ]]; then
    rn_ask XHTTP_PATH 'XHTTP path из профиля панели' /assets/stream.ts
    [[ "$XHTTP_PATH" =~ ^/[A-Za-z0-9._/-]+\.[A-Za-z0-9]+$ && "$XHTTP_PATH" != *..* ]] || { rn_die 'Timeweb path должен заканчиваться именем файла с расширением'; return 1; }
  else XHTTP_PATH=/; fi
  if [[ -n "${NGINX_CONFIG:-}" ]] && { ! grep -q '^# remnanode-managed:cdn-origin:' "$NGINX_CONFIG" || grep -q 'ssl_certificate ' "$NGINX_CONFIG"; }; then
    rn_cdn_repair_nginx
  else
    rn_cdn_install_nginx
  fi
  rn_cdn_tune_native_nginx
  rn_cdn_checks
  printf '\nГотово. SSH TCP/%s — только ключ. Управление TCP/%s — только для IP панели.\n' "$SSH_PORT" "$NODE_PORT"
  printf 'CDN-ресурс и Host/SNI настройте по HTML-гайду; обновите подписку и проверьте оба направления.\n'
  printf 'Общие IP-списки и шейпинг CDN edge не применяются.\n'
}

rn_cdn_main "$@"
