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
      if [[ -n "${NODE_PORT:-}" && "$NODE_PORT" != "$detected" ]]; then
        rn_die "NODE_PORT=$NODE_PORT не совпадает с работающей нодой ($detected). Сначала исправьте настройку в панели/compose."; return 1
      fi
      NODE_PORT="$detected"
    fi
  fi
  if [[ -z "${NODE_PORT:-}" ]]; then
    local control_ports=()
    mapfile -t control_ports < <(ss -H -ltnp | awk '/"rw-node"/ {n=split($4,a,":");print a[n]}' | sort -nu)
    if ((${#control_ports[@]}==1)); then NODE_PORT="${control_ports[0]}"; fi
  fi
}
rn_ssh_ports() {
  {
    [[ -z "${SSH_CONNECTION:-}" ]] || printf '%s\n' "${SSH_CONNECTION##* }"
    ss -H -ltnp | awk '/sshd|systemd/ {n=split($4,a,":"); if ($0 ~ /sshd/ || a[n]==22) print a[n]}'
    sshd -T 2>/dev/null | awk '$1=="port" {print $2}'
  } | awk '/^[0-9]+$/ && $1>0 && $1<=65535' | sort -nu | paste -sd, -
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
  rn_ask NODE_PORT 'Порт управления нодой из панели' 2222
  rn_port "$NODE_PORT" || { rn_die 'Некорректный NODE_PORT'; return 1; }
  RN_SSH_PORTS="$(rn_ssh_ports)"
  [[ -n "$RN_SSH_PORTS" ]] || { rn_die 'Не удалось определить SSH-порт'; return 1; }
  case ",$RN_SSH_PORTS,80,443," in *",$NODE_PORT,"*) rn_die 'Порт управления совпадает с SSH/HTTP/HTTPS'; return 1;; esac
  RN_ADMIN_IP=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then RN_ADMIN_IP="$(rn_ips "${SSH_CONNECTION%% *}")"; fi
  RN_BACKUP="$(mktemp -d /root/remnanode-security-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX)"
  chmod 700 "$RN_BACKUP"
  rn_info "SSH-порты сохраняются: $RN_SSH_PORTS; управление: TCP/$NODE_PORT только с $PANEL_IPS"
}
rn_backup() {
  local item
  for item in etc/ufw etc/default/ufw etc/fail2ban etc/ssh usr/local/sbin/remnanode-control-firewall etc/remnanode-security etc/systemd/system/remnanode-control-firewall.service; do
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
  elif [[ -n "$(ss -H -lun 'sport = :443')" ]]; then
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
import ipaddress,re,sys
excluded={int(sys.argv[1]),61000,61001}
found=set()
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
rn_ssh_harden() {
  if ! rn_ssh_verified_key; then
    rn_info 'Текущий вход по ключу не подтверждён: парольный вход и SSH-порты сохраняются.'
    return 0
  fi
  local dropin=/etc/ssh/sshd_config.d/00-remnanode-auth.conf
  install -d /etc/ssh/sshd_config.d
  cat >"$dropin" <<'EOF'
# Пароли отключаются только после подтверждённого текущего входа по ключу.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
EOF
  if [[ "$(head -n 1 /etc/ssh/sshd_config)" != "Include $dropin" ]]; then
    sed -i "1i Include $dropin" /etc/ssh/sshd_config
  fi
  if ! sshd -t; then
    cp -a "$RN_BACKUP/etc/ssh/sshd_config" /etc/ssh/sshd_config
    if [[ -f "$RN_BACKUP/$dropin" ]]; then cp -a "$RN_BACKUP/$dropin" "$dropin"; else rm -f "$dropin"; fi
    rn_die 'sshd не принял настройки; конфиг восстановлен'; return 1
  fi
  if systemctl is-active --quiet ssh.service; then
    if ! systemctl reload ssh.service; then
      cp -a "$RN_BACKUP/etc/ssh/sshd_config" /etc/ssh/sshd_config
      if [[ -f "$RN_BACKUP/$dropin" ]]; then cp -a "$RN_BACKUP/$dropin" "$dropin"; else rm -f "$dropin"; fi
      systemctl reload ssh.service || true
      rn_die 'Не удалось применить SSH-конфиг; восстановлена копия'; return 1
    fi
  fi
  rn_info 'Текущий вход по ключу подтверждён; парольная аутентификация отключена, порт сохранён.'
}
rn_security() {
  rn_prepare
  export DEBIAN_FRONTEND=noninteractive
  rn_ensure_packages ufw nftables fail2ban python3-systemd iproute2 util-linux
  rn_backup
  rn_firewall
  rn_install_inbound_sync
  rn_fail2ban
  rn_ssh_harden
  printf '%s\n' "$PANEL_IPS" >"$RN_STATE_DIR/panel-ips"
  chmod 600 "$RN_STATE_DIR/panel-ips"
  rn_info "Безопасность проверена. SSH-порты сохранены. Копия: $RN_BACKUP"
}
rn_existing_repair() {
  rn_security
  if command -v docker >/dev/null && docker inspect "$NODE_CONTAINER" >/dev/null 2>&1; then
    local mode
    mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$NODE_CONTAINER")"
    if [[ "$(docker inspect -f '{{.State.Running}}' "$NODE_CONTAINER")" != true ]]; then docker start "$NODE_CONTAINER"; fi
    rn_info "Сеть ноды: $mode"
    if [[ "$mode" != host ]]; then rn_info 'Bridge-сеть сохранена; control guard действует и на FORWARD. Другие опубликованные порты проверьте отдельно.'; fi
    docker inspect -f 'Нода: {{.State.Status}}; перезапуски: {{.RestartCount}}; журнал: {{.HostConfig.LogConfig.Type}}' "$NODE_CONTAINER"
  fi
  rn_info 'Домены, compose, SECRET_KEY и профили панели не перезаписывались.'
}

# PROVIDER заменяется при сборке: два отдельных автономных файла.
CDN_PROVIDER=timeweb
RN_ROLE=cdn
rn_cdn_options() {
  MODE=auto
  while (($#)); do
    case "$1" in
      --repair|--check|--security-only) MODE="${1#--}"; shift;;
      --panel-ip) PANEL_IPS="${2:?Нужен IP}"; shift 2;;
      --node-port) NODE_PORT="${2:?Нужен порт}"; shift 2;;
      --origin) ORIGIN_DOMAIN="${2:?Нужен домен}"; shift 2;;
      --xhttp-port) XHTTP_PORT="${2:?Нужен порт}"; shift 2;;
      --help) printf 'Запуск: bash install-%s-cdn.sh [--repair|--check|--security-only] [--panel-ip IP]\nДанные запрашиваются в терминале. Существующие SSH и ключ ноды сохраняются.\n' "$CDN_PROVIDER"; exit 0;;
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
    rn_info 'Существующая нода сохранена: её образ, compose и ключ не менялись'
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
  rn_prepare
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
  printf '\nГотово. Сохранены SSH и существующие ключи. Порт управления — только для панели.\n'
  printf 'CDN-ресурс и Host/SNI настройте по HTML-гайду; обновите подписку и проверьте оба направления.\n'
  printf 'Антисканер и шейпинг по IP CDN не включались.\n'
}

rn_cdn_main "$@"
