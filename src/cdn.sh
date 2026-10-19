# PROVIDER заменяется при сборке: два отдельных автономных файла.
CDN_PROVIDER=__PROVIDER__
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
