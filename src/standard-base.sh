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
INSTALLER_VERSION="2026-10-19.2"
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

ensure_ufw_rules() {
  ufw allow "$SSH_PORT"/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 443/udp
  ufw allow "$NODE_PORT"/tcp
  ufw allow 3000/tcp
  ufw allow 3001/tcp
}


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
    "Включить шейпинг? [Y/n]: " \
    "y"

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

mkdir -p "$NODE_DIR"
mkdir -p /var/log/remnanode
mkdir -p "$SSL_DIR"

if [[ -e "$NODE_DIR/docker-compose.yml" ]]; then

  cp -a \
    "$NODE_DIR/docker-compose.yml" \
    "$NODE_DIR/docker-compose.yml.bak.$(date +%Y%m%d-%H%M%S)"

fi

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
    --force-recreate \
    --remove-orphans

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

  step "SSH: порт $SSH_PORT, вход ключом"

  SSH_DROPIN="/etc/ssh/sshd_config.d/00-remnanode.conf"

  SSH_OLD_DROPIN="/etc/ssh/sshd_config.d/00-remnanode-key-only.conf"

  install -d \
    -m 755 \
    /etc/ssh/sshd_config.d

  install -d \
    -m 755 \
    /run/sshd

  install_standard_ssh_key

  ok "Стандартный SSH-ключ добавлен для root"

  SSH_BACKUP_STAMP="$(date +%Y%m%d-%H%M%S)"

  cp \
    "$SSHD" \
    "${SSHD}.bak.$SSH_BACKUP_STAMP"

  # Если Ubuntu-конфиг почему-то не включает sshd_config.d,
  # добавляем Include В НАЧАЛО.
  if ! grep -Eq \
    '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' \
    "$SSHD"
  then

    sed -i \
      '1i Include /etc/ssh/sshd_config.d/*.conf' \
      "$SSHD"

  fi

  # Убираем ВСЕ активные конкурирующие SSH-настройки,
  # включая возможный Port 22 в cloud-init drop-ins.
  for ssh_cfg in \
    "$SSHD" \
    /etc/ssh/sshd_config.d/*.conf
  do

    [[ -f "$ssh_cfg" ]] || continue

    [[ "$ssh_cfg" == "$SSH_DROPIN" ]] && continue

    if grep -Eq \
      '^[[:space:]]*(Port|PubkeyAuthentication|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitRootLogin)[[:space:]]+' \
      "$ssh_cfg"
    then

      cp -a \
        "$ssh_cfg" \
        "$ssh_cfg.bak.$SSH_BACKUP_STAMP"

      sed -i -E \
        's/^([[:space:]]*)(Port|PubkeyAuthentication|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitRootLogin)([[:space:]]+)/\1# Disabled by RemnaNode installer: \2\3/' \
        "$ssh_cfg"

    fi

  done

  rm -f "$SSH_OLD_DROPIN"

  cat >"$SSH_DROPIN" <<EOF
# Управляется установщиком RemnaNode.

# Старый TCP/22 не используется.
Port $SSH_PORT

PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
EOF

  chmod 600 "$SSH_DROPIN"

  # Открываем новый порт ДО перезапуска sshd,
  # если UFW уже был активен до запуска installer.
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$SSH_PORT"/tcp
  fi

  sshd -t

  # Ubuntu 22.10+/24.04 socket activation.
  # Без этого systemd может продолжать держать 22.
  systemctl disable \
    --now \
    ssh.socket \
    2>/dev/null || true

  systemctl enable \
    ssh.service \
    2>/dev/null || true

  sshd -t

  info "Перезапускаю sshd..."

  systemctl restart ssh

  sleep 1

  SSHD_EFFECTIVE="$(
    sshd -T 2>/dev/null
  )"

  # Должен присутствовать ТОЛЬКО выбранный Port.
  if ! awk \
    -v wanted="$SSH_PORT" '
      $1 == "port" {
        seen=1

        if ($2 != wanted)
          bad=1
      }

      END {
        exit !(seen && !bad)
      }
    ' <<<"$SSHD_EFFECTIVE"
  then

    err "sshd использует неправильный Port"
    echo "$SSHD_EFFECTIVE" |
      grep '^port ' >&2 || true

    exit 1

  fi

  grep -qx \
    'pubkeyauthentication yes' \
    <<<"$SSHD_EFFECTIVE" || {

    err "PubkeyAuthentication не включён"
    exit 1

  }

  grep -qx \
    'passwordauthentication no' \
    <<<"$SSHD_EFFECTIVE" || {

    err "PasswordAuthentication не отключён"
    exit 1

  }

  grep -qx \
    'kbdinteractiveauthentication no' \
    <<<"$SSHD_EFFECTIVE" || {

    err "KbdInteractiveAuthentication не отключён"
    exit 1

  }

  grep -Eqx \
    'permitrootlogin (prohibit-password|without-password)' \
    <<<"$SSHD_EFFECTIVE" || {

    err "PermitRootLogin настроен неправильно"
    exit 1

  }

  SSH_CUSTOM_LISTEN="$(
    ss \
      -H \
      -ltn \
      "sport = :$SSH_PORT" \
      2>/dev/null || true
  )"

  [[ -n "$SSH_CUSTOM_LISTEN" ]] || {

    err "sshd не слушает TCP/$SSH_PORT"
    exit 1

  }

  # Самое важное для твоего требования:
  # если новый порт не 22 — на 22 вообще ничего не должно слушать.
  if [[ "$SSH_PORT" != 22 ]]; then

    SSH_22_LISTEN="$(
      ss \
        -H \
        -ltn \
        'sport = :22' \
        2>/dev/null || true
    )"

    if [[ -n "$SSH_22_LISTEN" ]]; then

      # KillMode=process может оставить прежний sshd после смены MainPID.
      stop_stale_ssh_listeners || true
      SSH_22_LISTEN="$(ss -H -ltnp 'sport = :22')"

    fi

    if [[ -n "$SSH_22_LISTEN" ]]; then

      err "TCP/22 всё ещё слушается после смены SSH-порта"
      echo "$SSH_22_LISTEN" >&2

      exit 1

    fi

  fi

  ok "SSH действительно перенесён с 22 на $SSH_PORT"
  ok "Парольный вход root отключён"

  warn "Новое подключение: ssh -i ~/.ssh/id_ed25519 -p $SSH_PORT root@$DOMAIN"

  save_state 5

fi

# ============================================================
# ЭТАП 6
# ============================================================

if ((START_STEP <= 6)); then

  step "UFW (фаервол)"

  info "Устанавливаю UFW..."

  apt_run install -y ufw

  ensure_ufw_rules

  warn "Включаю UFW. SSH после этого — порт $SSH_PORT, только ключ."

  sleep 2

  ufw --force enable

  ufw status

  ok "UFW включён"

  save_state 6

fi

# ============================================================
# ЭТАП 7
# ============================================================

if ((START_STEP <= 7)); then

  step "fail2ban"

  info "Устанавливаю fail2ban..."

  apt_run install -y fail2ban

  cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled  = true
port     = $SSH_PORT
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF

  systemctl enable fail2ban

  systemctl restart fail2ban

  systemctl is-active \
    --quiet \
    fail2ban || {

    journalctl \
      -u fail2ban \
      --no-pager \
      -n 50 >&2 || true

    err "fail2ban не запустился"
    exit 1

  }

  fail2ban-client status sshd || true

  ok "fail2ban активен на SSH-порту $SSH_PORT"

  save_state 7

fi

# ============================================================
# ЭТАП 8
# ============================================================

if ((START_STEP <= 8)); then

  step "traffic-guard (анти-сканер)"

  info "Устанавливаю traffic-guard..."

  # НЕ:
  #
  #   curl ... | bash
  #
  # иначе вложенный bash способен читать остаток основного install.sh.
  run_remote_script \
    bash \
    https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh

  command -v traffic-guard >/dev/null 2>&1 || {

    err "traffic-guard не найден после установки"
    exit 1

  }

  info "Применяю списки блокировки..."

  traffic-guard full \
    -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
    -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
    --enable-logging \
    </dev/null

  # После вмешательства traffic-guard ещё раз гарантируем,
  # что критичные ALLOW-правила присутствуют.
  if command -v ufw >/dev/null 2>&1; then

    ensure_ufw_rules

    ufw reload || true

  fi

  SSH_AFTER_GUARD="$(
    ss \
      -H \
      -ltn \
      "sport = :$SSH_PORT" \
      2>/dev/null || true
  )"

  [[ -n "$SSH_AFTER_GUARD" ]] || {

    err "После traffic-guard SSH-порт $SSH_PORT перестал слушаться"
    exit 1

  }

  ok "traffic-guard настроен"
  ok "SSH после применения traffic-guard доступен на $SSH_PORT"

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
    --deny-regions "RU BY IR SY CU KP CN VE" \
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
echo "  • SSH-порт:               $SSH_PORT (TCP/22 отключён)"
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
echo "  SSH         = $SSH_PORT"
echo "  RemnaNode   = $NODE_PORT"
echo "  Reality     = TCP/443"
echo "  Hysteria2   = UDP/443"
echo "  nginx       = только 127.0.0.1:8443"
echo
printf '\nГотово: все %s этапов завершены.\nSSH: ssh -p %s root@%s\nAPI ноды: %s\nПолный журнал и параметры: %s\n' \
  "$TOTAL" "$SSH_PORT" "$DOMAIN" "$NODE_PORT" "$LOG_FILE" >&3
