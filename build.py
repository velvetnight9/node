"""Собирает три самостоятельных Bash-скрипта с общей защитой без внешнего source."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent
common=(ROOT/'src/security.sh').read_text(encoding='utf-8')
cdn=(ROOT/'src/cdn.sh').read_text(encoding='utf-8')
for provider in ('yandex','timeweb'):
    text='#!/usr/bin/env bash\nset -Eeuo pipefail\n# Автоматическая установка и ремонт CDN-ноды.\n'+common+'\n'+cdn.replace('__PROVIDER__',provider)+'\nrn_cdn_main "$@"\n'
    (ROOT/('install-'+provider+'-cdn.sh')).write_text(text,encoding='utf-8',newline='\n')

source=(ROOT/'src/standard-base.sh').read_text(encoding='utf-8-sig')
prefix='''
# BEGIN SHARED SECURITY
'''+common+'''
# END SHARED SECURITY
RN_ROLE=standard
RN_MODE="${1:-auto}"
case "$RN_MODE" in
  --help)
    printf 'Запуск: bash install.sh [--repair|--check|--resume]\\nPANEL_IPS="IPv4 IPv6" — адреса панели. SSH_PORT=48522 — вход с любого IP только по ключу.\\nNODE_PORT=9744 — управление только с IP панели; такой же порт укажите в панели.\\n'; exit 0;;
  --check)
    rn_node_info
    [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="${RN_RUNNING_NODE_PORT:-}"
    printf 'SSH: %s\\nNODE_PORT: %s\\n' "$(rn_ssh_ports)" "${NODE_PORT:-не определён}"
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
    printf 'Проверьте также inbound и доступность TCP/UDP из подписки.\\n'
    exit 0
fi
'''
source=source.replace('set -Eeuo pipefail\n','set -Eeuo pipefail\n'+prefix+'\n',1)
source=source.replace('INSTALLER_VERSION="2026-10-19.2"','INSTALLER_VERSION="2026-10-31.1"')
source=re.sub(r'^STANDARD_SSH_PUBLIC_KEY=.*$', 'STANDARD_SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"',source,count=1,flags=re.M)
start=source.index('ensure_ufw_rules() {')
end=source.index('\n}\n',start)+3
source=source[:start]+'ensure_ufw_rules() { rn_firewall; }\n'+source[end:]
source=source.replace('      NODE_PORT \\\n','      NODE_PORT \\\n      PANEL_IPS \\\n',1)
source=source.replace('"Включить шейпинг? [Y/n]: " \\\n    "y"','"Включить шейпинг? [y/N]: " \\\n    "n"')
# Вопрос задаётся до начала установки; без него controlport не открывается публично.
anchor='# docker-compose\n# ------------------------------------------------------------\n'
assert source.count(anchor)==1
source=source.replace(anchor,anchor+'''\ncommand -v python3 >/dev/null || apt-get -o DPkg::Lock::Timeout=300 install -y python3
rn_ask PANEL_IPS 'IP панели (IPv4/IPv6 через пробел)'
PANEL_IPS="$(rn_ips "$PANEL_IPS")"
''',1)
source=source.replace('    restart: always\n\n    cap_add:', '''    restart: always
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"

    cap_add:''',1)
# Повторный запуск/продолжение не меняет существующий compose и ключ.
begin=source.index('OLD_UMASK="$(umask)"')
finish=source.index('umask "$OLD_UMASK"',begin)+len('umask "$OLD_UMASK"')
source=source[:begin]+'if [[ ! -e "$NODE_DIR/docker-compose.yml" ]]; then\n'+source[begin:finish]+'\nelse\n  info "Существующий compose сохранён"\nfi\n'+source[finish:]
def replace_stage(number,body):
    global source
    a=source.index('if ((START_STEP <= '+str(number)+')); then')
    b=source.index('# ============================================================\n# ЭТАП '+str(number+1),a)
    source=source[:a]+body+'\n\n'+source[b:]
replace_stage(5,'''if ((START_STEP <= 5)); then
  step "SSH: проверка существующего доступа"
  if [[ -n "$STANDARD_SSH_PUBLIC_KEY" ]]; then
    printf '%s\\n' "$STANDARD_SSH_PUBLIC_KEY" | ssh-keygen -lf /dev/stdin >/dev/null
    install_standard_ssh_key
  fi
  RN_SSH_PORTS="$(rn_ssh_ports)"
  [[ -n "$RN_SSH_PORTS" ]] || { err 'Не найден SSH-порт'; exit 1; }
  sshd -t
  ok "SSH-порт $SSH_PORT выбран; key-only политика применяется следующим этапом"
  save_state 5
fi''')
replace_stage(6,'''if ((START_STEP <= 6)); then
  step "Файрвол: порт управления только для панели"
  rn_security
  rn_network
  save_state 6
fi''')
replace_stage(7,'''if ((START_STEP <= 7)); then
  step "Проверка Fail2ban SSH"
  fail2ban-client -t
  fail2ban-client status sshd
  ok "SSH jail запущен; баны не затрагивают VPN"
  save_state 7
fi''')
replace_stage(8,'''if ((START_STEP <= 8)); then
  step "Проверка защиты доступа"
  # Списки третьих лиц не применяются автоматически к действующему серверу.
  nft list table inet remnanode_control >/dev/null
  ok "Panel-only guard активен; traffic-guard автоматически не устанавливается"
  save_state 8
fi''')
source=source.replace('--force-recreate \\\n    --remove-orphans','--no-recreate')
source=source.replace('(TCP/22 отключён)','(существующий SSH-доступ сохранён)')
source=source.replace('SSH         = $SSH_PORT','SSH         = $SSH_PORT (сохранён)')
source=source.replace('SSH (ключ):   ssh -p $SSH_PORT','SSH:          ssh -p $SSH_PORT')
(ROOT/'install.sh').write_text(source,encoding='utf-8',newline='\n')
print('Собраны install.sh, install-yandex-cdn.sh, install-timeweb-cdn.sh')
