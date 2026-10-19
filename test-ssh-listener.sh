#!/usr/bin/env bash
# Изолированная проверка остаточного sshd; настоящие процессы не затрагиваются.
set -euo pipefail
cd "$(dirname "$0")"
source <(sed -n '/^stop_stale_ssh_listeners() {/,/^}/p' install.sh)
info() { :; }
systemctl() {
  if [[ "$*" == *MainPID* ]]; then echo 12567; else echo /system.slice/ssh.service; fi
}
sshd() { :; }
readlink() {
  if [[ "$*" == */proc/* && "$scenario" == foreign ]]; then
    echo /usr/bin/other
  else
    echo /usr/sbin/sshd
  fi
}
ps() {
  if [[ "$scenario" == session ]]; then echo 'sshd: root@pts/0'; else echo 'sshd: /usr/sbin/sshd -D [listener]'; fi
}
awk() { [[ "$scenario" != other_group ]]; }
ss() {
  if [[ "$*" == *-ltnp* ]]; then
    [[ "$scenario" != unknown ]] || { echo 'LISTEN *:22'; return; }
    local pid=570
    [[ "$scenario" != main ]] || pid=12567
    echo "LISTEN *:22 users:((\"sshd\",pid=$pid,fd=3))"
  elif [[ "$killed" == no || "$scenario" == stuck ]]; then
    echo 'LISTEN *:22'
  fi
  return 0
}
kill() { [[ "$*" == '-TERM 570' ]]; killed=yes; }
sleep() { :; }
for scenario in stale foreign session other_group main unknown stuck; do
  killed=no
  if stop_stale_ssh_listeners; then
    [[ "$scenario" == stale && "$killed" == yes ]]
  else
    [[ "$scenario" != stale ]]
    [[ "$scenario" == stuck || "$killed" == no ]]
  fi
  echo "PASS: $scenario"
done
