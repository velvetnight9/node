#!/usr/bin/env bash
# Изолированные проверки: системные службы и пакеты не изменяются.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export TEST_TMP="$tmp"

load_function() {
  source <(sed -n "/^$1() {/,/^}/p" install.sh)
}
info() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }
load_function apt_run
load_function prepare_docker_installer
declare -F apt_run prepare_docker_installer >/dev/null

cat >"$tmp/apt-get" <<'EOF'
#!/usr/bin/env bash
printf 'APT_ARGS: %s\n' "$*"
echo 'VISIBLE_PACKAGE_PROGRESS'
exit "${MOCK_APT_RC:-0}"
EOF
chmod +x "$tmp/apt-get"
export PATH="$tmp:$PATH"
apt_run install -y nginx >"$tmp/apt.log"
grep -q 'DPkg::Lock::Timeout=1800' "$tmp/apt.log"
grep -q VISIBLE_PACKAGE_PROGRESS "$tmp/apt.log"
export MOCK_APT_RC=100
if apt_run install -y nginx >"$tmp/fail.log" 2>&1; then
  echo 'FAIL: ошибка apt потеряна' >&2
  exit 1
else
  test "$?" = 100
fi
unset MOCK_APT_RC

cat >"$tmp/docker.sh" <<'EOF'
#!/bin/sh
sh_c='sh -c'
$sh_c 'apt-get -qq update >/dev/null'
apt_flags="-y -qq"
$sh_c "apt-get $apt_flags install docker-ce >/dev/null"
EOF
prepare_docker_installer "$tmp/docker.sh"
sh "$tmp/docker.sh" >"$tmp/docker.log"
test "$(grep -c VISIBLE_PACKAGE_PROGRESS "$tmp/docker.log")" = 2
! grep -q -- '-qq' "$tmp/docker.log"
grep -q 'install docker-ce' "$tmp/docker.log"

sed -n '/^STEP=0$/,/^apt_run() {/ { /^apt_run() {/!p; }' install.sh >"$tmp/error.sh"
cat >>"$tmp/error.sh" <<'EOF'
set -Eeuo pipefail
STEP=3
TOTAL=10
LOG_FILE=""
false
EOF
if bash "$tmp/error.sh" >"$tmp/error.log" 2>&1; then
  exit 1
fi
grep -q 'Этап:    3' "$tmp/error.log"
grep -q 'Код:     1' "$tmp/error.log"
grep -q 'НАЧАЛО ДИАГНОСТИКИ' "$tmp/error.log"
load_function run_with_progress
if run_with_progress 'Проверка дочернего процесса' bash -c 'echo CHILD_OUTPUT; exit 7' >"$tmp/child.log" 2>&1; then
  exit 1
else
  test "$?" = 7
fi
test -z "${PROGRESS_PID:-}"
grep -q CHILD_OUTPUT "$tmp/child.log"
echo 'PASS: ожидание apt, вывод Docker, сохранение ошибки и диагностика этапа'
