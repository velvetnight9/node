#!/usr/bin/env bash
# Проверяем реальный вывод в отдельном shell, без установки пакетов.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
sed -n '/^STEP=0$/,/^apt_run() {/ { /^apt_run() {/!p; }' install.sh >"$tmp/functions.sh"
cat >"$tmp/scenario.sh" <<'EOF'
set -Eeuo pipefail
source "$1/functions.sh"
mode="$2"
SECRET_KEY='test-secret-do-not-print'
test_dir="$1"
# Перенаправляем только создание файлов: настоящие системные каталоги не трогаем.
install() { :; }
mktemp() { command mktemp "$test_dir/$(basename "$1")"; }
start_install_log
printf '%s' "$LOG_FILE" >"$test_dir/$mode.path"
step 'Установка пакетов'
echo 'PACKAGE_INSTALL_NOISE'
echo "$SECRET_KEY"
case "$mode" in
  error) false ;;
  nested) value="$(false)" ;;
  explicit) err 'Служба не запустилась'; exit 7 ;;
  interrupt) kill -INT "$$" ;;
  success)
    sleep 2
    stop_progress
    draw_progress 1 2 '✓'
    printf '\n' >&3
    STEP=10
    STEP_LABEL='Готово'
    draw_progress 10 2 '✓'
    printf '\n' >&3
    ;;
esac
EOF
for mode in success error nested explicit interrupt; do
  rc=0
  bash "$tmp/scenario.sh" "$tmp" "$mode" >"$tmp/$mode.out" 2>&1 || rc=$?
  ! grep -q 'test-secret-do-not-print' "$tmp/$mode.out"
  grep -q PACKAGE_INSTALL_NOISE "$(cat "$tmp/$mode.path")"
  if [[ "$mode" == success ]]; then
    test "$rc" = 0
    ! grep -q PACKAGE_INSTALL_NOISE "$tmp/$mode.out"
    grep -q '100%' "$tmp/$mode.out"
    grep -q '10%' "$tmp/$mode.out"
  else
    case "$mode" in error|nested) test "$rc" = 1;; explicit) test "$rc" = 7;; interrupt) test "$rc" = 130;; esac
    test "$(grep -c 'НАЧАЛО ДИАГНОСТИКИ' "$tmp/$mode.out")" = 1
    grep -q 'Установка пакетов' "$tmp/$mode.out"
    grep -q PACKAGE_INSTALL_NOISE "$tmp/$mode.out"
    grep -q 'ключ скрыт' "$tmp/$mode.out"
    [[ "$mode" != explicit ]] || grep -q 'Служба не запустилась' "$tmp/$mode.out"
  fi
  echo "PASS: $mode"
done
