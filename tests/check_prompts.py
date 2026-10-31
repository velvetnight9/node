"""Проверяет ввод ключа до установки и остановку настоящего индикатора при вопросе."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
BASH = os.environ.get('QA_BASH', 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash')
installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
common = installer.split('# BEGIN SHARED SECURITY\n', 1)[1].split('# END SHARED SECURITY', 1)[0]
progress = installer[installer.index('STEP=0\n'):installer.index('\nok() {')]


def run(source, *, answer='', args=()):
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / 'scenario.sh'
        script.write_text('set -e\n' + source, encoding='utf-8', newline='\n')
        result = subprocess.run([BASH, script.as_posix(), *args], input=answer.encode(), capture_output=True, timeout=5)
        result.stdout = result.stdout.decode('utf-8')
        result.stderr = result.stderr.decode('utf-8')
        return result


# Меняем только устройство ввода/вывода, системные настройки не применяются.
common = common.replace('>/dev/tty', '>&2').replace('</dev/tty', '<&0').replace('-r /dev/tty', '-r /dev/stdin')
scenario = common + '\n' + progress + r'''
info() { :; }
LOG_FILE=test
step 'Проверка ввода' >/dev/null 2>&1
trap 'stop_progress' EXIT
rn_ask SSH_PUBLIC_KEY 'PUBLIC_KEY_PROMPT'
[[ "$SSH_PUBLIC_KEY" == test-public-key ]]
[[ -z "$PROGRESS_PID" ]] || { echo 'Индикатор продолжает стирать вопрос' >&2; exit 1; }
'''
result = run(scenario, answer='test-public-key\n')
assert result.returncode == 0, result.stdout + result.stderr
assert 'PUBLIC_KEY_PROMPT' in result.stderr
print('PASS вопрос останавливает настоящий индикатор и принимает ответ')

preflight = installer.index("rn_ssh_key_input\n", installer.index('# docker-compose\n'))
assert preflight < installer.index('\nstart_install_log\n'), 'Ключ запрашивается после запуска установки'
print('PASS ключ запрашивается до журнала и индикатора установки')

scenario = common + r'''
rn_ssh_verified_key() { return 1; }
install() { echo 'Слишком раннее изменение сервера' >&2; return 1; }
SSH_PUBLIC_KEY=invalid
if rn_ssh_key_input; then exit 1; fi
rn_ssh_verified_key() { return 0; }
if rn_ssh_key_input; then exit 1; fi
rn_ssh_verified_key() { return 1; }
SSH_PUBLIC_KEY="$1"
rn_ssh_key_input
unset SSH_PUBLIC_KEY
rn_ssh_verified_key() { return 0; }
rn_ssh_key_input
'''
# Ключ одноразовый, используется только для проверки формата.
public_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZXbNTtFh0GzTPqb6RgyEAjM8WaI+Er3hWZncF3kwSK'
result = run(scenario, args=(public_key,))
assert result.returncode == 0, result.stdout + result.stderr
assert 'Публичный SSH-ключ для root' not in result.stderr
print('PASS ранняя проверка ключа без изменения сервера, повторного ввода и запроса при подтверждённом входе')
