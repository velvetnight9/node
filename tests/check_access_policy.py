"""Проверяет сутки бана SSH и реальную ротацию закреплённого watchdog при Google RU."""
from pathlib import Path
import configparser
import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path(__file__).resolve().parents[1]
BASH = os.environ.get('QA_BASH', 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash')
for name in ('install.sh', 'install-yandex-cdn.sh', 'install-timeweb-cdn.sh'):
    text = (ROOT / name).read_text(encoding='utf-8')
    jail = re.search(r'cat >/etc/fail2ban/jail.d/99-remnanode-sshd.local <<EOF\n(.*?)\nEOF', text, re.S)[1]
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(jail)
    ssh = config['sshd']
    assert ssh.getint('maxretry') == 6, (name, 'Бан должен начинаться после пяти ошибок')
    assert ssh['findtime'] == '10m', name
    assert ssh['bantime'] == '24h', (name, 'Бан должен длиться сутки')
    assert ssh['bantime.increment'] == 'false', name
    assert ssh['bantime.rndtime'] == '0', name
    assert ssh['banaction'] == 'nftables-multiport', name
    print('PASS', name, 'шестая ошибка SSH за 10 минут, бан ровно 24 часа')

installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
assert '--deny-regions "RU BY IR SY CU KP CN VE"' in installer
assert '--no-watchdog' not in installer
upstream = Path(sys.argv[1]).read_bytes()
expected = re.search(r'^PSIPHON_INSTALLER_SHA256="([a-f0-9]+)"', installer, re.M)[1]
assert hashlib.sha256(upstream).hexdigest() == expected, 'Нужен закреплённый upstream installer'
source = upstream.decode()
assert 'WATCHDOG=1' in source
assert 'systemctl enable --now vps-psiphon-watchdog.timer' in source
watchdog = re.search(r"cat > /usr/local/sbin/vps-psiphon-watchdog <<'WD'\n(.*?)\nWD", source, re.S)[1]

# Запускаем настоящий watchdog, заменяя только системные пути и внешние вызовы.
harness = r'''
set -euo pipefail
cd "$1"
export PATH="$PWD/bin:$PATH"
mkdir -p bin
cat > bin/curl <<'SH'
#!/bin/bash
case "$*" in
  *generate_204*) printf 204 ;;
  *youtube.com*)
    while (($#)); do
      if [[ "$1" == -o ]]; then printf '{"GL":"%s"}' "$MOCK_GL" >"$2"; break; fi
      shift
    done
    printf '204800 200' ;;
  *ipify.org*) printf 192.0.2.1 ;;
esac
SH
printf '#!/bin/bash\necho "$*" >> systemctl.log\n' > bin/systemctl
printf '#!/bin/bash\n:\n' > bin/sleep
printf '#!/bin/bash\nprintf "2020-01-01T00:00:00Z"\n' > bin/docker
chmod +x bin/*
for region in RU DE; do
  export MOCK_GL="$region"
  rm -f state systemctl.log
  bash watchdog.sh
  test ! -s systemctl.log
  bash watchdog.sh
  if [[ "$region" == RU ]]; then
    grep -q 'restart vps-psiphon.service' systemctl.log
    grep -q 'denied-country (Google sees RU' watchdog.log
    # Следующие отказы не должны вызывать повторный restart во время cooldown.
    bash watchdog.sh
    bash watchdog.sh
    test "$(wc -l < systemctl.log)" = 1
  else
    test ! -s systemctl.log
  fi
done
'''
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    watchdog = watchdog.replace('/etc/default/vps-psiphon', './env').replace('/var/log/vps-psiphon-watchdog.log', './watchdog.log').replace('/var/lib/vps-psiphon-watchdog.state', './state').replace('/usr/local/sbin/vps-psiphon-advance-region', 'true')
    (folder / 'watchdog.sh').write_text(watchdog, encoding='utf-8', newline='\n')
    (folder / 'env').write_text("SOCKS_PORT=1080\nBIND=172.17.0.1\nEGRESS_REGION=DE\nDENY_REGIONS='RU BY IR SY CU KP CN VE'\nFAIL_THRESHOLD=2\nFAIL_WINDOW=5\nROTATE_COOLDOWN=1800\n", encoding='utf-8')
    result = subprocess.run([BASH, '-c', harness, 'test', folder.as_posix()], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
print('PASS Google RU вызывает ротацию, DE не вызывает, cooldown защищает от повторных restart')
