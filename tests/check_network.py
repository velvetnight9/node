"""Изолированная проверка IPv6/BBR без изменения сетевых настроек машины."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('QA_BASH', 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash')
SOURCE = (ROOT / 'src/security.sh').read_text(encoding='utf-8')
HARNESS = r'''
set -Eeuo pipefail
source "$1/source.sh"
root="$1"
scenario="$2"
export RN_BACKUP="$root/backup" PANEL_IPS='192.0.2.20' SSH_CONNECTION='192.0.2.10 12345 192.0.2.1 22'
rn_ensure_packages() { :; }
rn_ssh_context() { :; }
modprobe() { echo "$*" >>"$root/modprobe.log"; [[ "$scenario" != builtin ]]; }
sysctl() {
  if [[ "$1" == -n ]]; then
    case "$2" in
      net.ipv4.tcp_available_congestion_control)
        if [[ "$scenario" == unsupported ]]; then echo 'reno cubic'; else echo 'reno cubic bbr'; fi;;
      net.ipv4.tcp_congestion_control) cat "$root/cc";;
      net.core.default_qdisc) cat "$root/qdisc";;
      *) return 1;;
    esac
  elif [[ "$1" == -p ]]; then
    echo "$2" >>"$root/apply.log"
    local key equal value path
    while read -r key equal value; do
      [[ "$equal" == = ]] || continue
      key="${key#-}"
      case "$key" in
        net.core.default_qdisc) echo "$value" >"$root/qdisc";;
        net.ipv4.tcp_congestion_control) echo "$value" >"$root/cc";;
        net.ipv6.conf.all.disable_ipv6|net/ipv6/conf/all/disable_ipv6)
          for path in "$root"/ipv6/*/disable_ipv6; do
            [[ -f "$path" ]] || continue
            [[ "$scenario" != verify-failure || "$path" != */eth0/* ]] || continue
            echo "$value" >"$path"
          done;;
        net.ipv6.conf.*.disable_ipv6)
          path="${key#net.ipv6.conf.}"; path="${path%.disable_ipv6}"
          [[ ! -f "$root/ipv6/$path/disable_ipv6" ]] || echo "$value" >"$root/ipv6/$path/disable_ipv6";;
        net/ipv6/conf/*/disable_ipv6)
          path="${key#net/ipv6/conf/}"; echo "$value" >"$root/ipv6/$path";;
        *) return 1;;
      esac
      if [[ "$scenario" == apply-failure && "$2" == */network-new.conf ]]; then return 1; fi
    done <"$2"
  else return 1; fi
}
case "$scenario" in
  ipv6-ssh) SSH_CONNECTION='2001:db8::10 12345 2001:db8::1 22';;
  ipv6-server-ssh) SSH_CONNECTION='192.0.2.10 12345 ::ffff:192.0.2.1 22';;
  ipv6-panel) PANEL_IPS='2001:db8::20';;
esac
case "$scenario" in
  ipv6-ssh|ipv6-server-ssh|ipv6-panel)
    if rn_network_access; then exit 10; fi
    [[ ! -e "$root/apply.log" && ! -e "$root/modprobe.log" ]];;
  unsupported|apply-failure|verify-failure)
    if rn_network; then exit 11; fi
    [[ "$(cat "$root/cc")" == cubic && "$(cat "$root/qdisc")" == pfifo_fast ]]
    [[ "$(cat "$root/ipv6/eth0/disable_ipv6")" == 0 ]]
    [[ "$(cat "$root/ipv6/eth0.100/disable_ipv6")" == 1 ]]
    [[ "$(cat "$root/sysctl.d/99-remnanode-network.conf")" == OLD_SYSCTL ]]
    [[ "$(cat "$root/modules-load.d/remnanode-network.conf")" == OLD_MODULES ]]
    [[ "$scenario" != unsupported || ! -e "$root/apply.log" ]];;
  *)
    rn_network
    rn_network_verify
    cp "$root/sysctl.d/99-remnanode-network.conf" "$root/once"
    cp "$root/modules-load.d/remnanode-network.conf" "$root/modules-once"
    rn_network
    cmp "$root/once" "$root/sysctl.d/99-remnanode-network.conf"
    cmp "$root/modules-once" "$root/modules-load.d/remnanode-network.conf"
    grep -qx tcp_bbr "$root/modules-once"
    grep -qx sch_fq "$root/modules-once"
    [[ "$(cat "$root/cc")" == bbr && "$(cat "$root/qdisc")" == fq ]];;
esac
'''

for scenario in ('ok', 'builtin', 'kernel-ipv6-off', 'unsupported', 'apply-failure',
                 'verify-failure', 'ipv6-ssh', 'ipv6-server-ssh', 'ipv6-panel'):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in ('backup', 'sysctl.d', 'modules-load.d'):
            (root / name).mkdir()
        if scenario != 'kernel-ipv6-off':
            for interface in ('all', 'default', 'lo', 'eth0', 'eth0.100'):
                path = root / 'ipv6' / interface
                path.mkdir(parents=True)
                (path / 'disable_ipv6').write_text('1\n' if interface == 'eth0.100' else '0\n')
        (root / 'cc').write_text('cubic\n')
        (root / 'qdisc').write_text('pfifo_fast\n')
        (root / 'sysctl.d/99-remnanode-network.conf').write_text('OLD_SYSCTL\n')
        (root / 'modules-load.d/remnanode-network.conf').write_text('OLD_MODULES\n')
        source = SOURCE.replace('/etc/sysctl.d', root.as_posix() + '/sysctl.d')
        source = source.replace('/etc/modules-load.d', root.as_posix() + '/modules-load.d')
        source = source.replace('/proc/sys/net/ipv6/conf', root.as_posix() + '/ipv6')
        (root / 'source.sh').write_text(source, encoding='utf-8', newline='\n')
        result = subprocess.run([BASH, '-c', HARNESS, 'network-qa', root.as_posix(), scenario],
                                capture_output=True, text=True, encoding='utf-8')
        assert result.returncode == 0, (scenario, result.returncode, result.stdout, result.stderr)
        print('PASS', scenario)
