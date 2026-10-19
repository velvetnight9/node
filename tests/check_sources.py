"""Быстрые проверки сборки, конфигов и сохранения существующего upstream."""
from pathlib import Path
import ast
import os
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
BASH=os.environ.get('QA_BASH','C:/Program Files/Git/bin/bash.exe' if os.name=='nt' else 'bash')
common=(ROOT/'src/security.sh').read_text(encoding='utf-8')
for name in ('install.sh','install-yandex-cdn.sh','install-timeweb-cdn.sh'):
    text=(ROOT/name).read_text(encoding='utf-8')
    assert common in text,(name,'Общая защита не пересобрана')
    subprocess.run([BASH,'-n',str(ROOT/name)],check=True,capture_output=True)
    for snippet in re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)",text,re.S):ast.parse(snippet)
    assert 'ufw allow "$NODE_PORT"/tcp' not in text
    assert 'cat >/etc/fail2ban/jail.local' not in text
    assert 'banaction = nftables-multiport' in text
    assert 'ct status dnat ct original proto-dst' in text
    if name!='install.sh':
        for bad in ('ssh-ed25519 AAAA','traffic-guard full','tc qdisc del'):
            assert bad not in text,(name,bad)
        static_ips=set(re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',text))
        assert static_ips <= {'0.0.0.0','127.0.0.0','127.0.0.1'},(name,static_ips)
    print('PASS',name,'Bash/Python/общая защита')

# Проверяем настоящий Python-патчер nginx, не имитацию его реализации.
source=(ROOT/'src/cdn.sh').read_text(encoding='utf-8')
patcher=next(s for s in re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)",source,re.S) if 'Несколько upstream' in s)
with tempfile.TemporaryDirectory() as tmp:
    f=Path(tmp)/'nginx.conf'
    original='upstream cdn_xhttp {\n    server 127.0.0.1:4443;\n}\nserver {\nlocation / { proxy_pass http://cdn_xhttp; }\n}\n'
    f.write_text(original)
    r=subprocess.run([os.sys.executable,'-X','utf8','-c',patcher,str(f),'7443'],capture_output=True,text=True)
    assert r.returncode==0 and f.read_text()==original.replace(':4443;',':7443;'),r.stderr
    once=f.read_bytes()
    subprocess.run([os.sys.executable,'-X','utf8','-c',patcher,str(f),'7443'],check=True,capture_output=True)
    assert once==f.read_bytes()
    f.write_text(original+'upstream other {\nserver 127.0.0.1:5555;\n}\n')
    before=f.read_bytes()
    r=subprocess.run([os.sys.executable,'-X','utf8','-c',patcher,str(f),'7443'],capture_output=True)
    assert r.returncode!=0 and before==f.read_bytes()
print('PASS nginx 4443→7443, повтор без изменений, отказ при неоднозначности')

limits=next(s for s in re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)",source,re.S) if "max(8192" in s)
with tempfile.TemporaryDirectory() as tmp:
    f=Path(tmp)/'nginx.conf'
    f.write_text('user www-data;\nevents {\n worker_connections 768;\n}\nhttp {}\n')
    command=[os.sys.executable,'-X','utf8','-c',limits,str(f)]
    subprocess.run(command,check=True,capture_output=True)
    assert 'worker_connections 8192;' in f.read_text() and 'worker_rlimit_nofile 65535;' in f.read_text()
    once=f.read_bytes()
    subprocess.run(command,check=True,capture_output=True)
    assert once==f.read_bytes()
    large=f.read_text().replace('8192','32768').replace('65535','262144')
    f.write_text(large)
    subprocess.run(command,check=True,capture_output=True)
    assert f.read_text()==large
    f.write_text('user www-data;\nhttp {}\n')
    before=f.read_bytes()
    result=subprocess.run(command,capture_output=True)
    assert result.returncode!=0 and f.read_bytes()==before
print('PASS лимиты nginx: повышение, сохранение больших, повтор, отказ без events')

detector=re.search(r"python3 -c '\n(.*?)\n' \"\$NODE_PORT\"",common.split('rn_discover_public_inbounds() {',1)[1],re.S)[1]
sample='''tcp LISTEN 0 4096 0.0.0.0:24443 0.0.0.0:* users:(("rw-core",pid=100,fd=1))
tcp LISTEN 0 4096 127.0.0.1:7443 0.0.0.0:* users:(("rw-core",pid=100,fd=2))
tcp LISTEN 0 4096 [::]:61000 [::]:* users:(("rw-core",pid=100,fd=3))
tcp LISTEN 0 4096 [::]:9744 [::]:* users:(("rw-node",pid=99,fd=3))
tcp LISTEN 0 4096 0.0.0.0:55203 0.0.0.0:* users:(("rw-core",pid=101,fd=3)) uid:65534 ino:789
udp UNCONN 0 0 [::]:443 [::]:* users:(("xray",pid=100,fd=4))
'''
r=subprocess.run([os.sys.executable,'-X','utf8','-c',detector,'9744'],input=sample,capture_output=True,text=True)
assert r.returncode==0 and r.stdout=='tcp 24443\n',(r.stdout,r.stderr)
print('PASS определение 24443/TCP без локального XHTTP/API и неподтверждённых UDP')
