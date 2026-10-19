#!/bin/bash
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || exit 1
export DEBIAN_FRONTEND=noninteractive
export SSH_PORT=24022
export SSH_PUBLIC_KEY="$(cat /root/qa-ssh-test/key.pub)"
systemctl start ssh.service
apt-get update
apt-get install -y nginx openssl
source /source/src/security.sh
source /source/src/cdn.sh
# След предыдущего прогона в этой же одноразовой QA VM.
rm -f /etc/nginx/sites-enabled/remnanode-cdn.conf
install -d /etc/letsencrypt/live/origin.example.test
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=origin.example.test -addext subjectAltName=DNS:origin.example.test -addext basicConstraints=critical,CA:true -keyout /etc/letsencrypt/live/origin.example.test/privkey.pem -out /etc/letsencrypt/live/origin.example.test/fullchain.pem >/dev/null 2>&1
cp /etc/letsencrypt/live/origin.example.test/fullchain.pem /usr/local/share/ca-certificates/qa-origin.crt
update-ca-certificates
cat >/tmp/qa-xhttp-http.py <<'PY'
import ctypes,http.server
ctypes.CDLL(None).prctl(15,b'rw-core',0,0,0)
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(400);self.end_headers()
 def log_message(self,*args):pass
http.server.HTTPServer(('127.0.0.1',7443),H).serve_forever()
PY
python3 /tmp/qa-xhttp-http.py & CORE=$!
trap 'kill "$CORE" 2>/dev/null || true' EXIT
sleep 1
export ORIGIN_DOMAIN=origin.example.test NODE_PORT=9744 PANEL_IPS='10.77.0.3 fd77::3'
export SSH_CONNECTION='10.99.0.10 43210 10.77.0.1 22'
export NGINX_CONFIG=/etc/nginx/sites-available/qa-cdn.conf
ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/qa-cdn.conf
# Моделируется только Docker API; nginx, TLS, пакеты, systemd, nft/UFW настоящие.
docker() {
 case "$*" in
  'inspect remnanode') echo '[{"Config":{"Env":["NODE_PORT=9744"]},"HostConfig":{"NetworkMode":"host"},"State":{"Running":true}}]';;
  'inspect -f {{.State.Running}} remnanode') echo true;;
  'inspect -f {{.State.Running}} cdn-nginx'|'inspect cdn-nginx') return 1;;
  *) echo "Unexpected Docker mutation: $*" >&2; return 1;;
 esac
}; export -f docker
apt-get() { :; }; export -f apt-get
for provider in yandex timeweb; do
 CDN_PROVIDER=$provider
 XHTTP_PORT=4443
 if [[ "$provider" == timeweb ]]; then XHTTP_PATH=/assets/stream.ts; else XHTTP_PATH=/; fi
 export XHTTP_PATH
 rn_cdn_nginx_config 1 >"$NGINX_CONFIG"
 nginx -t
 systemctl restart nginx
 before=$(curl -sS --max-time 5 --resolve origin.example.test:443:127.0.0.1 -o /dev/null -w '%{http_code}' "https://origin.example.test$XHTTP_PATH")
 [[ "$before" == 502 ]] || { echo "QA_FAIL before_$provider=$before"; exit 1; }
 unset XHTTP_PORT
 bash "/source/install-$provider-cdn.sh" --repair
 grep -q 'server 127.0.0.1:7443;' "$NGINX_CONFIG"
 after=$(curl -sS --max-time 5 --resolve origin.example.test:443:127.0.0.1 -o /dev/null -w '%{http_code}' "https://origin.example.test$XHTTP_PATH")
 [[ "$after" == 400 ]] || { echo "QA_FAIL after_$provider=$after"; exit 1; }
 once=$(sha256sum "$NGINX_CONFIG")
 main_once=$(sha256sum /etc/nginx/nginx.conf)
 bash "/source/install-$provider-cdn.sh" --repair
 [[ "$once" == "$(sha256sum "$NGINX_CONFIG")" ]] || exit 1
 [[ "$main_once" == "$(sha256sum /etc/nginx/nginx.conf)" ]] || exit 1
 nginx -T 2>/dev/null | grep 'worker_connections 8192;' >/dev/null
 nginx -T 2>/dev/null | grep 'worker_rlimit_nofile 65535;' >/dev/null
 echo "QA_PASS ${provider}_native_https_502_to_400_and_idempotent_repair"
done
# Возобновление после неудачного ACME: нода уже есть, HTTP bootstrap записан.
rm -f /etc/nginx/sites-enabled/qa-cdn.conf
export NGINX_CONFIG=/etc/nginx/sites-available/remnanode-cdn.conf EMAIL=qa@example.test
CDN_PROVIDER=yandex
XHTTP_PATH=/
XHTTP_PORT=4443
rn_cdn_nginx_config 0 >"$NGINX_CONFIG"
ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/remnanode-cdn.conf
certbot() { printf 'QA_ACME %s\n' "$*"; }; export -f certbot
unset XHTTP_PORT
bash /source/install-yandex-cdn.sh --repair
grep -q 'ssl_certificate ' "$NGINX_CONFIG"
echo QA_PASS interrupted_http_bootstrap_resumes_without_node_reinstall
echo ALL_CDN_QA_PASSED
