#!/bin/bash
set -Eeuo pipefail
[[ "${DISPOSABLE_INSTALLER_QA:-}" == 1 ]] || exit 1
source /source/src/security.sh
NODE_DIR=$(mktemp -d)
RN_BACKUP=$(mktemp -d)
trap 'rm -rf "$NODE_DIR" "$RN_BACKUP"' EXIT
NODE_CONTAINER=remnanode
NODE_PORT=9744
RN_RUNNING_NODE_PORT=2222
cat >"$NODE_DIR/docker-compose.yml" <<'YAML'
services:
  node:
    image: remnawave/node:latest
    container_name: remnanode
    network_mode: host
    environment:
      - NODE_PORT=2222
      - SECRET_KEY=FAKE_KEEP
  other:
    image: nginx:stable
YAML
rn_ensure_packages() { :; }
docker() {
 case "$*" in
  'inspect -f {{.HostConfig.NetworkMode}} remnanode') echo host;;
  'inspect -f {{.Image}} remnanode'|'image inspect -f {{.Id}} remnawave/node:latest') echo sha256:unchanged;;
  'inspect -f {{.Config.Image}} remnanode') echo remnawave/node:latest;;
  'compose config --quiet') python3 -c 'import json;json.load(open("docker-compose.yml"))';;
  'compose up -d --no-deps --pull never node') :;;
  *) echo "QA unexpected Docker call: $*" >&2;return 1;;
 esac
}
ss() { echo 'LISTEN 0 4096 *:9744 *:*'; }
rn_change_node_port
python3 - "$NODE_DIR/docker-compose.yml" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]));env=c['services']['node']['environment']
assert 'NODE_PORT=9744' in env and 'NODE_PORT=2222' not in env
assert 'SECRET_KEY=FAKE_KEEP' in env
assert c['services']['other']['image']=='nginx:stable'
PY
once=$(sha256sum "$NODE_DIR/docker-compose.yml")
rn_change_node_port
[[ "$once" == "$(sha256sum "$NODE_DIR/docker-compose.yml")" ]]
echo QA_PASS_control_port_changed_without_key_image_or_other_service_changes
