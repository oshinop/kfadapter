#!/usr/bin/env sh
# Render a custom listener config and require the health probe to consume it.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
IMAGE_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000
unset KFADAPTER_IMAGE_REPOSITORY KFADAPTER_IMAGE

fail() {
    printf '%s\n' "configured-healthcheck: $*" >&2
    exit 1
}

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
work=$(mktemp -d "$tmp_root/kfadapter-healthcheck.XXXXXXXX")
work=$(CDPATH= cd -- "$work" && pwd -P)
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

config="$work/config.yml"
override="$work/compose-health.yaml"
cat >"$config" <<'YAML'
management:
  listen: 0.0.0.0:12009
  sessionTTL: 30m
proxy:
  listen: 0.0.0.0:12008
  dialTimeout: 10s
  handshakeTimeout: 15s
provider:
  requestTimeout: 15s
  refreshInterval: 23h
YAML
cat >"$override" <<EOF
services:
  kfadapter:
    volumes:
      - $config:/kfadapter/config.yml:ro
EOF

KFADAPTER_IMAGE_DIGEST="$IMAGE_DIGEST" \
docker compose --env-file /dev/null -f "$PROJECT_ROOT/compose.yaml" -f "$override" config --format json >"$work/rendered.json"
python3 - "$config" "$work/rendered.json" <<'PY'
from pathlib import Path
import json
import sys

config = Path(sys.argv[1]).resolve()
rendered = json.loads(Path(sys.argv[2]).read_text())
service = rendered["services"]["kfadapter"]
assert service["working_dir"] == "/kfadapter"
assert service["image"] == "ghcr.io/oshinop/kfadapter@sha256:0000000000000000000000000000000000000000000000000000000000000000"
assert service["healthcheck"]["test"] == ["CMD", "./kfadapter", "healthcheck"]
mounts = {mount["target"]: mount for mount in service["volumes"]}
state = mounts["/kfadapter/data"]
config_mount = mounts["/kfadapter/config.yml"]
assert state["type"] == "volume"
assert state["source"] == "db_data"
assert state.get("read_only") is not True
assert config_mount["type"] == "bind"
assert config_mount["read_only"] is True
assert Path(config_mount["source"]).resolve() == config
assert rendered["volumes"] == {"db_data": {"name": "kfadapter_db_data"}}
text = config.read_text()
assert "listen: 0.0.0.0:12009" in text
assert "sessionTTL: 30m" in text
assert "listen: 0.0.0.0:12008" in text
assert "handshakeTimeout: 15s" in text
assert "requestTimeout: 15s" in text
assert "refreshInterval: 23h" in text
ports = {(port["host_ip"], int(port["published"]), int(port["target"])) for port in service["ports"]}
assert ports == {("127.0.0.1", 10809, 10809), ("127.0.0.1", 10808, 10808)}
PY
printf '%s\n' "configured-healthcheck: passed"
