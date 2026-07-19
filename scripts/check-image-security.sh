#!/usr/bin/env sh
# Verify the final image's observable Alpine runtime contract.
set -eu

fail() {
    printf '%s\n' "image-security: $*" >&2
    exit 1
}

[ "$#" -eq 1 ] || {
    printf '%s\n' "usage: scripts/check-image-security.sh image-reference" >&2
    exit 2
}
IMAGE=$1
command -v docker >/dev/null 2>&1 || fail "Docker is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

docker image inspect "$IMAGE" | python3 -c '
import json
import re
import sys

image = json.load(sys.stdin)[0]
config = image["Config"]
if config.get("User") != "65532:65532":
    raise SystemExit("image-security: runtime user must be numeric 65532:65532")
if config.get("WorkingDir") != "/kfadapter":
    raise SystemExit("image-security: runtime working directory must be /kfadapter")
if config.get("Entrypoint") != ["./kfadapter"]:
    raise SystemExit("image-security: entrypoint must be the adapter binary relative to its working directory")
if config.get("Volumes"):
    raise SystemExit("image-security: final image must not declare a volume")
if config.get("ExposedPorts"):
    raise SystemExit("image-security: final image must not expose ports")
labels = config.get("Labels") or {}
if not labels.get("org.opencontainers.image.version"):
    raise SystemExit("image-security: missing OCI version label")
sensitive = re.compile(r"(?:password|secret|token|credential|authkey|encryptkey|provider)", re.I)
for entry in config.get("Env") or []:
    name, _, value = entry.partition("=")
    if sensitive.search(name) or sensitive.search(value):
        raise SystemExit(f"image-security: secret-like environment entry {name}")
'

container=$(docker create "$IMAGE")
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
files=$(mktemp)
trap 'rm -f "$files"; cleanup' EXIT HUP INT TERM
docker export "$container" | tar -tf - >"$files"
grep -Eq '(^|/)kfadapter/kfadapter$' "$files" || fail "adapter binary is missing"
grep -Eq '(^|/)etc/alpine-release$' "$files" || fail "final image is not Alpine"
grep -Eq '(^|/)bin/sh$' "$files" || fail "Alpine shell is missing"
docker export "$container" | python3 -c '
import sys
import tarfile

found = False
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
    for member in archive:
        if member.name.rstrip("/") != "kfadapter/data":
            continue
        found = True
        if not member.isdir() or member.uid != 65532 or member.gid != 65532 or member.mode & 0o7777 != 0o700:
            raise SystemExit("image-security: /kfadapter/data must be a 0700 directory owned by 65532:65532")
if not found:
    raise SystemExit("image-security: /kfadapter/data is missing")
'
if ! docker run --rm --entrypoint /bin/sh "$IMAGE" -c 'test -x /kfadapter/kfadapter'; then
    fail "Alpine runtime cannot execute the adapter binary"
fi
printf '%s\n' "image-security: passed"
