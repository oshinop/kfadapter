#!/usr/bin/env sh
# Fail unless the active Docker Engine is reached through a local unix socket.
set -eu

fail() {
    printf '%s\n' "docker-local-context: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "Docker Engine is required"
case "${DOCKER_HOST:-}" in
    ''|unix:///*) ;;
    *) fail "DOCKER_HOST must use a local unix-socket endpoint" ;;
esac
context_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}') ||
    fail "could not inspect the active Docker context"
case "$context_host" in
    ''|*'
'*) fail "active Docker context returned an empty or ambiguous endpoint" ;;
    unix:///*) ;;
    *) fail "active Docker context must use a local unix-socket endpoint" ;;
esac
