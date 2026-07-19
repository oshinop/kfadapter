#!/usr/bin/env sh
# Prove developer Compose preserves protected SQLite state across force recreation.
set -eu

fail() {
    printf '%s\n' "local-compose-first-run: $*" >&2
    exit 1
}

[ "$#" -eq 1 ] || {
    printf '%s\n' "usage: scripts/check-local-compose-first-run.sh image-reference" >&2
    exit 2
}

IMAGE=$1
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
PROJECT=kfadapter-local
COMPOSE_FILE=$PROJECT_ROOT/deploy/compose.local-build.yaml
snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/kfadapter-local-compose.XXXXXXXX") || fail "could not create state snapshot directory"
cleanup_snapshot() {
    rm -rf -- "$snapshot_dir"
}
trap cleanup_snapshot EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || fail "Docker is required"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image is not available locally"

compose() {
    KFADAPTER_LOCAL_IMAGE=$IMAGE docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf -- "$snapshot_dir"
}
trap cleanup EXIT HUP INT TERM
compose down -v --remove-orphans >/dev/null 2>&1 || true

compose up -d --no-build kfadapter >/dev/null
container=$(compose ps -q kfadapter)
[ -n "$container" ] || fail "Compose did not create the service"
working_dir=$(docker inspect --format '{{.Config.WorkingDir}}' "$container")
[ "$working_dir" = "/kfadapter" ] || fail "local service working directory must be /kfadapter"

expected_state_volume="${PROJECT}_db_data"
mount=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/kfadapter/data"}}{{.Type}} {{.Name}}{{end}}{{end}}' "$container")
case "$mount" in
    "volume "*) ;;
    *) fail "local state must use a Docker-managed volume" ;;
esac
state_volume=${mount#volume }
[ "$state_volume" = "$expected_state_volume" ] || fail "local state must use its project-scoped db_data volume"

web_binding=$(docker inspect --format '{{with index .NetworkSettings.Ports "10809/tcp"}}{{(index . 0).HostIp}}:{{(index . 0).HostPort}}{{end}}' "$container")
socks_binding=$(docker inspect --format '{{with index .NetworkSettings.Ports "10808/tcp"}}{{(index . 0).HostIp}}:{{(index . 0).HostPort}}{{end}}' "$container")
if [ -n "$web_binding" ] || [ -n "$socks_binding" ]; then
    [ "$(docker inspect --format '{{len .NetworkSettings.Ports}}' "$container")" = 2 ] || fail "service must publish exactly web and SOCKS ports"
    [ "$web_binding" = "127.0.0.1:10809" ] || fail "web port must publish only to loopback"
    [ "$socks_binding" = "127.0.0.1:10808" ] || fail "SOCKS port must publish only to loopback"
fi
command -v curl >/dev/null 2>&1 || fail "curl is required"

wait_for_healthy() {
    container=$1
    attempt=0
    while [ "$attempt" -lt 60 ]; do
        if docker exec --workdir /kfadapter "$container" ./kfadapter healthcheck >/dev/null 2>&1; then
            docker exec "$container" /kfadapter/kfadapter validate-state --file /kfadapter/data/state.db >/dev/null 2>&1 || fail "initialized state is invalid"
            curl --fail --silent --show-error http://127.0.0.1:10809/healthz >/dev/null || fail "published management health endpoint is unreachable"
            curl --fail --silent --show-error http://127.0.0.1:10809/ >/dev/null || fail "published management interface is unreachable"
            startup_line='kfadapter: ready management=http://127.0.0.1:10809 proxy=socks5://127.0.0.1:10808'
            [ "$(docker logs "$container" 2>&1 | grep -Fxc "$startup_line")" = 1 ] || fail "safe startup endpoint log is missing or duplicated"
            return 0
        fi
        status=$(docker inspect --format '{{.State.Status}}' "$container")
        if [ "$status" != running ]; then
            docker logs "$container" >&2 || true
            fail "service exited before becoming healthy"
        fi
        attempt=$((attempt + 1))
        sleep 0.5
    done

    docker logs "$container" >&2 || true
    fail "service did not become healthy"
}

wait_for_healthy "$container"
before_state="$snapshot_dir/state-before.db"
docker cp "$container:/kfadapter/data/state.db" "$before_state" >/dev/null || fail "could not snapshot initialized SQLite state"
[ -s "$before_state" ] || fail "initialized SQLite state snapshot is empty"

compose up -d --no-build --force-recreate kfadapter >/dev/null
replacement=$(compose ps -q kfadapter)
[ -n "$replacement" ] || fail "force recreation did not create the service"
[ "$replacement" != "$container" ] || fail "force recreation reused the original container"
replacement_mount=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/kfadapter/data"}}{{.Type}} {{.Name}}{{end}}{{end}}' "$replacement")
[ "$replacement_mount" = "volume $state_volume" ] || fail "force recreation did not retain the named state volume"
wait_for_healthy "$replacement"
after_state="$snapshot_dir/state-after.db"
docker cp "$replacement:/kfadapter/data/state.db" "$after_state" >/dev/null || fail "could not snapshot recreated SQLite state"
cmp -s "$before_state" "$after_state" || fail "force recreation changed named-volume SQLite state bytes"
compose down -v --remove-orphans >/dev/null
if docker volume inspect "$state_volume" >/dev/null 2>&1; then
    fail "local Compose state volume was not removed by down -v"
fi

printf '%s\n' "local-compose-first-run: passed"
