#!/usr/bin/env sh
# Perform a digest-pinned upgrade and restore the prior immutable image on failure.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
STATE_VOLUME=kfadapter_db_data
BACKUP_DIR=${BACKUP_DIR:-"$PROJECT_ROOT/backups"}

fail() {
    printf '%s\n' "upgrade: $*" >&2
    exit 1
}

compose() {
    docker compose --env-file /dev/null -f "$PROJECT_ROOT/compose.yaml" "$@"
}

wait_for_healthy() {
    health_failure="replacement did not become healthy within 60 seconds"
    attempt=0
    while [ "$attempt" -lt 12 ]; do
        container=$(compose ps -q kfadapter 2>/dev/null || true)
        if [ -z "$container" ]; then
            health_failure="replacement container was not created"
            return 1
        fi
        status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container" 2>/dev/null || true)
        case "$status" in
            healthy)
                return 0
                ;;
            unhealthy|exited|dead|missing|'')
                health_failure="replacement did not become healthy (status: ${status:-missing})"
                return 1
                ;;
        esac
        attempt=$((attempt + 1))
        sleep 5 || {
            health_failure="could not wait for replacement health"
            return 1
        }
    done
    return 1
}

verify_state_mount() {
    inspected_container=$1
    state_mount_failure="could not inspect the running state mount"
    inspected_state_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/kfadapter/data"}}{{.Type}}{{end}}{{end}}' "$inspected_container") || return 1
    inspected_state_name=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/kfadapter/data"}}{{.Name}}{{end}}{{end}}' "$inspected_container") || return 1
    inspected_state_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/kfadapter/data"}}{{.Source}}{{end}}{{end}}' "$inspected_container") || return 1
    if [ "$inspected_state_type" != volume ] || [ "$inspected_state_name" != "$STATE_VOLUME" ]; then
        state_mount_failure="running service does not use the Compose-managed Docker state volume"
        return 1
    fi
    inspected_state_identity=$(python3 "$SCRIPT_DIR/verify-state-path.py" \
        --state-dir "$inspected_state_source" \
        --base "$PROJECT_ROOT" \
        --uid "${KFADAPTER_HOST_UID:-65532}" \
        --gid "${KFADAPTER_HOST_GID:-65532}" 2>/dev/null) || {
        state_mount_failure="running service state path failed identity validation"
        return 1
    }
    if [ "$inspected_state_identity" != "$state_identity" ]; then
        state_mount_failure="running service state path identity changed"
        return 1
    fi
    return 0
}

state_backup_ready=0
pre_upgrade_archive=
rollback_failure=
upgrade_in_progress=0
rollback_in_progress=0
rollback() {
    export KFADAPTER_IMAGE_REPOSITORY=$old_repository
    export KFADAPTER_IMAGE_DIGEST=$old_digest
    if ! compose stop kfadapter; then
        rollback_failure="could not stop the replacement service before rollback"
        return 1
    fi
    if ! docker image inspect "$old_image" >/dev/null 2>&1; then
        rollback_failure="cached prior immutable image is unavailable"
        return 1
    fi
    if [ "$state_backup_ready" -eq 1 ]; then
        if ! "$SCRIPT_DIR/restore-state.sh" "$pre_upgrade_archive"; then
            rollback_failure="could not restore the protected pre-upgrade state archive"
            return 1
        fi
        state_identity=$(python3 "$SCRIPT_DIR/verify-state-path.py" \
            --state-dir "$state_dir" \
            --base "$PROJECT_ROOT" \
            --uid "${KFADAPTER_HOST_UID:-65532}" \
            --gid "${KFADAPTER_HOST_GID:-65532}") || {
            rollback_failure="restored state path failed identity validation"
            return 1
        }
    fi
    if ! compose up -d --pull never --no-deps --force-recreate kfadapter; then
        if ! compose stop kfadapter; then
            rollback_failure="could not recreate the prior immutable service and could not stop its partial container"
        else
            rollback_failure="could not recreate the prior immutable service from the local cache"
        fi
        return 1
    fi
    rollback_mount_failure=
    rollback_container=$(compose ps -q kfadapter 2>/dev/null || true)
    if [ -z "$rollback_container" ]; then
        rollback_mount_failure="prior immutable service container was not created"
    elif ! verify_state_mount "$rollback_container"; then
        rollback_mount_failure=$state_mount_failure
    fi
    if [ -n "$rollback_mount_failure" ]; then
        if ! compose stop kfadapter; then
            rollback_failure="$rollback_mount_failure and the partial prior service could not be stopped"
        else
            rollback_failure=$rollback_mount_failure
        fi
        return 1
    fi
    if ! wait_for_healthy; then
        prior_health_failure=$health_failure
        if ! compose stop kfadapter; then
            rollback_failure="prior immutable service was not healthy after rollback and could not be stopped: $prior_health_failure"
        else
            rollback_failure="prior immutable service was not healthy after rollback: $prior_health_failure"
        fi
        return 1
    fi
    return 0
}

rollback_or_fail() {
    rollback_in_progress=1
    trap - EXIT HUP INT TERM
    original_failure=$1
    if rollback; then
        if [ "$state_backup_ready" -eq 1 ]; then
            printf '%s\n' "upgrade: $original_failure; prior immutable service was restored and is healthy; pre-upgrade state archive was restored" >&2
        else
            printf '%s\n' "upgrade: $original_failure; prior immutable service was restored and is healthy; no pre-upgrade state archive was created" >&2
        fi
    else
        printf '%s\n' "upgrade: original failure: $original_failure; rollback failure: $rollback_failure" >&2
    fi
    exit 1
}

handle_upgrade_exit() {
    exit_status=$1
    trap - EXIT HUP INT TERM
    if [ "$exit_status" -eq 0 ] || [ "$upgrade_in_progress" -ne 1 ] || [ "$rollback_in_progress" -eq 1 ]; then
        exit "$exit_status"
    fi
    rollback_in_progress=1
    if rollback; then
        printf '%s\n' "upgrade: interrupted; prior immutable service and protected state were restored" >&2
    else
        printf '%s\n' "upgrade: interrupted; rollback failure: $rollback_failure" >&2
    fi
    exit "$exit_status"
}

trap 'handle_upgrade_exit 129' HUP
trap 'handle_upgrade_exit 130' INT
trap 'handle_upgrade_exit 143' TERM
trap 'handle_upgrade_exit $?' EXIT

[ "$#" -eq 0 ] || {
    printf '%s\n' "usage: set KFADAPTER_IMAGE_DIGEST=sha256:<digest>; optionally set KFADAPTER_IMAGE_REPOSITORY=repository (default: ghcr.io/oshinop/kfadapter); scripts/upgrade.sh" >&2
    exit 2
}
[ -n "${KFADAPTER_IMAGE_DIGEST:-}" ] || fail "KFADAPTER_IMAGE_DIGEST is required"

[ "$(id -u)" -eq 0 ] || fail "run as root to preserve numeric state ownership during upgrade and rollback"
state_dir=$(sh "$SCRIPT_DIR/state-volume-path.sh") || fail "could not resolve Docker state volume"
"$SCRIPT_DIR/preflight.sh" --state-dir "$state_dir"
state_identity=$(python3 "$SCRIPT_DIR/verify-state-path.py" \
    --state-dir "$state_dir" \
    --base "$PROJECT_ROOT" \
    --uid "${KFADAPTER_HOST_UID:-65532}" \
    --gid "${KFADAPTER_HOST_GID:-65532}")
state_dir=$(python3 "$SCRIPT_DIR/verify-state-path.py" \
    --state-dir "$state_dir" \
    --base "$PROJECT_ROOT" \
    --uid "${KFADAPTER_HOST_UID:-65532}" \
    --gid "${KFADAPTER_HOST_GID:-65532}" \
    --expect-identity "$state_identity" \
    --print-canonical-path)
[ -n "$BACKUP_DIR" ] || fail "BACKUP_DIR must not be empty"
case "$BACKUP_DIR" in
    /*) backup_archive_dir=$BACKUP_DIR ;;
    *) backup_archive_dir=$PROJECT_ROOT/$BACKUP_DIR ;;
esac
backup_nonce=$(python3 -c 'import secrets; print(secrets.token_hex(16))') || fail "could not generate a unique pre-upgrade archive name"
pre_upgrade_archive="$backup_archive_dir/pre-upgrade-$backup_nonce.tar.gz"
old_container=$(compose ps -q kfadapter) || fail "could not identify the running service"
[ -n "$old_container" ] || fail "kfadapter is not running"
old_image=$(docker inspect --format '{{.Config.Image}}' "$old_container") || fail "could not inspect the current service image"
if ! printf '%s\n' "$old_image" | grep -Eq '^([a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+)@sha256:[0-9a-f]{64}$'; then
    fail "current service image must use an untagged repository@sha256:<64-lowercase-hex> reference"
fi
old_repository=${old_image%@*}
old_digest=${old_image#*@}
old_status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$old_container") || fail "could not inspect current service health"
[ "$old_status" = healthy ] || fail "current service must be healthy before upgrade"
if ! verify_state_mount "$old_container"; then
    fail "$state_mount_failure"
fi

upgrade_in_progress=1
if ! compose stop kfadapter; then
    fail "could not stop the current service"
fi
if ! BACKUP_DIR="$BACKUP_DIR" "$SCRIPT_DIR/backup-state.sh" "$pre_upgrade_archive"; then
    rollback_or_fail "could not create a protected pre-upgrade state backup"
fi
state_backup_ready=1
if ! compose pull kfadapter; then
    rollback_or_fail "could not pull the requested immutable image"
fi
if ! compose up -d --no-deps --force-recreate kfadapter; then
    rollback_or_fail "could not recreate the requested service"
fi
replacement_container=$(compose ps -q kfadapter 2>/dev/null || true)
[ -n "$replacement_container" ] || rollback_or_fail "replacement container was not created"
if ! verify_state_mount "$replacement_container"; then
    rollback_or_fail "$state_mount_failure"
fi
if ! wait_for_healthy; then
    rollback_or_fail "$health_failure"
fi
upgrade_in_progress=0
printf '%s\n' "upgrade: replacement is healthy"
