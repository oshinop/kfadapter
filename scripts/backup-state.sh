#!/usr/bin/env sh
# Create an offline, owner-preserving state archive without following output paths.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
STATE_VOLUME=kfadapter_db_data
BACKUP_DIR=${BACKUP_DIR:-"$PROJECT_ROOT/backups"}

fail() {
    printf '%s\n' "backup-state: $*" >&2
    exit 1
}

if [ "$#" -gt 1 ]; then
    printf '%s\n' "usage: scripts/backup-state.sh [archive.tar.gz]" >&2
    exit 2
fi
state_dir=$(sh "$SCRIPT_DIR/state-volume-path.sh") || fail "could not resolve Docker state volume"
[ -n "$BACKUP_DIR" ] || fail "BACKUP_DIR must not be empty"
ARCHIVE=${1:-}

command -v python3 >/dev/null 2>&1 || fail "python3 is required for no-follow state backup"
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
"$SCRIPT_DIR/preflight.sh" --state-only --state-dir "$state_dir"
running_services=$(docker ps --filter "volume=$STATE_VOLUME" -q) ||
    fail "could not determine whether the Docker state volume is in use"
[ -z "$running_services" ] || fail "Docker state volume is in use; stop every container mounting it before creating a state backup"

if [ -n "$ARCHIVE" ]; then
    python3 "$SCRIPT_DIR/backup-state-write.py" \
        --project-root "$PROJECT_ROOT" \
        --state-dir "$state_dir" \
        --state-identity "$state_identity" \
        --backup-dir "$BACKUP_DIR" \
        --archive "$ARCHIVE" >/dev/null
else
    python3 "$SCRIPT_DIR/backup-state-write.py" \
        --project-root "$PROJECT_ROOT" \
        --state-dir "$state_dir" \
        --state-identity "$state_identity" \
        --backup-dir "$BACKUP_DIR" >/dev/null
fi
printf '%s\n' "backup-state: created protected state archive"
