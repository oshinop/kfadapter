#!/usr/bin/env sh
# Restore an offline state archive atomically, retaining the previous state dir.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
STATE_VOLUME=kfadapter_db_data
STATE_UID=${KFADAPTER_HOST_UID:-65532}
STATE_GID=${KFADAPTER_HOST_GID:-65532}
MAX_ARCHIVE_BYTES=${KFADAPTER_RESTORE_MAX_ARCHIVE_BYTES:-67108864}
MAX_UNCOMPRESSED_BYTES=${KFADAPTER_RESTORE_MAX_UNCOMPRESSED_BYTES:-268435456}

fail() {
    printf '%s\n' "restore-state: $*" >&2
    exit 1
}

compose() {
    docker compose --env-file /dev/null -f "$PROJECT_ROOT/compose.yaml" "$@"
}

validate_restored_state() {
    image=$(compose config --images kfadapter) || fail "could not resolve the production validation image"
    image_count=$(printf '%s\n' "$image" | wc -l | tr -d ' ')
    [ "$image_count" = 1 ] && [ -n "$image" ] || fail "production validation image is ambiguous or unavailable"
    docker image inspect "$image" >/dev/null 2>&1 || fail "cached immutable production validation image is unavailable"
    docker run --rm --pull never --network none --read-only \
        --user "65532:65532" \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --pids-limit 64 \
        --memory 128m \
        --entrypoint /kfadapter/kfadapter \
        -v "$stage:/restore:ro" \
        "$image" validate-state --file /restore/state.db >/dev/null 2>&1 || \
        fail "restored SQLite state validation failed"
}

if [ "$#" -ne 1 ]; then
    printf '%s\n' "usage: KFADAPTER_RESTORE_MAX_ARCHIVE_BYTES=67108864 KFADAPTER_RESTORE_MAX_UNCOMPRESSED_BYTES=268435456 scripts/restore-state.sh archive.tar.gz" >&2
    exit 2
fi
[ "$(id -u)" -eq 0 ] || fail "run as root to preserve numeric state ownership"
ARCHIVE=$1
[ ! -L "$ARCHIVE" ] || fail "archive must not be a symlink"
[ -f "$ARCHIVE" ] || fail "archive does not exist or is not a regular file"
state_dir=$(sh "$SCRIPT_DIR/state-volume-path.sh") || fail "could not resolve Docker state volume"
command -v python3 >/dev/null 2>&1 || fail "python3 is required to validate and extract a bounded state archive"
state_identity=$(python3 "$SCRIPT_DIR/verify-state-path.py" \
    --state-dir "$state_dir" \
    --base "$PROJECT_ROOT" \
    --uid "$STATE_UID" \
    --gid "$STATE_GID")
state_dir=$(python3 "$SCRIPT_DIR/verify-state-path.py" \
    --state-dir "$state_dir" \
    --base "$PROJECT_ROOT" \
    --uid "$STATE_UID" \
    --gid "$STATE_GID" \
    --expect-identity "$state_identity" \
    --print-canonical-path) || fail "could not canonicalize the verified state directory"
"$SCRIPT_DIR/preflight.sh" --state-dir "$state_dir"
running_services=$(docker ps --filter "volume=$STATE_VOLUME" -q) ||
    fail "could not determine whether the Docker state volume is in use"
[ -z "$running_services" ] || fail "Docker state volume is in use; stop every container mounting it before restoring state"

parent=$(dirname -- "$state_dir")
[ -d "$parent" ] && [ ! -L "$parent" ] || fail "state parent must be a regular directory"
state_name=${state_dir##*/}
stage=$(mktemp -d "$parent/.kfadapter-restore.XXXXXXXX")
stage_name=${stage##*/}
cleanup() {
    [ -z "${stage:-}" ] || rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM

python3 "$SCRIPT_DIR/restore-state-archive.py" \
    --archive "$ARCHIVE" \
    --destination "$stage" \
    --max-archive-bytes "$MAX_ARCHIVE_BYTES" \
    --max-uncompressed-bytes "$MAX_UNCOMPRESSED_BYTES"
payload_name=$(python3 "$SCRIPT_DIR/restore-state-commit.py" \
    --parent "$parent" \
    --stage-name "$stage_name" \
    --prepare-stage \
    --uid "$STATE_UID" \
    --gid "$STATE_GID") || fail "could not securely prepare restored state"
[ "$payload_name" = state.db ] || fail "restore preparation returned an unsupported state payload"
"$SCRIPT_DIR/preflight.sh" --state-only --state-dir "$stage"
validate_restored_state

stage_path=$stage
stage=
if ! previous_name=$(python3 "$SCRIPT_DIR/restore-state-commit.py" \
    --parent "$parent" \
    --state-name "$state_name" \
    --stage-name "$stage_name" \
    --state-identity "$state_identity"); then
    fail "could not commit restored state; prepared staged data was retained at $stage_path"
fi
printf '%s\n' "restore-state: restored state; retained the previous directory for rollback"
