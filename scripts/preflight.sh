#!/usr/bin/env sh
# Validate the supported native-Linux deployment boundary and any existing state mount.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
state_dir=
manual_state_dir=${KFADAPTER_STATE_DIR:-${STATE_DIR:-}}
STATE_UID=${KFADAPTER_HOST_UID:-65532}
STATE_GID=${KFADAPTER_HOST_GID:-65532}
IMAGE_REPOSITORY=${KFADAPTER_IMAGE_REPOSITORY:-}
IMAGE_DIGEST=${KFADAPTER_IMAGE_DIGEST:-}
LOCAL_BUILD=0
STATE_ONLY=0

fail() {
    printf '%s\n' "preflight: $*" >&2
    exit 1
}

if [ -n "${KFADAPTER_STATE_DIR:-}" ] && [ -n "${STATE_DIR:-}" ] && [ "$KFADAPTER_STATE_DIR" != "$STATE_DIR" ]; then
    fail "KFADAPTER_STATE_DIR and STATE_DIR must match when both are set"
fi

usage() {
    cat >&2 <<'USAGE'
usage: scripts/preflight.sh [--local-build] [--state-only] [--state-dir DIR] [--image-repository REPOSITORY] [--image-digest DIGEST]

Production mode requires an immutable KFADAPTER_IMAGE_DIGEST=sha256:<64-hex>
and the Compose-managed protected Docker state volume. The repository defaults
to ghcr.io/oshinop/kfadapter; set KFADAPTER_IMAGE_REPOSITORY to an untagged
repository only for migration or exact rollback. After preflight passes, run
docker compose --env-file /dev/null -f compose.yaml up -d so project .env
cannot change the validated image inputs. --local-build validates the
isolated developer Compose file and its Docker-managed state volume. For
rootless Docker or userns-remap production, set KFADAPTER_HOST_UID and
KFADAPTER_HOST_GID to the mapped state owner. For manual or test state-only
validation, set KFADAPTER_STATE_DIR (or STATE_DIR) to an explicit state directory.
USAGE
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --local-build)
            LOCAL_BUILD=1
            ;;
        --state-only)
            STATE_ONLY=1
            ;;
        --state-dir)
            [ "$#" -ge 2 ] || usage
            state_dir=$2
            shift
            ;;
        --image-repository)
            [ "$#" -ge 2 ] || usage
            IMAGE_REPOSITORY=$2
            shift
            ;;
        --image-digest)
            [ "$#" -ge 2 ] || usage
            IMAGE_DIGEST=$2
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            usage
            ;;
    esac
    shift
done

if [ -n "$state_dir" ] && [ -n "$manual_state_dir" ] && [ "$state_dir" != "$manual_state_dir" ]; then
    fail "--state-dir must match KFADAPTER_STATE_DIR or STATE_DIR when both are set"
fi
if [ -z "$state_dir" ] && [ -n "$manual_state_dir" ]; then
    state_dir=$manual_state_dir
fi
if [ "$STATE_ONLY" -ne 1 ] && [ -n "$manual_state_dir" ]; then
    fail "KFADAPTER_STATE_DIR and STATE_DIR are supported only with --state-only"
fi

resolve_state_dir() {
    if [ -z "$state_dir" ]; then
        state_dir=$(sh "$SCRIPT_DIR/state-volume-path.sh") || fail "could not resolve Docker state volume"
    fi
}

resolve_production_state_dir() {
    if volume_state_dir=$(sh "$SCRIPT_DIR/state-volume-path.sh" --if-present); then
        if [ -n "$state_dir" ] && [ "$state_dir" != "$volume_state_dir" ]; then
            fail "production state directory must be the Compose-managed Docker volume mountpoint"
        fi
        state_dir=$volume_state_dir
        return 0
    else
        state_resolution_status=$?
    fi
    [ "$state_resolution_status" -eq 3 ] || fail "could not resolve Docker state volume"
    [ -z "$state_dir" ] || fail "production state directory must be the Compose-managed Docker volume mountpoint"
    return 1
}

validate_state() {
    resolve_state_dir
    command -v python3 >/dev/null 2>&1 || fail "python3 is required for no-follow state validation"
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
        --print-canonical-path)
}


validate_image() {
    if [ -n "$IMAGE_REPOSITORY" ] && ! printf '%s\n' "$IMAGE_REPOSITORY" | grep -Eq '^([a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+)$'; then
        fail "KFADAPTER_IMAGE_REPOSITORY must be an untagged registry repository"
    fi
    [ -n "$IMAGE_DIGEST" ] || fail "KFADAPTER_IMAGE_DIGEST is required in production mode"
    if ! printf '%s\n' "$IMAGE_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
        fail "KFADAPTER_IMAGE_DIGEST must be sha256:<64-lowercase-hex>"
    fi
}

validate_native_docker() {
    [ "$(uname -s)" = Linux ] || fail "native Linux is required; Docker Desktop is unsupported"
    command -v docker >/dev/null 2>&1 || fail "Docker Engine is required"

    server_os=$(docker version --format '{{.Server.Os}}' 2>/dev/null || true)
    [ "$server_os" = linux ] || fail "Docker server must be Linux"
    operating_system=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)
    case "$operating_system" in
        *[Dd]ocker\ [Dd]esktop*|*DockerDesktop*|*desktop*)
            fail "Docker Desktop is unsupported; use native Linux Docker Engine"
            ;;
    esac
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 plugin is required"
}


if [ "$STATE_ONLY" -eq 1 ]; then
    validate_state
    exit 0
fi

validate_native_docker
if [ "$LOCAL_BUILD" -eq 1 ]; then
    docker compose --env-file /dev/null -f "$PROJECT_ROOT/deploy/compose.local-build.yaml" config --quiet
else
    if resolve_production_state_dir; then
        validate_state
    fi
    validate_image
    export KFADAPTER_IMAGE_REPOSITORY=$IMAGE_REPOSITORY
    export KFADAPTER_IMAGE_DIGEST=$IMAGE_DIGEST
    docker compose --env-file /dev/null -f "$PROJECT_ROOT/compose.yaml" config --quiet

fi
printf '%s\n' "preflight: passed"
