#!/usr/bin/env sh
# Resolve the host mountpoint for the Compose-managed production state volume.
set -eu
LC_ALL=C
export LC_ALL
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

fail() {
    printf '%s\n' "state-volume-path: $*" >&2
    exit 1
}

usage() {
    printf '%s\n' "usage: scripts/state-volume-path.sh [--if-present]" >&2
    exit 2
}

allow_absent=0
case "$#" in
    0)
        ;;
    1)
        [ "$1" = "--if-present" ] || usage
        allow_absent=1
        ;;
    *)
        usage
        ;;
esac

volume=kfadapter_db_data

sh "$SCRIPT_DIR/docker-local-context.sh" || exit 1
if [ "$allow_absent" -eq 1 ]; then
    available_volumes=$(docker volume ls --format '{{.Name}}') ||
        fail "could not list Docker volumes"
    if ! printf '%s\n' "$available_volumes" | grep -Fx -- "$volume" >/dev/null; then
        exit 3
    fi
fi
if ! docker volume inspect --format '{{.Name}}' "$volume" >/dev/null 2>&1; then
    fail "could not inspect Compose-managed Docker volume '$volume'"
fi

inspect_field() {
    template=$1
    field=$2
    value=$(docker volume inspect --format "$template" "$volume") ||
        fail "could not inspect Docker volume '$volume'"
    case "$value" in
        ''|*'
'*)
            fail "Docker volume '$volume' returned an empty or ambiguous $field"
            ;;
    esac
    printf '%s\n' "$value"
}

inspected_name=$(inspect_field '{{.Name}}' name)
driver=$(inspect_field '{{.Driver}}' driver)
mountpoint=$(inspect_field '{{.Mountpoint}}' Mountpoint)
options=$(inspect_field '{{json .Options}}' options)

[ "$inspected_name" = "$volume" ] ||
    fail "Docker volume '$volume' inspection returned a different volume name"
[ "$driver" = local ] ||
    fail "Docker volume '$volume' must use the local driver"
case "$options" in
    null|'{}')
        ;;
    *)
        fail "Docker volume '$volume' must not use local-driver mount options"
        ;;
esac
case "$mountpoint" in
    /*)
        ;;
    *)
        fail "Docker volume '$volume' Mountpoint must be an absolute path"
        ;;
esac
case "$mountpoint" in
    *'/./'*|*'/../'*|*/.|*/..|*'//'*)
        fail "Docker volume '$volume' Mountpoint must be a canonical path"
        ;;
esac
[ "$mountpoint" != / ] || fail "Docker volume '$volume' Mountpoint must not be the filesystem root"
[ -d "$mountpoint" ] || fail "Docker volume '$volume' Mountpoint is not a directory"
[ ! -L "$mountpoint" ] || fail "Docker volume '$volume' Mountpoint must not be a symlink"

printf '%s\n' "$mountpoint"
