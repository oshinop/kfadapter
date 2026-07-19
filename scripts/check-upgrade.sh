#!/usr/bin/env sh
# Exercise immutable rollback with exact SQLite archive recovery.
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OLD_REPOSITORY=registry.invalid/kfadapter-old
NEW_REPOSITORY=ghcr.io/oshinop/kfadapter
EXPLICIT_REPOSITORY=registry.invalid/kfadapter-explicit
OLD_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
NEW_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222
OLD_IMAGE=$OLD_REPOSITORY@$OLD_DIGEST
NEW_IMAGE=$NEW_REPOSITORY@$NEW_DIGEST
EXPLICIT_IMAGE=$EXPLICIT_REPOSITORY@$NEW_DIGEST

fail() {
    printf '%s\n' "upgrade-test: $*" >&2
    exit 1
}

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
work=$(mktemp -d "$tmp_root/kfadapter-upgrade.XXXXXXXX")
work=$(CDPATH= cd -- "$work" && pwd -P)
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

actual_uid=$(id -u)
actual_gid=$(id -g)
state_dir="$work/alternate-state"
mkdir -p "$work/bin" "$work/scripts" "$state_dir"
python3 - "$state_dir/state.db" <<'PY'
from pathlib import Path
import sqlite3
import sys

database = Path(sys.argv[1])
connection = sqlite3.connect(database)
connection.execute("PRAGMA journal_mode=DELETE")
connection.execute("CREATE TABLE deployment_verification (marker TEXT NOT NULL)")
connection.execute("INSERT INTO deployment_verification(marker) VALUES ('pre-upgrade')")
connection.commit()
connection.execute("VACUUM")
connection.close()
database.chmod(0o600)
PY
cp "$state_dir/state.db" "$work/baseline-state.db"
cp "$PROJECT_ROOT/scripts/docker-local-context.sh" "$PROJECT_ROOT/scripts/upgrade.sh" "$PROJECT_ROOT/scripts/verify-state-path.py" "$PROJECT_ROOT/scripts/state-volume-path.sh" "$work/scripts/"
cat >"$work/scripts/preflight.sh" <<'SH'
#!/usr/bin/env sh
printf '%s\n' "preflight $*" >>"$FAKE_LOG"
exit 0
SH
cat >"$work/scripts/backup-state.sh" <<'SH'
#!/usr/bin/env sh
set -eu
[ "$#" -eq 1 ] || exit 2
archive=$1
printf '%s\n' "backup archive=$archive state=$FAKE_STATE_MOUNTPOINT" >>"$FAKE_LOG"
python3 - "$FAKE_STATE_MOUNTPOINT/state.db" <<'PY'
from pathlib import Path
import sqlite3
import sys

source = Path(sys.argv[1])
connection = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
assert connection.execute("SELECT marker FROM deployment_verification").fetchall() == [("pre-upgrade",)]
connection.close()
PY
printf '%s\n' "validate-state backup=$FAKE_STATE_MOUNTPOINT/state.db" >>"$FAKE_LOG"
[ "${FAIL_PHASE:-}" != backup ] || exit 1
python3 - "$FAKE_STATE_MOUNTPOINT/state.db" "$archive" <<'PY'
from io import BytesIO
from pathlib import Path
import sys
from tarfile import TarInfo, open as taropen

source = Path(sys.argv[1])
archive = Path(sys.argv[2])
payload = source.read_bytes()
archive.parent.mkdir(parents=True, exist_ok=True)
with taropen(archive, "x:gz") as bundle:
    member = TarInfo("state.db")
    member.mode = 0o600
    member.size = len(payload)
    bundle.addfile(member, BytesIO(payload))
PY
SH
cat >"$work/scripts/restore-state.sh" <<'SH'
#!/usr/bin/env sh
set -eu
[ "$#" -eq 1 ] || exit 2
state_dir=${FAKE_STATE_MOUNTPOINT:?}
archive=$1
printf '%s\n' "restore archive=$archive state=$state_dir repository=$KFADAPTER_IMAGE_REPOSITORY digest=$KFADAPTER_IMAGE_DIGEST" >>"$FAKE_LOG"
[ "$(cat "$FAKE_RUNTIME_STATE")" = stopped ] || exit 1
[ "$KFADAPTER_IMAGE_REPOSITORY" = "$OLD_REPOSITORY" ] || exit 1
[ "$KFADAPTER_IMAGE_DIGEST" = "$OLD_DIGEST" ] || exit 1
[ "${FAIL_ROLLBACK:-}" != restore ] || exit 1
python3 - "$archive" "$state_dir/state.db" <<'PY'
from pathlib import Path
import sqlite3
import stat
import sys
from tarfile import open as taropen

archive = Path(sys.argv[1])
destination = Path(sys.argv[2])
with taropen(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    assert len(members) == 1
    member = members[0]
    assert member.name == "state.db" and member.isreg() and stat.S_IMODE(member.mode) == 0o600
    source = bundle.extractfile(member)
    assert source is not None
    payload = source.read()
destination.write_bytes(payload)
destination.chmod(0o600)
connection = sqlite3.connect(f"{destination.as_uri()}?mode=ro", uri=True)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
assert connection.execute("SELECT marker FROM deployment_verification").fetchall() == [("pre-upgrade",)]
connection.close()
PY
replacement_state_dir="${state_dir}.restore-fixture"
previous_state_dir="${state_dir}.previous-fixture"
rm -rf -- "$replacement_state_dir" "$previous_state_dir"
mkdir "$replacement_state_dir"
chmod 0700 "$replacement_state_dir"
mv "$state_dir/state.db" "$replacement_state_dir/state.db"
mv "$state_dir" "$previous_state_dir"
mv "$replacement_state_dir" "$state_dir"
rm -rf -- "$previous_state_dir"
printf '%s\n' "validate-state restore=$state_dir/state.db archive=$archive" >>"$FAKE_LOG"
SH
cat >"$work/bin/id" <<'SH'
#!/usr/bin/env sh
set -eu
case "${1:-}" in
    -u) printf '%s\n' "${FAKE_ID_UID:-0}" ;;
    *) exit 2 ;;
esac
SH
cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env sh
set -eu

state=$(cat "$FAKE_RUNTIME_STATE")
log() {
    printf '%s\n' "$*" >>"$FAKE_LOG"
}
case "${1:-}" in
    context)
        [ "${2:-}" = inspect ] && [ "${3:-}" = --format ] && [ "${4:-}" = '{{.Endpoints.docker.Host}}' ] || exit 2
        printf '%s\n' unix:///var/run/docker.sock
        ;;
    volume)
        [ "${2:-}" = inspect ] && [ "${3:-}" = --format ] && [ "${5:-}" = kfadapter_db_data ] || exit 2
        case "${4:-}" in
            '{{.Name}}') printf '%s\n' kfadapter_db_data ;;
            '{{.Driver}}') printf '%s\n' local ;;
            '{{.Mountpoint}}') printf '%s\n' "${FAKE_STATE_MOUNTPOINT:?}" ;;
            '{{json .Options}}') printf '%s\n' null ;;
            *) exit 2 ;;
        esac
        ;;
    compose)
        shift
        [ "${1:-}" = --env-file ] && [ "${2:-}" = /dev/null ] || exit 2
        shift 2
        compose_file_count=0
        while [ "${1:-}" = -f ]; do
            compose_file_count=$((compose_file_count + 1))
            shift 2
        done
        [ "$compose_file_count" -eq 1 ] || exit 2
        action=${1:-}
        shift || true
        case "$action" in
            ps)
                log "ps"
                case "$state" in
                    old-running) printf '%s\n' old-container ;;
                    new-running) printf '%s\n' new-container ;;
                esac
                ;;
            stop)
                log "stop"
                printf '%s\n' stopped >"$FAKE_RUNTIME_STATE"
                ;;
            pull)
                image=${KFADAPTER_IMAGE_REPOSITORY:-ghcr.io/oshinop/kfadapter}@$KFADAPTER_IMAGE_DIGEST
                log "pull $image"
                if [ "$image" != "$OLD_IMAGE" ] && [ "${FAIL_PHASE:-}" = pull ]; then
                    exit 1
                fi
                if [ "$image" != "$OLD_IMAGE" ] && [ "${FAKE_INTERRUPT_ON:-}" = pull ]; then
                    log "interrupt TERM during pull"
                    kill -TERM "$PPID"
                fi
                ;;
            up)
                image=${KFADAPTER_IMAGE_REPOSITORY:-ghcr.io/oshinop/kfadapter}@$KFADAPTER_IMAGE_DIGEST
                log "up $image"
                if [ "$image" = "$OLD_IMAGE" ]; then
                    : >"$FAKE_ROLLBACK_MARKER"
                    case "${FAIL_ROLLBACK:-}" in
                        up) exit 1 ;;
                        up-partial)
                            printf '%s\n' old-running >"$FAKE_RUNTIME_STATE"
                            exit 1
                            ;;
                    esac
                    printf '%s\n' old-running >"$FAKE_RUNTIME_STATE"
                else
                    python3 - "$FAKE_STATE_MOUNTPOINT/state.db" <<'PY'
from pathlib import Path
import sqlite3
import sys

database = Path(sys.argv[1])
connection = sqlite3.connect(database)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
connection.execute("UPDATE deployment_verification SET marker = 'replacement'")
connection.commit()
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
assert connection.execute("SELECT marker FROM deployment_verification").fetchall() == [("replacement",)]
connection.close()
PY
                    printf '%s\n' "validate-state replacement=$FAKE_STATE_MOUNTPOINT/state.db" >>"$FAKE_LOG"
                    log "replacement mutated SQLite state"
                    [ "${FAIL_PHASE:-}" != up ] || exit 1
                    printf '%s\n' new-running >"$FAKE_RUNTIME_STATE"
                fi
                ;;
            *) exit 2 ;;
        esac
        ;;
    image)
        [ "${2:-}" = inspect ] || exit 2
        image=${3:-}
        log "image inspect $image"
        [ "$image" = "$OLD_IMAGE" ] || exit 1
        [ "${MISSING_OLD_CACHE:-}" != 1 ] || exit 1
        ;;
    inspect)
        [ "${2:-}" = --format ] || exit 2
        format=${3:-}
        container=${4:-}
        case "$format" in
            *Config.Image*)
                case "$container" in
                    old-container) printf '%s\n' "$OLD_IMAGE" ;;
                    new-container) printf '%s\n' "$NEW_IMAGE" ;;
                    *) exit 1 ;;
                esac
                ;;
            *'Destination "/kfadapter/data"'*'{{.Type}}'*) printf '%s\n' volume ;;
            *'Destination "/kfadapter/data"'*'{{.Name}}'*) printf '%s\n' "${FAKE_RUNNING_STATE_VOLUME:-kfadapter_db_data}" ;;
            *'Destination "/kfadapter/data"'*'{{.Source}}'*) printf '%s\n' "${FAKE_RUNNING_STATE_MOUNTPOINT:-$FAKE_STATE_MOUNTPOINT}" ;;
            *State.Health*)
                case "$container:$state" in
                    old-container:old-running)
                        if [ "${FAIL_ROLLBACK:-}" = health ] && [ -e "$FAKE_ROLLBACK_MARKER" ]; then
                            printf '%s\n' unhealthy
                        else
                            printf '%s\n' healthy
                        fi
                        ;;
                    new-container:new-running)
                        if [ "${FAIL_PHASE:-}" = health ]; then
                            printf '%s\n' unhealthy
                        else
                            printf '%s\n' healthy
                        fi
                        ;;
                    *) printf '%s\n' exited ;;
                esac
                ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
SH
chmod 0755 "$work/scripts/docker-local-context.sh" "$work/scripts/upgrade.sh" "$work/scripts/verify-state-path.py" "$work/scripts/state-volume-path.sh" "$work/scripts/preflight.sh" "$work/scripts/backup-state.sh" "$work/scripts/restore-state.sh" "$work/bin/id" "$work/bin/docker"

run_upgrade() {
    image_repository=${1:-}
    rm -f -- "$work/rollback-marker"
    (
        unset KFADAPTER_IMAGE_REPOSITORY
        [ -z "$image_repository" ] || export KFADAPTER_IMAGE_REPOSITORY="$image_repository"
        PATH="$work/bin:$PATH" \
            FAKE_RUNTIME_STATE="$work/runtime-state" \
            FAKE_LOG="$work/log" \
            FAKE_ROLLBACK_MARKER="$work/rollback-marker" \
            FAKE_ID_UID="${FAKE_ID_UID:-0}" \
            OLD_IMAGE="${FAKE_OLD_IMAGE:-$OLD_IMAGE}" \
            NEW_IMAGE="$NEW_IMAGE" \
            OLD_REPOSITORY="$OLD_REPOSITORY" \
            OLD_DIGEST="$OLD_DIGEST" \
            FAIL_PHASE="${FAIL_PHASE:-}" \
            FAIL_ROLLBACK="${FAIL_ROLLBACK:-}" \
            MISSING_OLD_CACHE="${MISSING_OLD_CACHE:-}" \
            FAKE_INTERRUPT_ON="${FAKE_INTERRUPT_ON:-}" \
            FAKE_STATE_MOUNTPOINT="$state_dir" \
            FAKE_RUNNING_STATE_VOLUME="${FAKE_RUNNING_STATE_VOLUME:-}" \
            FAKE_RUNNING_STATE_MOUNTPOINT="${FAKE_RUNNING_STATE_MOUNTPOINT:-}" \
            KFADAPTER_HOST_UID="$actual_uid" \
            KFADAPTER_HOST_GID="$actual_gid" \
            KFADAPTER_IMAGE_DIGEST="$NEW_DIGEST" \
            "$work/scripts/upgrade.sh"
    )
}

assert_named_volume_flow() {
    grep -Fqx "ps" "$work/log" || fail "Compose ps was not invoked"
    grep -Fqx "stop" "$work/log" || fail "Compose stop was not invoked"
    grep -Fq "backup archive=" "$work/log" || fail "backup did not receive an explicit archive path"
    grep -Fq "state=$state_dir" "$work/log" || fail "backup did not use the named-volume mountpoint"
    grep -Fq "validate-state backup=$state_dir/state.db" "$work/log" || fail "upgrade backup did not validate SQLite state"
}

assert_baseline_state() {
    cmp -s "$work/baseline-state.db" "$state_dir/state.db" || fail "rollback did not restore exact SQLite database bytes"
    python3 - "$state_dir/state.db" <<'PY'
from pathlib import Path
import sqlite3
import sys

database = Path(sys.argv[1])
connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
assert connection.execute("SELECT marker FROM deployment_verification").fetchall() == [("pre-upgrade",)]
connection.close()
PY
}

assert_replacement_state() {
    python3 - "$state_dir/state.db" <<'PY'
from pathlib import Path
import sqlite3
import sys

database = Path(sys.argv[1])
connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
assert connection.execute("SELECT marker FROM deployment_verification").fetchall() == [("replacement",)]
connection.close()
PY
}

assert_no_old_pull() {
    if grep -Fq "pull $OLD_IMAGE" "$work/log"; then
        fail "rollback contacted the registry for the old image"
    fi
}

previous_archive=
assert_protected_archive_recovery() {
    backup_line=$(grep -F "backup archive=" "$work/log")
    backup_archive=${backup_line#backup archive=}
    backup_archive=${backup_archive%% state=*}
    case "$backup_archive" in
        "$work"/backups/pre-upgrade-*.tar.gz) ;;
        *) fail "backup archive path was not an explicit collision-resistant pre-upgrade path" ;;
    esac
    [ "$backup_archive" != "$previous_archive" ] || fail "pre-upgrade archive path was reused"
    previous_archive=$backup_archive
    [ -f "$backup_archive" ] || fail "protected pre-upgrade archive was not created"
    python3 - "$backup_archive" "$work/baseline-state.db" <<'PY'
from pathlib import Path
import stat
import sys
from tarfile import open as taropen

archive = Path(sys.argv[1])
expected = Path(sys.argv[2]).read_bytes()
with taropen(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    assert len(members) == 1
    member = members[0]
    assert member.name == "state.db" and member.isreg() and stat.S_IMODE(member.mode) == 0o600
    payload = bundle.extractfile(member)
    assert payload is not None and payload.read() == expected
PY
    grep -Fq "restore archive=$backup_archive state=$state_dir repository=$OLD_REPOSITORY digest=$OLD_DIGEST" "$work/log" || fail "rollback did not restore the exact protected archive under the old image context"
    grep -Fq "validate-state restore=$state_dir/state.db archive=$backup_archive" "$work/log" || fail "rollback did not validate restored SQLite state"
    python3 - "$work/log" "$backup_archive" "$OLD_IMAGE" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text().splitlines()
archive = sys.argv[2]
old_image = sys.argv[3]
restore_index = next(i for i, line in enumerate(lines) if line.startswith(f"restore archive={archive} "))
stop_indexes = [i for i, line in enumerate(lines) if line == "stop"]
old_up_index = next(i for i, line in enumerate(lines) if line == f"up {old_image}")
assert stop_indexes and max(stop_indexes) < restore_index < old_up_index
PY
}

assert_rollback() {
    phase=$1
    cp "$work/baseline-state.db" "$state_dir/state.db"
    printf '%s\n' old-running >"$work/runtime-state"
    : >"$work/log"
    state_inode_before=$(python3 -c 'import os, sys; print(os.stat(sys.argv[1], follow_symlinks=False).st_ino)' "$state_dir")
    if FAIL_PHASE="$phase" run_upgrade >"$work/output" 2>&1; then
        fail "$phase failure did not fail the upgrade"
    fi
    [ "$(cat "$work/runtime-state")" = old-running ] || fail "$phase failure did not restore the old service"
    assert_named_volume_flow
    grep -Fq "image inspect $OLD_IMAGE" "$work/log" || fail "$phase rollback did not verify the exact cached old image"
    assert_no_old_pull
    grep -Fq "up $OLD_IMAGE" "$work/log" || fail "$phase rollback did not recreate the exact cached old image"
    grep -Fq 'prior immutable service was restored and is healthy' "$work/output" || fail "$phase rollback did not prove old service health"
    if [ "$phase" = backup ]; then
        if grep -Fq 'restore archive=' "$work/log"; then
            fail "rollback restored state after backup creation failed"
        fi
        backup_line=$(grep -F "backup archive=" "$work/log")
        backup_archive=${backup_line#backup archive=}
        backup_archive=${backup_archive%% state=*}
        [ ! -e "$backup_archive" ] || fail "failed backup left a protected archive behind"
    else
        assert_protected_archive_recovery
        state_inode_after=$(python3 -c 'import os, sys; print(os.stat(sys.argv[1], follow_symlinks=False).st_ino)' "$state_dir")
        [ "$state_inode_after" != "$state_inode_before" ] || fail "$phase rollback fixture did not exchange the state directory"
    fi
    case "$phase" in
        up|health) grep -Fq 'replacement mutated SQLite state' "$work/log" || fail "$phase replacement did not mutate SQLite state before failure" ;;
    esac
    assert_baseline_state
}


tagged_old_image=registry.invalid/kfadapter-old:legacy@$OLD_DIGEST
cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
if FAKE_OLD_IMAGE="$tagged_old_image" run_upgrade >"$work/output" 2>&1; then
    fail "upgrade accepted a tag-qualified current image that rollback cannot validate"
fi
unset FAKE_OLD_IMAGE
grep -Fq 'current service image must use an untagged repository@sha256:<64-lowercase-hex> reference' "$work/output" ||
    fail "tag-qualified current image rejection was not explained"
[ "$(cat "$work/runtime-state")" = old-running ] || fail "tag-qualified current image rejection changed the running service"
if grep -Eq '^(stop|backup )' "$work/log"; then
    fail "tag-qualified current image rejection reached destructive upgrade work"
fi

for phase in backup pull up health; do
    assert_rollback "$phase"
done

cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
run_upgrade >"$work/output" 2>&1
assert_named_volume_flow
grep -Fq "up $NEW_IMAGE" "$work/log" || fail "new service did not use the requested immutable image"
grep -Fq 'replacement is healthy' "$work/output" || fail "healthy replacement was not reported"
if grep -Fq 'restore archive=' "$work/log"; then
    fail "healthy replacement unexpectedly restored state"
fi
assert_replacement_state

cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
run_upgrade "$EXPLICIT_REPOSITORY" >"$work/output" 2>&1
grep -Fq "up $EXPLICIT_IMAGE" "$work/log" || fail "explicit repository override did not use the requested immutable image"
grep -Fq 'replacement is healthy' "$work/output" || fail "healthy explicit repository override was not reported"
assert_replacement_state
cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
if FAKE_INTERRUPT_ON=pull run_upgrade >"$work/output" 2>&1; then
    fail "interrupted upgrade returned success"
else
    interrupt_status=$?
fi
FAKE_INTERRUPT_ON=
[ "$interrupt_status" -eq 143 ] || fail "interrupted upgrade returned status $interrupt_status instead of 143"
[ "$(cat "$work/runtime-state")" = old-running ] || fail "interrupted upgrade did not restore the old service"
grep -Fq 'interrupted; prior immutable service and protected state were restored' "$work/output" || fail "interrupted upgrade did not report protected rollback"
assert_named_volume_flow
assert_protected_archive_recovery
assert_no_old_pull
if grep -Fq "up $NEW_IMAGE" "$work/log"; then
    fail "interrupted upgrade started the replacement service"
fi
[ "$(grep -Fxc "up $OLD_IMAGE" "$work/log")" = 1 ] || fail "interrupted upgrade recreated the old service more than once"
[ "$(grep -Fc 'restore archive=' "$work/log")" = 1 ] || fail "interrupted upgrade restored state more than once"
assert_baseline_state

cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
if FAIL_PHASE=health FAIL_ROLLBACK=up run_upgrade >"$work/output" 2>&1; then
    fail "rollback recreation failure did not fail the upgrade"
fi
grep -Fq 'replacement did not become healthy' "$work/output" || fail "original failure was hidden by rollback recreation failure"
grep -Fq 'rollback failure: could not recreate the prior immutable service from the local cache' "$work/output" || fail "rollback recreation failure was not reported"
if grep -Fq 'prior immutable service was restored and is healthy' "$work/output"; then
    fail "rollback recreation failure was reported as success"
fi
assert_no_old_pull
assert_baseline_state
[ "$(cat "$work/runtime-state")" = stopped ] || fail "rollback recreation failure left a service running"

for rollback_failure in up-partial health; do
    cp "$work/baseline-state.db" "$state_dir/state.db"
    printf '%s\n' old-running >"$work/runtime-state"
    : >"$work/log"
    if FAIL_PHASE=health FAIL_ROLLBACK="$rollback_failure" run_upgrade >"$work/output" 2>&1; then
        fail "$rollback_failure rollback failure did not fail the upgrade"
    fi
    [ "$(cat "$work/runtime-state")" = stopped ] || fail "$rollback_failure rollback failure left a service running"
    grep -Fq 'rollback failure:' "$work/output" || fail "$rollback_failure rollback failure was not reported"
    assert_no_old_pull
    assert_baseline_state
done

cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
if FAIL_PHASE=health FAIL_ROLLBACK=restore run_upgrade >"$work/output" 2>&1; then
    fail "restore failure did not fail the upgrade"
fi
[ "$(cat "$work/runtime-state")" = stopped ] || fail "restore failure attempted to recreate the old service"
grep -Fq 'replacement did not become healthy' "$work/output" || fail "original failure was hidden by restore failure"
grep -Fq 'rollback failure: could not restore the protected pre-upgrade state archive' "$work/output" || fail "restore failure was not reported"
if grep -Fq 'prior immutable service was restored and is healthy' "$work/output"; then
    fail "restore failure was reported as success"
fi
grep -Fq 'replacement mutated SQLite state' "$work/log" || fail "restore failure scenario did not mutate replacement SQLite state"
assert_replacement_state
assert_no_old_pull

cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
if FAIL_PHASE=health MISSING_OLD_CACHE=1 run_upgrade >"$work/output" 2>&1; then
    fail "missing cached old image did not fail the upgrade"
fi
grep -Fq 'original failure: replacement did not become healthy' "$work/output" || fail "replacement health failure was hidden"
grep -Fq 'rollback failure: cached prior immutable image is unavailable' "$work/output" || fail "missing cached image failure was not reported"
if grep -Fq 'restore archive=' "$work/log"; then
    fail "rollback attempted state restoration without the prior validation image"
fi
assert_no_old_pull
[ "$(cat "$work/runtime-state")" = stopped ] || fail "missing cached image left the unhealthy replacement running"
grep -Fq 'replacement mutated SQLite state' "$work/log" || fail "missing-cache scenario did not start the replacement"
assert_replacement_state
cp "$work/baseline-state.db" "$state_dir/state.db"
printf '%s\n' old-running >"$work/runtime-state"
: >"$work/log"
if FAKE_RUNNING_STATE_VOLUME=other-state-volume run_upgrade >"$work/output" 2>&1; then
    fail "upgrade accepted a running service on a different state volume"
fi
unset FAKE_RUNNING_STATE_VOLUME
grep -Fq 'running service does not use the Compose-managed Docker state volume' "$work/output" || fail "state-volume mismatch was not reported"
[ "$(cat "$work/runtime-state")" = old-running ] || fail "state-volume mismatch changed the running service"
if grep -Eq '^(stop|backup )' "$work/log"; then
    fail "state-volume mismatch reached service stop or backup"
fi
: >"$work/log"
if FAKE_ID_UID=501 run_upgrade >"$work/output" 2>&1; then
    fail "non-root upgrade did not fail"
fi
grep -Fq 'run as root to preserve numeric state ownership' "$work/output" || fail "non-root upgrade did not explain the root requirement"
[ "$(cat "$work/runtime-state")" = old-running ] || fail "non-root upgrade changed the running service"
[ ! -s "$work/log" ] || fail "non-root upgrade reached preflight or Docker"
assert_baseline_state

printf '%s\n' "upgrade-test: passed"
