#!/usr/bin/env sh
# Prove SQLite backups archive only the payload and never follow attacker-controlled paths.
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

fail() {
    printf '%s\n' "backup-state-test: $*" >&2
    exit 1
}

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
work=$(mktemp -d "$tmp_root/kfadapter-backup-state.XXXXXXXX")
work=$(CDPATH= cd -- "$work" && pwd -P)
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

actual_uid=$(id -u)
actual_gid=$(id -g)
mkdir -p "$work/bin" "$work/scripts" "$work/state"
cp "$PROJECT_ROOT/scripts/backup-state.sh" "$PROJECT_ROOT/scripts/backup-state-write.py" "$PROJECT_ROOT/scripts/docker-local-context.sh" "$PROJECT_ROOT/scripts/state-volume-path.sh" "$PROJECT_ROOT/scripts/verify-state-path.py" "$work/scripts/"
cat >"$work/scripts/preflight.sh" <<'SH'
#!/usr/bin/env sh
exit 0
SH
cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env sh
case "${1:-}" in
    context)
        [ "${2:-}" = inspect ] && [ "${3:-}" = --format ] && [ "${4:-}" = '{{.Endpoints.docker.Host}}' ] || exit 2
        printf '%s\n' "${FAKE_DOCKER_CONTEXT_HOST:-unix:///var/run/docker.sock}"
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
    ps)
        [ "${2:-}" = --filter ] && [ "${3:-}" = volume=kfadapter_db_data ] && [ "${4:-}" = -q ] || exit 2
        [ "${FAKE_DOCKER_PS_FAIL:-}" != 1 ] || exit 1
        [ "${FAKE_DOCKER_RUNNING:-}" != 1 ] || printf '%s\n' running-container
        ;;
    *) exit 2 ;;
esac
SH
chmod 0755 "$work/scripts/preflight.sh" "$work/scripts/backup-state.sh" "$work/scripts/backup-state-write.py" "$work/scripts/docker-local-context.sh" "$work/scripts/state-volume-path.sh" "$work/scripts/verify-state-path.py" "$work/bin/docker"
python3 - "$work/state/state.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("CREATE TABLE fixture (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
connection.execute("INSERT INTO fixture VALUES (?, ?)", ("backup", b"exact SQLite payload\x00"))
connection.commit()
connection.close()
PY
cp "$work/state/state.db" "$work/state.db.expected"

run_backup() {
    backup_dir=$1
    shift
    PATH="$work/bin:$PATH" \
        FAKE_DOCKER_PS_FAIL="${FAKE_DOCKER_PS_FAIL:-}" \
        FAKE_DOCKER_RUNNING="${FAKE_DOCKER_RUNNING:-}" \
        FAKE_DOCKER_CONTEXT_HOST="${FAKE_DOCKER_CONTEXT_HOST:-}" \
        FAKE_STATE_MOUNTPOINT="${FAKE_STATE_MOUNTPOINT:-$work/state}" \
        BACKUP_DIR="$backup_dir" \
        KFADAPTER_HOST_UID="$actual_uid" \
        KFADAPTER_HOST_GID="$actual_gid" \
        "$work/scripts/backup-state.sh" "$@"
}

assert_archive_payload() {
    archive=$1
    if ! python3 - "$archive" "$work/state.db.expected" <<'PY'
from pathlib import Path
import sys
import tarfile

archive_path, expected_path = map(Path, sys.argv[1:])
expected = expected_path.read_bytes()
if archive_path.stat().st_mode & 0o777 != 0o600:
    raise SystemExit("backup archive mode is not 0600")
with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    if len(members) != 1:
        raise SystemExit(f"archive has {len(members)} members instead of exactly one")
    member = members[0]
    if member.name != "state.db":
        raise SystemExit(f"archive member is {member.name!r}, not 'state.db'")
    if not member.isreg():
        raise SystemExit("archive state.db member is not regular")
    if member.mode & 0o777 != 0o600:
        raise SystemExit("archive state.db member mode is not 0600")
    payload = archive.extractfile(member)
    if payload is None or payload.read() != expected:
        raise SystemExit("archive state.db payload differs from the source bytes")
PY
    then
        fail "archive did not contain exactly the expected regular state.db payload"
    fi
}

assert_rejected_backup() {
    name=$1
    archive="$work/rejected/$name.tar.gz"
    if run_backup "$work/rejected" "$archive" >/dev/null 2>&1; then
        fail "backup accepted forbidden state entry $name"
    fi
    [ ! -e "$archive" ] || fail "rejected backup for $name created an archive"
    cmp -s "$work/state.db.expected" "$work/state/state.db" || fail "rejected backup for $name changed state.db"
}

run_backup "$work/nested/backups"
run_backup "$work/nested/backups"
set -- "$work/nested/backups"/state-*.tar.gz
[ "$#" -eq 2 ] || fail "default backups did not receive unique archive suffixes"
[ "$1" != "$2" ] || fail "backup archive suffix collided"
assert_archive_payload "$1"
assert_archive_payload "$2"

explicit="$work/explicit/archive.tar.gz"
run_backup "$work/nested/backups" "$explicit"
[ -f "$explicit" ] || fail "normal explicit archive path was not created"
assert_archive_payload "$explicit"
ps_failure_archive="$work/ps-failure/archive.tar.gz"
python3 - "$work/state/state.db" >"$work/ps-failure-state-before" <<'PY'
from pathlib import Path
import stat
import sys

metadata = Path(sys.argv[1]).lstat()
print(stat.S_IFMT(metadata.st_mode), stat.S_IMODE(metadata.st_mode), metadata.st_nlink, metadata.st_uid, metadata.st_gid, metadata.st_size, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns)
PY
if FAKE_DOCKER_PS_FAIL=1 run_backup "$work/ps-failure" "$ps_failure_archive" >"$work/ps-failure-output" 2>&1; then
    fail "backup continued after Docker ps failure"
fi
FAKE_DOCKER_PS_FAIL=
grep -Fq 'could not determine whether the Docker state volume is in use' "$work/ps-failure-output" || fail "backup did not report Docker ps failure"
[ ! -e "$ps_failure_archive" ] || fail "Docker ps failure created an archive"
cmp -s "$work/state.db.expected" "$work/state/state.db" || fail "Docker ps failure changed state.db bytes"
python3 - "$work/state/state.db" >"$work/ps-failure-state-after" <<'PY'
from pathlib import Path
import stat
import sys

metadata = Path(sys.argv[1]).lstat()
print(stat.S_IFMT(metadata.st_mode), stat.S_IMODE(metadata.st_mode), metadata.st_nlink, metadata.st_uid, metadata.st_gid, metadata.st_size, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns)
PY
cmp -s "$work/ps-failure-state-before" "$work/ps-failure-state-after" || fail "Docker ps failure changed state.db metadata"
unset FAKE_DOCKER_PS_FAIL
if FAKE_DOCKER_CONTEXT_HOST=ssh://remote.example/run/docker.sock run_backup "$work/remote-context" "$work/remote-context/archive.tar.gz" >"$work/remote-context-output" 2>&1; then
    fail "backup accepted a remote Docker context"
fi
grep -Fq 'active Docker context must use a local unix-socket endpoint' "$work/remote-context-output" || fail "backup did not report the remote Docker context"
[ ! -e "$work/remote-context/archive.tar.gz" ] || fail "remote Docker context created a backup archive"
unset FAKE_DOCKER_CONTEXT_HOST
running_archive="$work/running/archive.tar.gz"
if FAKE_DOCKER_RUNNING=1 run_backup "$work/running" "$running_archive" >"$work/running-output" 2>&1; then
    fail "backup accepted a Docker state volume mounted by a running container"
fi
unset FAKE_DOCKER_RUNNING
grep -Fq 'Docker state volume is in use' "$work/running-output" || fail "backup did not report the mounted state volume"
[ ! -e "$running_archive" ] || fail "mounted state volume created an archive"
cmp -s "$work/state.db.expected" "$work/state/state.db" || fail "mounted-state rejection changed state.db bytes"

mkdir "$work/rejected"
mv "$work/state/state.db" "$work/state.db.saved"
ln -s "$work/state.db.expected" "$work/state/state.db"
assert_rejected_backup state-db-symlink
rm -- "$work/state/state.db"
mv "$work/state.db.saved" "$work/state/state.db"

mv "$work/state/state.db" "$work/state.db.saved"
printf '%s\n' 'not a SQLite database' >"$work/state/state.db"
chmod 0600 "$work/state/state.db"
corrupt_archive="$work/rejected/corrupt-state-db.tar.gz"
if run_backup "$work/rejected" "$corrupt_archive" >/dev/null 2>&1; then
    fail "backup accepted a corrupt state.db"
fi
[ ! -e "$corrupt_archive" ] || fail "corrupt state.db backup created an archive"
rm -- "$work/state/state.db"
mv "$work/state.db.saved" "$work/state/state.db"

printf '%s\n' transient >"$work/state/state.db-wal"
assert_rejected_backup state-db-wal
rm -- "$work/state/state.db-wal"

printf '%s\n' unrelated >"$work/state/unrelated"
assert_rejected_backup unrelated-regular
rm -- "$work/state/unrelated"

printf '%s\n' symlink-target >"$work/symlink-target"
ln -s "$work/symlink-target" "$work/state/unrelated-link"
assert_rejected_backup unrelated-symlink
rm -- "$work/state/unrelated-link"

mkfifo "$work/state/unrelated-fifo"
assert_rejected_backup unrelated-fifo
rm -- "$work/state/unrelated-fifo"
if run_backup "$work/nested/backups" "$work/state/../state/forbidden.tar.gz" >/dev/null 2>&1; then
    fail "backup archive inside state passed canonical path checks"
fi
[ ! -e "$work/state/forbidden.tar.gz" ] || fail "rejected state-local archive was created"

mkdir "$work/backup-target" "$work/state-target"
printf '%s\n' sentinel >"$work/backup-target/sentinel"
printf '%s\n' state-sentinel >"$work/state-target/sentinel"
chmod 0754 "$work/backup-target" "$work/state-target"
python3 - "$work/backup-target" "$work/state-target" >"$work/targets-before" <<'PY'
from pathlib import Path
import stat
import sys
for value in sys.argv[1:]:
    metadata = Path(value).stat()
    print(value, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
PY
ln -s "$work/backup-target" "$work/backup-parent-link"
if run_backup "$work/backup-parent-link/nested" >/dev/null 2>&1; then
    fail "symlinked default backup parent passed"
fi
ln -s "$work/backup-target" "$work/explicit-parent-link"
if run_backup "$work/nested/backups" "$work/explicit-parent-link/archive.tar.gz" >/dev/null 2>&1; then
    fail "symlinked explicit backup parent passed"
fi
python3 - "$work/backup-target" "$work/state-target" >"$work/targets-after" <<'PY'
from pathlib import Path
import stat
import sys
for value in sys.argv[1:]:
    metadata = Path(value).stat()
    print(value, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
PY
cmp -s "$work/targets-before" "$work/targets-after" || fail "symlink target ownership or mode changed"
[ "$(cat "$work/backup-target/sentinel")" = sentinel ] || fail "backup output path changed symlink target contents"
[ "$(cat "$work/state-target/sentinel")" = state-sentinel ] || fail "backup state path changed symlink target contents"
[ ! -e "$work/backup-target/nested" ] || fail "symlinked default parent received output"
[ ! -e "$work/backup-target/archive.tar.gz" ] || fail "symlinked explicit parent received output"
printf '%s\n' "backup-state-test: passed"
