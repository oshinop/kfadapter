#!/usr/bin/env sh
# Exercise bounded SQLite restore and exact rollback retention without root or Docker.
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
actual_uid=$(id -u)
actual_gid=$(id -g)

fail() {
    printf '%s\n' "restore-state-test: $*" >&2
    exit 1
}

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
work=$(mktemp -d "$tmp_root/kfadapter-restore-state.XXXXXXXX")
work=$(CDPATH= cd -- "$work" && pwd -P)
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/bin" "$work/scripts" "$work/state" "$work/input"
: >"$work/docker.log"
cp "$PROJECT_ROOT/scripts/docker-local-context.sh" "$PROJECT_ROOT/scripts/restore-state.sh" "$PROJECT_ROOT/scripts/restore-state-archive.py" "$PROJECT_ROOT/scripts/restore-state-commit.py" "$PROJECT_ROOT/scripts/state-volume-path.sh" "$PROJECT_ROOT/scripts/verify-state-path.py" "$work/scripts/"
cat >"$work/scripts/preflight.sh" <<'SH'
#!/usr/bin/env sh
set -eu
printf '%s\n' "preflight $*" >>"${FAKE_DOCKER_LOG:?}"
SH
cat >"$work/bin/id" <<'SH'
#!/usr/bin/env sh
[ "${1:-}" = -u ] || exit 2
printf '%s\n' 0
SH
cat >"$work/bin/docker" <<'SH'
#!/usr/bin/env sh
set -eu
log=${FAKE_DOCKER_LOG:?}
case "${1:-}" in
    context)
        [ "${2:-}" = inspect ] && [ "${3:-}" = --format ] && [ "${4:-}" = '{{.Endpoints.docker.Host}}' ] || exit 2
        printf '%s\n' "${FAKE_DOCKER_CONTEXT_HOST:-unix:///var/run/docker.sock}"
        exit 0
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
        exit 0
        ;;
    ps)
        printf '%s\n' ps >>"$log"
        [ "${2:-}" = --filter ] && [ "${3:-}" = volume=kfadapter_db_data ] && [ "${4:-}" = -q ] || exit 2
        [ "${FAKE_DOCKER_PS_FAIL:-}" != 1 ] || exit 1
        [ "${FAKE_DOCKER_RUNNING:-}" != 1 ] || printf '%s\n' running-container
        exit 0
        ;;
    image)
        [ "${2:-}" = inspect ] || exit 2
        [ "${3:-}" = "ghcr.io/oshinop/kfadapter@sha256:$(printf '%064d' 0)" ] || exit 2
        printf '%s\n' image-inspect >>"$log"
        exit 0
        ;;
    run)
        shift
        [ "${1:-}" = --rm ] || exit 2; shift
        [ "${1:-}" = --pull ] && [ "${2:-}" = never ] || exit 2; shift 2
        [ "${1:-}" = --network ] && [ "${2:-}" = none ] || exit 2; shift 2
        [ "${1:-}" = --read-only ] || exit 2; shift
        [ "${1:-}" = --user ] && [ "${2:-}" = "65532:65532" ] || exit 2; shift 2
        [ "${1:-}" = --cap-drop ] && [ "${2:-}" = ALL ] || exit 2; shift 2
        [ "${1:-}" = --security-opt ] && [ "${2:-}" = no-new-privileges ] || exit 2; shift 2
        [ "${1:-}" = --pids-limit ] && [ "${2:-}" = 64 ] || exit 2; shift 2
        [ "${1:-}" = --memory ] && [ "${2:-}" = 128m ] || exit 2; shift 2
        [ "${1:-}" = --entrypoint ] && [ "${2:-}" = /kfadapter/kfadapter ] || exit 2; shift 2
        [ "${1:-}" = -v ] || exit 2
        mount=${2:-}; shift 2
        case "$mount" in /*:/restore:ro) ;; *) exit 2 ;; esac
        [ "${1:-}" = "ghcr.io/oshinop/kfadapter@sha256:$(printf '%064d' 0)" ] || exit 2; shift
        [ "$#" -eq 3 ] && [ "${1:-}" = validate-state ] && [ "${2:-}" = --file ] && [ "${3:-}" = /restore/state.db ] || exit 2
        stage=${mount%:/restore:ro}
        printf '%s\n' docker-run-offline-validator >>"$log"
        python3 - "$stage" "${FAKE_EXPECTED_STATE_DB:?}" <<'PY'
from pathlib import Path
import sqlite3
import stat
import sys

stage = Path(sys.argv[1])
expected = Path(sys.argv[2])
entries = list(stage.iterdir())
assert len(entries) == 1 and entries[0].name == "state.db"
metadata = entries[0].stat(follow_symlinks=False)
assert stat.S_ISREG(metadata.st_mode) and not entries[0].is_symlink()
database = entries[0]
connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
connection.close()
assert database.read_bytes() == expected.read_bytes()
PY
        [ "${FAKE_VALIDATION:-valid}" = valid ] || exit 1
        exit 0
        ;;
    compose)
        shift
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --env-file|-f) shift 2 ;;
                *) break ;;
            esac
        done
        case "${1:-}" in
            config)
                [ "${2:-}" = --images ] && [ "${3:-}" = kfadapter ] || exit 2
                printf '%s\n' compose-config-images >>"$log"
                printf '%s\n' "ghcr.io/oshinop/kfadapter@sha256:$(printf '%064d' 0)"
                exit 0
                ;;
            run)
                shift
                no_deps=false network= entrypoint= mount=
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        --rm|--pull) [ "$1" = --pull ] && [ "${2:-}" = never ] && shift; shift ;;
                        --no-deps) no_deps=true; shift ;;
                        --network) network=${2:-}; shift 2 ;;
                        --entrypoint) entrypoint=${2:-}; shift 2 ;;
                        -v) mount=${2:-}; shift 2 ;;
                        *) break ;;
                    esac
                done
                [ "$no_deps" = true ] && [ "$network" = none ] && \
                    [ "$entrypoint" = /kfadapter/kfadapter ] && \
                    case "$mount" in /*:/restore:ro) true;; *) false;; esac && \
                    [ "$#" -eq 4 ] && [ "${1:-}" = kfadapter ] && \
                    [ "${2:-}" = validate-state ] && [ "${3:-}" = --file ] && \
                    [ "${4:-}" = /restore/state.db ] || exit 2
                stage=${mount%:/restore:ro}
                printf '%s\n' compose-run-offline-validator >>"$log"
                python3 - "$stage" "${FAKE_EXPECTED_STATE_DB:?}" <<'PY'
from pathlib import Path
import sqlite3
import stat
import sys

stage = Path(sys.argv[1])
expected = Path(sys.argv[2])
entries = list(stage.iterdir())
assert len(entries) == 1 and entries[0].name == "state.db"
metadata = entries[0].stat(follow_symlinks=False)
assert stat.S_ISREG(metadata.st_mode) and not entries[0].is_symlink()
database = entries[0]
connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
connection.close()
assert database.read_bytes() == expected.read_bytes()
PY
                [ "${FAKE_VALIDATION:-valid}" = valid ] || exit 1
                printf '%s\n' "state valid"
                exit 0
                ;;
        esac
        ;;
esac
exit 2
SH
chmod 0755 "$work/scripts/docker-local-context.sh" "$work/scripts/preflight.sh" "$work/scripts/restore-state.sh" "$work/scripts/restore-state-archive.py" "$work/scripts/restore-state-commit.py" "$work/scripts/state-volume-path.sh" "$work/scripts/verify-state-path.py" "$work/bin/id" "$work/bin/docker"

run_restore() {
    FAKE_DOCKER_LOG="$work/docker.log" \
        FAKE_DOCKER_PS_FAIL="${FAKE_DOCKER_PS_FAIL:-}" \
        FAKE_DOCKER_RUNNING="${FAKE_DOCKER_RUNNING:-}" \
        FAKE_STATE_MOUNTPOINT="${FAKE_STATE_MOUNTPOINT:-$work/state}" \
        FAKE_EXPECTED_STATE_DB="$work/input/state.db" \
        FAKE_VALIDATION="${FAKE_VALIDATION:-valid}" \
        PATH="$work/bin:$PATH" \
        KFADAPTER_HOST_UID="$actual_uid" \
        KFADAPTER_HOST_GID="$actual_gid" \
        "$work/scripts/restore-state.sh" "$1"
}

run_restore_at_volume_path() {
    FAKE_DOCKER_LOG="$work/docker.log" \
        FAKE_DOCKER_PS_FAIL="${FAKE_DOCKER_PS_FAIL:-}" \
        FAKE_DOCKER_RUNNING="${FAKE_DOCKER_RUNNING:-}" \
        FAKE_STATE_MOUNTPOINT="$1" \
        FAKE_EXPECTED_STATE_DB="$work/input/state.db" \
        FAKE_VALIDATION="${FAKE_VALIDATION:-valid}" \
        PATH="$work/bin:$PATH" \
        KFADAPTER_HOST_UID="$actual_uid" \
        KFADAPTER_HOST_GID="$actual_gid" \
        "$work/scripts/restore-state.sh" "$2"
}

assert_live_payload() {
    python3 - "$work/state" "$1" "$2" "$actual_uid" "$actual_gid" <<'PY'
from pathlib import Path
import stat
import sys

state = Path(sys.argv[1])
expected_name = sys.argv[2]
expected = Path(sys.argv[3])
expected_uid = int(sys.argv[4])
expected_gid = int(sys.argv[5])
entries = list(state.iterdir())
assert len(entries) == 1 and entries[0].name == expected_name
metadata = entries[0].stat(follow_symlinks=False)
assert stat.S_ISREG(metadata.st_mode) and not entries[0].is_symlink()
assert stat.S_IMODE(metadata.st_mode) == 0o600
assert metadata.st_uid == expected_uid and metadata.st_gid == expected_gid
assert entries[0].read_bytes() == expected.read_bytes()
PY
}
snapshot_live_metadata() {
    python3 - "$work/state/state.db" <<'PY'
from pathlib import Path
import stat
import sys

metadata = Path(sys.argv[1]).lstat()
print(stat.S_IFMT(metadata.st_mode), stat.S_IMODE(metadata.st_mode), metadata.st_nlink, metadata.st_uid, metadata.st_gid, metadata.st_size, metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns)
PY
}
assert_exact_archive_payload() {
    python3 - "$1" "$2" <<'PY'
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
}


python3 - "$work/input/state.db" "$work/original-state.db" <<'PY'
from pathlib import Path
import sqlite3
import sys

def create_database(path: Path, marker: str) -> None:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("CREATE TABLE deployment_verification (marker TEXT NOT NULL)")
    connection.execute("INSERT INTO deployment_verification(marker) VALUES (?)", (marker,))
    connection.commit()
    connection.execute("VACUUM")
    connection.close()
    path.chmod(0o600)

create_database(Path(sys.argv[1]), "restored-current-state")
create_database(Path(sys.argv[2]), "prior-current-state")
PY
current_archive="$work/current-state-db.tar.gz"
COPYFILE_DISABLE=1 tar --create --gzip --file "$current_archive" --directory "$work/input" state.db
cp "$work/original-state.db" "$work/state/state.db"

: >"$work/docker.log"
run_restore_at_volume_path "$work/state/" "$current_archive"
assert_live_payload state.db "$work/input/state.db" || fail "current SQLite state was not restored byte-for-byte"
grep -Fq "preflight --state-dir $work/state" "$work/docker.log" || fail "restore did not run pinned production preflight against the canonical state path"
assert_exact_archive_payload "$current_archive" "$work/input/state.db" || fail "current SQLite archive did not retain exact database bytes"
case "$(cat "$work/docker.log")" in
    *compose-config-images*image-inspect*docker-run-offline-validator*) ;;
    *) fail "current SQLite restore did not use the cached Docker validator offline" ;;
esac

: >"$work/docker.log"
if FAKE_VALIDATION=invalid run_restore "$current_archive" >/dev/null 2>&1; then
    fail "offline validator accepted a rejected SQLite database"
fi
assert_live_payload state.db "$work/input/state.db" || fail "offline validator rejection changed live SQLite bytes"
grep -Fq 'docker-run-offline-validator' "$work/docker.log" || fail "valid SQLite archive bypassed offline validation"
FAKE_VALIDATION=valid
run_restore "$current_archive"
assert_live_payload state.db "$work/input/state.db" || fail "repeated current SQLite restore changed state bytes"
set -- "$work"/.state.pre-restore-*
[ "$#" -eq 2 ] || fail "same-second current restores did not retain unique previous directories"
[ "$1" != "$2" ] || fail "current restores reused a previous directory"
previous_current_count=0
previous_original_count=0
for previous in "$@"; do
    [ -d "$previous/state" ] || fail "previous state was not retained in its protected directory"
    [ -f "$previous/state/state.db" ] || fail "previous state did not retain a current SQLite payload"
    if cmp -s "$work/input/state.db" "$previous/state/state.db"; then
        previous_current_count=$((previous_current_count + 1))
    elif cmp -s "$work/original-state.db" "$previous/state/state.db"; then
        previous_original_count=$((previous_original_count + 1))
    else
        fail "previous state did not retain known SQLite bytes"
    fi
done
[ "$previous_current_count" -eq 1 ] || fail "repeated current restore did not preserve its prior SQLite state"
[ "$previous_original_count" -eq 1 ] || fail "initial current SQLite state was not retained for rollback"
: >"$work/docker.log"
snapshot_live_metadata >"$work/ps-failure-state-before"
if FAKE_DOCKER_PS_FAIL=1 run_restore "$current_archive" >"$work/ps-failure-output" 2>&1; then
    fail "restore continued after Docker ps failure"
fi
FAKE_DOCKER_PS_FAIL=
grep -Fq 'could not determine whether the Docker state volume is in use' "$work/ps-failure-output" || fail "restore did not report Docker ps failure"
assert_live_payload state.db "$work/input/state.db" || fail "Docker ps failure changed live SQLite bytes"
snapshot_live_metadata >"$work/ps-failure-state-after"
cmp -s "$work/ps-failure-state-before" "$work/ps-failure-state-after" || fail "Docker ps failure changed live SQLite metadata"
grep -Fqx ps "$work/docker.log" || fail "restore Docker ps failure reached later Docker operations"
unset FAKE_DOCKER_PS_FAIL
snapshot_live_metadata >"$work/running-state-before"
if FAKE_DOCKER_RUNNING=1 run_restore "$current_archive" >"$work/running-output" 2>&1; then
    fail "restore accepted a state directory mounted by a running container"
fi
unset FAKE_DOCKER_RUNNING
grep -Fq 'Docker state volume is in use' "$work/running-output" || fail "restore did not report the mounted state volume"
assert_live_payload state.db "$work/input/state.db" || fail "mounted-state rejection changed live SQLite bytes"
snapshot_live_metadata >"$work/running-state-after"
cmp -s "$work/running-state-before" "$work/running-state-after" || fail "mounted-state rejection changed live SQLite metadata"


mkdir "$work/symlink-target" "$work/symlink-stage" "$work/ancestor-stage"
printf '%s\n' sentinel >"$work/symlink-target/sentinel"
ln -s "$work/symlink-target" "$work/symlink-state"
if python3 "$work/scripts/restore-state-commit.py" --parent "$work" --state-name symlink-state --stage-name symlink-stage --state-identity ignored >/dev/null 2>&1; then
    fail "symlink state source passed commit validation"
fi
[ "$(cat "$work/symlink-target/sentinel")" = sentinel ] || fail "symlink target was modified"
chmod 0754 "$work/symlink-target"
python3 - "$work/symlink-target" >"$work/restore-target-before" <<'PY'
from pathlib import Path
import stat
import sys
metadata = Path(sys.argv[1]).stat()
print(stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
PY
ln -s "$work/symlink-target" "$work/restore-wrapper-link"
if run_restore_at_volume_path "$work/restore-wrapper-link" "$current_archive" >/dev/null 2>&1; then
    fail "restore wrapper accepted a symlink state directory"
fi
python3 - "$work/symlink-target" >"$work/restore-target-after" <<'PY'
from pathlib import Path
import stat
import sys
metadata = Path(sys.argv[1]).stat()
print(stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)
PY
cmp -s "$work/restore-target-before" "$work/restore-target-after" || fail "restore wrapper modified symlink target ownership or mode"
ln -s "$work" "$work/symlink-parent"
if python3 "$work/scripts/restore-state-commit.py" --parent "$work/symlink-parent" --state-name state --stage-name ancestor-stage --state-identity ignored >/dev/null 2>&1; then
    fail "symlink state ancestor passed commit validation"
fi

if KFADAPTER_RESTORE_MAX_ARCHIVE_BYTES=1 run_restore "$current_archive" >/dev/null 2>&1; then
    fail "compressed archive beyond its limit was restored"
fi
assert_live_payload state.db "$work/input/state.db" || fail "compressed-limit rejection changed live current SQLite bytes"
unset KFADAPTER_RESTORE_MAX_ARCHIVE_BYTES

python3 - "$work/bomb-current.tar.gz" <<'PY'
from io import BytesIO
from pathlib import Path
from tarfile import TarInfo, open as taropen
import sys

with taropen(Path(sys.argv[1]), "w:gz") as archive:
    entry = TarInfo("state.db")
    body = b"0" * 8192
    entry.size = len(body)
    archive.addfile(entry, BytesIO(body))
PY
if KFADAPTER_RESTORE_MAX_UNCOMPRESSED_BYTES=1024 run_restore "$work/bomb-current.tar.gz" >/dev/null 2>&1; then
    fail "uncompressed archive beyond its limit was restored"
fi
assert_live_payload state.db "$work/input/state.db" || fail "uncompressed-limit rejection changed live current SQLite bytes"
unset KFADAPTER_RESTORE_MAX_UNCOMPRESSED_BYTES

printf '%s\n' malformed >"$work/malformed-state.tar.gz"
python3 - "$work" "$work/input/state.db" <<'PY'
from io import BytesIO
from pathlib import Path
from tarfile import DIRTYPE, FIFOTYPE, LNKTYPE, SYMTYPE, TarInfo, open as taropen
import sys

root = Path(sys.argv[1])
current = Path(sys.argv[2]).read_bytes()

def regular(archive, name, body):
    entry = TarInfo(name)
    entry.size = len(body)
    archive.addfile(entry, BytesIO(body))

with taropen(root / "missing-state.tar.gz", "w:gz") as archive:
    regular(archive, "other", b"x")
with taropen(root / "sqlite-sibling.tar.gz", "w:gz") as archive:
    regular(archive, "state.db", current)
    regular(archive, "state.db-wal", b"wal")
with taropen(root / "duplicate-current.tar.gz", "w:gz") as archive:
    regular(archive, "state.db", current)
    regular(archive, "./state.db", current)
with taropen(root / "traversal-current.tar.gz", "w:gz") as archive:
    regular(archive, "../state.db", current)
with taropen(root / "directory-current.tar.gz", "w:gz") as archive:
    entry = TarInfo("state.db")
    entry.type = DIRTYPE
    archive.addfile(entry)
with taropen(root / "special-current.tar.gz", "w:gz") as archive:
    entry = TarInfo("state.db")
    entry.type = FIFOTYPE
    archive.addfile(entry)
with taropen(root / "symlink-current.tar.gz", "w:gz") as archive:
    entry = TarInfo("state.db")
    entry.type = SYMTYPE
    entry.linkname = "elsewhere"
    archive.addfile(entry)
with taropen(root / "hardlink-current.tar.gz", "w:gz") as archive:
    entry = TarInfo("state.db")
    entry.type = LNKTYPE
    entry.linkname = "elsewhere"
    archive.addfile(entry)
with taropen(root / "oversized-current.tar.gz", "w:gz") as archive:
    regular(archive, "state.db", b"0" * ((18 << 20) + 1))
with taropen(root / "corrupt-current.tar.gz", "w:gz") as archive:
    regular(archive, "state.db", b"not a SQLite database")
PY

for rejected in malformed-state missing-state sqlite-sibling duplicate-current traversal-current directory-current special-current symlink-current hardlink-current oversized-current; do
    if run_restore "$work/$rejected.tar.gz" >/dev/null 2>&1; then
        fail "$rejected archive was restored"
    fi
    assert_live_payload state.db "$work/input/state.db" || fail "$rejected rejection changed live current SQLite bytes"
done

: >"$work/docker.log"
if run_restore "$work/corrupt-current.tar.gz" >/dev/null 2>&1; then
    fail "corrupt current SQLite archive passed offline validation"
fi
assert_live_payload state.db "$work/input/state.db" || fail "corrupt current SQLite rejection changed live bytes"
grep -Fq 'docker-run-offline-validator' "$work/docker.log" || fail "corrupt SQLite archive did not reach offline validation"
printf '%s\n' "restore-state-test: passed"
