#!/usr/bin/env sh
# Prove restored-state durability ordering and failure rollback semantics.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

fail() {
    printf '%s\n' "restore-commit-test: $*" >&2
    exit 1
}

tmp_root=${TMPDIR:-/tmp}
tmp_root=${tmp_root%/}
work=$(mktemp -d "$tmp_root/kfadapter-restore-commit.XXXXXXXX")
work=$(CDPATH= cd -- "$work" && pwd -P)
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

python3 - "$PROJECT_ROOT/scripts/restore-state-commit.py" "$work" <<'PY'
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import os
import subprocess
import sys

script = Path(sys.argv[1])
work = Path(sys.argv[2])


def load_module():
    spec = spec_from_file_location("restore_state_commit", script)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_tree(parent: Path) -> tuple[Path, Path, str]:
    parent.mkdir(mode=0o700)
    state = parent / "state"
    stage = parent / "stage"
    state.mkdir(mode=0o700)
    stage.mkdir(mode=0o700)
    (state / "original").write_text("original")
    (stage / "state.db").write_bytes(b"SQLite format 3\x00restored fixture\n")
    (state / "original").chmod(0o600)
    (stage / "state.db").chmod(0o600)
    metadata = state.stat()
    return state, stage, f"{metadata.st_dev}:{metadata.st_ino}"


# Success must durably flush staging, atomically exchange it into place, flush
# the exchange, then retain the displaced state in the previous directory.
module = load_module()
success_parent = work / "success"
state, stage, identity = make_tree(success_parent)
events: list[str] = []
real_open = module.os.open
real_fsync = module.os.fsync
real_rename = module.os.rename
real_exchange = module.exchange_directories
real_sync_tree = module.sync_tree
parent_descriptor: list[int | None] = [None]


def traced_open(path, *args, **kwargs):
    descriptor = real_open(path, *args, **kwargs)
    if Path(path) == success_parent:
        parent_descriptor[0] = descriptor
    return descriptor


def traced_sync_tree(descriptor):
    events.append("staging-tree-synced")
    return real_sync_tree(descriptor)


def traced_fsync(descriptor):
    events.append("parent-fsynced" if descriptor == parent_descriptor[0] else "fsynced")
    return real_fsync(descriptor)


def traced_rename(source, target, *args, **kwargs):
    events.append("displaced-to-previous")
    return real_rename(source, target, *args, **kwargs)


def traced_exchange(parent_fd, first_name, second_name):
    events.append("directories-exchanged")
    return real_exchange(parent_fd, first_name, second_name)


module.os.open = traced_open
module.os.fsync = traced_fsync
module.os.rename = traced_rename
module.exchange_directories = traced_exchange
module.sync_tree = traced_sync_tree
try:
    previous = module.commit(success_parent, "state", "stage", identity)
finally:
    module.os.open = real_open
    module.os.fsync = real_fsync
    module.os.rename = real_rename
    module.exchange_directories = real_exchange
    module.sync_tree = real_sync_tree

staging_sync = events.index("staging-tree-synced")
exchange = events.index("directories-exchanged")
retention = events.index("displaced-to-previous")
assert staging_sync < exchange < retention, events
assert "parent-fsynced" in events[staging_sync + 1 : exchange], events
assert events[exchange + 1 : retention].count("fsynced") >= 2, events
assert "parent-fsynced" in events[exchange + 1 : retention], events
assert "parent-fsynced" in events[retention + 1 :], events
assert (success_parent / "state" / "state.db").read_bytes() == b"SQLite format 3\x00restored fixture\n"
assert (success_parent / previous / "state" / "original").read_text() == "original"

# An atomic exchange failure must retain both the original live state and the
# staged SQLite state without leaving a reserved previous-state directory.
exchange_failure_parent = work / "exchange-failure"
state, stage, identity = make_tree(exchange_failure_parent)
module = load_module()
real_exchange = module.exchange_directories


def failing_exchange(parent_fd, first_name, second_name):
    raise module.CommitError("injected atomic exchange failure")


module.exchange_directories = failing_exchange
try:
    try:
        module.commit(exchange_failure_parent, "state", "stage", identity)
    except module.CommitError as error:
        assert "could not commit restored state" in str(error)
    else:
        raise AssertionError("injected exchange failure committed state")
finally:
    module.exchange_directories = real_exchange
assert (exchange_failure_parent / "state" / "original").read_text() == "original"
assert (exchange_failure_parent / "stage" / "state.db").read_bytes() == b"SQLite format 3\x00restored fixture\n"
assert list(exchange_failure_parent.glob(".state.pre-restore-*")) == []

# Fail the first fsync after atomic exchange. The command itself must fail,
# but recovery must make the original path immediately usable and leave the
# staged restoration data available for diagnosis/retry.
# (Failure setup follows the exchange-failure assertion above.)
failure_parent = work / "failure"
state, stage, identity = make_tree(failure_parent)
inject = work / "inject"
inject.mkdir()
(inject / "sitecustomize.py").write_text(
    "import os\n"
    "_real_fsync = os.fsync\n"
    "_calls = 0\n"
    "def fsync(fd):\n"
    "    global _calls\n"
    "    _calls += 1\n"
    "    if _calls == 5:\n"
    "        raise OSError('injected post-exchange fsync failure')\n"
    "    return _real_fsync(fd)\n"
    "os.fsync = fsync\n"
)
environment = os.environ.copy()
environment["PYTHONPATH"] = str(inject)
completed = subprocess.run(
    [
        sys.executable,
        str(script),
        "--parent",
        str(failure_parent),
        "--state-name",
        "state",
        "--stage-name",
        "stage",
        "--state-identity",
        identity,
    ],
    env=environment,
    capture_output=True,
    text=True,
    check=False,
)
assert completed.returncode != 0
assert "original state was restored" in completed.stderr
assert (failure_parent / "state" / "original").read_text() == "original"
assert (failure_parent / "stage" / "state.db").read_bytes() == b"SQLite format 3\x00restored fixture\n"
assert (failure_parent / "state").is_dir() and not (failure_parent / "state").is_symlink()
PY
printf '%s\n' "restore-commit-test: passed"
