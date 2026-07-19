#!/usr/bin/env python3
"""Commit a prepared state directory without following untrusted path entries."""

from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import stat
import sys
from pathlib import Path


class CommitError(Exception):
    pass


def fail(message: str) -> None:
    raise CommitError(message)


def valid_name(value: str, option: str) -> str:
    if not value or value in {".", ".."} or "/" in value:
        fail(f"{option} must be a single directory name")
    return value


DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

STATE_DB_MAX_BYTES = 18 << 20


def same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, stat.S_IFMT(first.st_mode)) == (
        second.st_dev,
        second.st_ino,
        stat.S_IFMT(second.st_mode),
    )


def directory_stat(parent_fd: int, name: str, message: str) -> os.stat_result:
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        fail(f"{message}: {error}")
    if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
        fail(message)
    return entry


def open_checked_directory(parent_fd: int, name: str, message: str) -> tuple[int, os.stat_result]:
    entry = directory_stat(parent_fd, name, message)
    try:
        descriptor = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        fail(f"{message}: {error}")
    try:
        opened = os.fstat(descriptor)
        if not same_identity(entry, opened) or not stat.S_ISDIR(opened.st_mode):
            fail(f"{message}: directory identity changed")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def sync_tree(directory_fd: int) -> None:
    """Durably flush only the regular-file, no-symlink staged tree."""
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            entry_metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry_metadata.st_mode):
                fail("restore staging directory must not contain symlinks")
            if stat.S_ISREG(entry_metadata.st_mode):
                try:
                    file_fd = os.open(entry.name, FILE_FLAGS, dir_fd=directory_fd)
                except OSError as error:
                    fail(f"could not open staged file safely: {error}")
                try:
                    opened = os.fstat(file_fd)
                    if not same_identity(entry_metadata, opened) or not stat.S_ISREG(opened.st_mode):
                        fail("restore staging file identity changed")
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
            elif stat.S_ISDIR(entry_metadata.st_mode):
                try:
                    child_fd = os.open(entry.name, DIR_FLAGS, dir_fd=directory_fd)
                except OSError as error:
                    fail(f"could not open staged directory safely: {error}")
                try:
                    opened = os.fstat(child_fd)
                    if not same_identity(entry_metadata, opened) or not stat.S_ISDIR(opened.st_mode):
                        fail("restore staging directory identity changed")
                    sync_tree(child_fd)
                finally:
                    os.close(child_fd)
            else:
                fail("restore staging directory must contain only regular files and directories")
    os.fsync(directory_fd)


def validate_stage_file(directory_fd: int) -> str:
    entries = list(os.scandir(directory_fd))
    if len(entries) != 1:
        fail("restore staging directory must contain exactly one state.db payload")
    entry = entries[0]
    if entry.name != "state.db":
        fail("restore staging directory entry is not state.db")
    entry_metadata = entry.stat(follow_symlinks=False)
    if (
        stat.S_ISLNK(entry_metadata.st_mode)
        or not stat.S_ISREG(entry_metadata.st_mode)
        or entry_metadata.st_nlink != 1
        or entry_metadata.st_size <= 0
        or entry_metadata.st_size > STATE_DB_MAX_BYTES
        or stat.S_IMODE(entry_metadata.st_mode) != 0o600
    ):
        fail("restore staging payload is not a safe bounded 0600 regular file")
    try:
        file_fd = os.open(entry.name, FILE_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        fail(f"could not open staged state payload safely: {error}")
    try:
        opened = os.fstat(file_fd)
        if (
            not same_identity(entry_metadata, opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != entry_metadata.st_size
            or opened.st_size > STATE_DB_MAX_BYTES
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            fail("restore staging payload identity changed")
        return entry.name
    finally:
        os.close(file_fd)


def validate_staging_layout(parent: Path, stage_name: str) -> str:
    try:
        parent_fd = os.open(parent, DIR_FLAGS)
    except OSError as error:
        fail(f"cannot open the state parent safely: {error}")
    try:
        stage_fd, stage_metadata = open_checked_directory(
            parent_fd, stage_name, "restore staging directory is not a safe directory"
        )
        try:
            payload_name = validate_stage_file(stage_fd)
            final_metadata = directory_stat(parent_fd, stage_name, "restore staging directory is not a safe directory")
            if not same_identity(stage_metadata, final_metadata):
                fail("restore staging directory identity changed")
            return payload_name
        finally:
            os.close(stage_fd)
    finally:
        os.close(parent_fd)


def prepare_staging(parent: Path, stage_name: str, uid: int, gid: int) -> str:
    if uid < 0 or gid < 0:
        fail("state owner IDs must be non-negative")
    try:
        parent_fd = os.open(parent, DIR_FLAGS)
    except OSError as error:
        fail(f"cannot open the state parent safely: {error}")
    try:
        stage_fd, stage_metadata = open_checked_directory(
            parent_fd, stage_name, "restore staging directory is not a safe directory"
        )
        try:
            payload_name = validate_stage_file(stage_fd)
            file_fd = os.open(payload_name, FILE_FLAGS, dir_fd=stage_fd)
            try:
                file_metadata = os.fstat(file_fd)
                os.fchown(file_fd, uid, gid)
                os.fchmod(file_fd, 0o600)
                secured_file = os.fstat(file_fd)
                if (
                    not same_identity(file_metadata, secured_file)
                    or not stat.S_ISREG(secured_file.st_mode)
                    or secured_file.st_nlink != 1
                    or secured_file.st_size != file_metadata.st_size
                    or stat.S_IMODE(secured_file.st_mode) != 0o600
                    or secured_file.st_uid != uid
                    or secured_file.st_gid != gid
                ):
                    fail("restore staging payload changed while ownership was prepared")
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            os.fchown(stage_fd, uid, gid)
            os.fchmod(stage_fd, 0o700)
            secured_stage = os.fstat(stage_fd)
            if (
                not same_identity(stage_metadata, secured_stage)
                or not stat.S_ISDIR(secured_stage.st_mode)
                or stat.S_IMODE(secured_stage.st_mode) != 0o700
                or secured_stage.st_uid != uid
                or secured_stage.st_gid != gid
            ):
                fail("restore staging directory changed while ownership was prepared")
            validate_stage_file(stage_fd)
            final_metadata = directory_stat(parent_fd, stage_name, "restore staging directory is not a safe directory")
            if not same_identity(stage_metadata, final_metadata):
                fail("restore staging directory identity changed")
            os.fsync(stage_fd)
            os.fsync(parent_fd)
            return payload_name
        finally:
            os.close(stage_fd)
    except OSError as error:
        fail(f"could not prepare restored state ownership: {error}")
    finally:
        os.close(parent_fd)

def sync_staging(parent_fd: int, stage_name: str) -> os.stat_result:
    stage_fd, stage_metadata = open_checked_directory(
        parent_fd, stage_name, "restore staging directory is not a safe directory"
    )
    try:
        validate_stage_file(stage_fd)
        sync_tree(stage_fd)
        final_metadata = directory_stat(parent_fd, stage_name, "restore staging directory is not a safe directory")
        if not same_identity(stage_metadata, final_metadata):
            fail("restore staging directory identity changed")
        return stage_metadata
    finally:
        os.close(stage_fd)


def exchange_directories(parent_fd: int, first_name: str, second_name: str) -> None:
    if sys.platform.startswith("linux"):
        symbol = "renameat2"
        unavailable = "atomic restore requires Linux renameat2 RENAME_EXCHANGE support"
    elif sys.platform == "darwin":
        symbol = "renameatx_np"
        unavailable = "atomic restore requires Darwin renameatx_np RENAME_SWAP support"
    else:
        fail("atomic restore requires platform atomic directory exchange support")
    try:
        exchange = getattr(ctypes.CDLL(None, use_errno=True), symbol)
    except (AttributeError, OSError):
        fail(unavailable)
    exchange.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    exchange.restype = ctypes.c_int
    if exchange(
        parent_fd,
        os.fsencode(first_name),
        parent_fd,
        os.fsencode(second_name),
        0x2,
    ) != 0:
        error = ctypes.get_errno()
        fail(f"could not atomically exchange state directories: {os.strerror(error)}")


def reserve_previous(parent_fd: int, state_name: str) -> str:
    for _ in range(32):
        name = f".{state_name}.pre-restore-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            return name
        except FileExistsError:
            continue
        except OSError as error:
            fail(f"could not reserve the previous-state directory: {error}")
    fail("could not reserve a unique previous-state directory")


def rollback_to_original(
    parent_fd: int,
    previous_fd: int,
    state_name: str,
    stage_name: str,
    old_state_fd: int,
    new_state_fd: int,
    old_state_preserved: bool,
) -> None:
    if old_state_preserved:
        os.rename("state", stage_name, src_dir_fd=previous_fd, dst_dir_fd=parent_fd)
        if old_state_fd >= 0:
            os.fsync(old_state_fd)
        os.fsync(previous_fd)
        os.fsync(parent_fd)
    exchange_directories(parent_fd, stage_name, state_name)
    if new_state_fd >= 0:
        os.fsync(new_state_fd)
    if old_state_fd >= 0:
        os.fsync(old_state_fd)
    os.fsync(parent_fd)


def commit(parent: Path, state_name: str, stage_name: str, expected_identity: str) -> str:
    try:
        parent_fd = os.open(parent, DIR_FLAGS)
    except OSError as error:
        fail(f"cannot open the state parent safely: {error}")

    previous_name = ""
    previous_fd = -1
    old_state_fd = -1
    new_state_fd = -1
    state_exchanged = False
    old_state_preserved = False
    try:
        old_state_fd, state_metadata = open_checked_directory(
            parent_fd, state_name, "state directory is not a safe directory"
        )
        if f"{state_metadata.st_dev}:{state_metadata.st_ino}" != expected_identity:
            fail("state directory identity changed")
        stage_metadata = sync_staging(parent_fd, stage_name)
        previous_name = reserve_previous(parent_fd, state_name)
        previous_fd, _ = open_checked_directory(
            parent_fd, previous_name, "previous-state directory is not a safe directory"
        )
        os.fsync(previous_fd)
        os.fsync(parent_fd)
        current_stage = directory_stat(parent_fd, stage_name, "restore staging directory is not a safe directory")
        if not same_identity(stage_metadata, current_stage):
            fail("restore staging directory identity changed")
        exchange_directories(parent_fd, stage_name, state_name)
        state_exchanged = True
        new_state_fd, installed = open_checked_directory(
            parent_fd, state_name, "restored state directory is not a safe directory"
        )
        if not same_identity(stage_metadata, installed):
            fail("restored state directory identity changed")
        displaced = directory_stat(parent_fd, stage_name, "displaced state directory is not a safe directory")
        if not same_identity(state_metadata, displaced):
            fail("displaced state directory identity changed")
        os.fsync(new_state_fd)
        os.fsync(old_state_fd)
        os.fsync(parent_fd)
        os.rename(stage_name, "state", src_dir_fd=parent_fd, dst_dir_fd=previous_fd)
        old_state_preserved = True
        os.fsync(old_state_fd)
        os.fsync(previous_fd)
        os.fsync(parent_fd)
        return previous_name
    except (OSError, CommitError) as error:
        if not state_exchanged:
            if previous_name:
                try:
                    os.rmdir(previous_name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError:
                    pass
            fail(f"could not commit restored state: {error}")
        try:
            rollback_to_original(
                parent_fd,
                previous_fd,
                state_name,
                stage_name,
                old_state_fd,
                new_state_fd,
                old_state_preserved,
            )
        except (OSError, CommitError) as rollback_error:
            fail(
                "could not commit restored state; durable rollback to the live path could not be confirmed. "
                f"Inspect the protected previous directory and live path: {error}; {rollback_error}"
            )
        fail(f"could not commit restored state; original state was restored and staged data was retained: {error}")
    finally:
        if new_state_fd >= 0:
            os.close(new_state_fd)
        if old_state_fd >= 0:
            os.close(old_state_fd)
        if previous_fd >= 0:
            os.close(previous_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--state-name")
    parser.add_argument("--stage-name", required=True)
    parser.add_argument("--state-identity")
    parser.add_argument("--validate-stage", action="store_true")
    parser.add_argument("--prepare-stage", action="store_true")
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    args = parser.parse_args()
    stage_name = valid_name(args.stage_name, "--stage-name")
    if args.validate_stage and args.prepare_stage:
        parser.error("--validate-stage and --prepare-stage cannot be combined")
    if args.validate_stage:
        validate_staging_layout(args.parent, stage_name)
        return 0
    if args.prepare_stage:
        if args.uid is None or args.gid is None:
            parser.error("--uid and --gid are required with --prepare-stage")
        print(prepare_staging(args.parent, stage_name, args.uid, args.gid))
        return 0
    if args.state_name is None or args.state_identity is None:
        parser.error("--state-name and --state-identity are required when committing")
    state_name = valid_name(args.state_name, "--state-name")
    if state_name == stage_name:
        fail("state and restore staging directories must differ")
    print(commit(args.parent, state_name, stage_name, args.state_identity))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CommitError as error:
        print(f"restore-state: {error}", file=sys.stderr)
        raise SystemExit(1)
