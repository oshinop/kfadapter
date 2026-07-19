#!/usr/bin/env python3
"""Verify state ownership and identity without following path symlinks."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path
STATE_DB_MAX_BYTES = 18 << 20



class StatePathError(Exception):
    pass


def fail(message: str) -> None:
    raise StatePathError(message)


def absolute_parts(path: str, base: Path) -> list[str]:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base / candidate
    if not candidate.is_absolute():
        fail("state directory must resolve to an absolute path")
    parts = list(candidate.parts)
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts[1:]):
        fail("state directory must not contain noncanonical path components")
    return parts[1:]

def canonical_path(parts: list[str]) -> str:
    return "/" + "/".join(parts)


def open_directory(parts: list[str]) -> tuple[int, str, int]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent = os.open("/", flags)
    try:
        for part in parts[:-1]:
            metadata = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                fail("state directory ancestry must contain only non-symlink directories")
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        name = parts[-1]
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail("state directory must be a non-symlink directory")
        directory = os.open(name, flags, dir_fd=parent)
        return parent, name, directory
    except OSError as error:
        os.close(parent)
        fail(f"could not inspect state directory safely: {error}")
    except Exception:
        os.close(parent)
        raise


def same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, stat.S_IFMT(first.st_mode)) == (
        second.st_dev,
        second.st_ino,
        stat.S_IFMT(second.st_mode),
    )


def verify_tree(directory_fd: int, uid: int, gid: int) -> None:
    metadata = os.fstat(directory_fd)
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("state directory mode must be exactly 0700")
    if metadata.st_uid != uid or metadata.st_gid != gid:
        fail(f"state directory owner must be UID:GID {uid}:{gid}")

    entries = list(os.scandir(directory_fd))
    if not entries:
        return
    if len(entries) != 1 or entries[0].name != "state.db":
        fail("state directory must be empty or contain exactly one state.db file")
    entry = entries[0]
    entry_metadata = entry.stat(follow_symlinks=False)
    if (
        stat.S_ISLNK(entry_metadata.st_mode)
        or not stat.S_ISREG(entry_metadata.st_mode)
        or entry_metadata.st_nlink != 1
        or entry_metadata.st_size <= 0
        or entry_metadata.st_size > STATE_DB_MAX_BYTES
        or stat.S_IMODE(entry_metadata.st_mode) != 0o600
        or entry_metadata.st_uid != uid
        or entry_metadata.st_gid != gid
    ):
        fail("state payload must be a non-empty 0600 regular file with one link and the state owner")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        file_fd = os.open(entry.name, flags, dir_fd=directory_fd)
    except OSError as error:
        fail(f"could not open state payload safely: {error}")
    try:
        opened = os.fstat(file_fd)
        if (
            not same_file_identity(entry_metadata, opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != entry_metadata.st_size
            or opened.st_size > STATE_DB_MAX_BYTES
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != uid
            or opened.st_gid != gid
        ):
            fail("state payload identity changed")
    finally:
        os.close(file_fd)

def verify(path: str, base: Path, uid: int, gid: int, expected: str | None) -> str:
    parent, name, directory = open_directory(absolute_parts(path, base))
    try:
        metadata = os.fstat(directory)
        identity = f"{metadata.st_dev}:{metadata.st_ino}"
        if expected is not None and identity != expected:
            fail("state directory identity changed")
        verify_tree(directory, uid, gid)
        final_entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        final = os.fstat(directory)
        if stat.S_ISLNK(final_entry.st_mode) or (final_entry.st_dev, final_entry.st_ino) != (final.st_dev, final.st_ino):
            fail("state directory identity changed")
        return identity
    finally:
        os.close(directory)
        os.close(parent)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--expect-identity")
    parser.add_argument("--print-canonical-path", action="store_true")
    args = parser.parse_args()
    if not args.base.is_absolute() or args.base.is_symlink():
        fail("--base must be an absolute non-symlink directory")
    parts = absolute_parts(args.state_dir, args.base)
    identity = verify(args.state_dir, args.base, args.uid, args.gid, args.expect_identity)
    print(canonical_path(parts) if args.print_canonical_path else identity)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StatePathError as error:
        print(f"state-path: {error}", file=sys.stderr)
        raise SystemExit(1)
