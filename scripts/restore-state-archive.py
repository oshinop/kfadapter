#!/usr/bin/env python3
"""Validate and safely extract a bounded gzip state archive into an empty stage."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024
MAX_MEMBERS = 10_000
STATE_DB_MAX_BYTES = 18 << 20



class ArchiveError(Exception):
    pass


def fail(message: str) -> None:
    raise ArchiveError(message)


def positive_limit(value: str, option: str) -> int:
    if not value.isdecimal() or value.startswith("0") or len(value) > 9:
        fail(f"{option} must be a positive decimal byte limit no greater than 999999999")
    return int(value)


def canonical_parts(name: str) -> tuple[str, ...]:
    if name in {".", "./"}:
        return ()
    if name.startswith("./"):
        name = name[2:]
    if not name or name.startswith("/"):
        fail("archive contains an unsafe path")
    parts = tuple(name.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        fail("archive contains an unsafe path")
    return parts


def inspect(archive: tarfile.TarFile, max_uncompressed: int) -> None:
    entries: set[tuple[str, ...]] = set()
    payload_name: str | None = None
    total_size = 0

    for member in archive:
        if len(entries) >= MAX_MEMBERS:
            fail("archive contains too many entries")
        parts = canonical_parts(member.name)
        if parts in entries:
            fail("archive contains duplicate or colliding entries")
        entries.add(parts)
        if not parts:
            if not member.isdir():
                fail("archive contains an unsafe path")
            continue
        if len(parts) != 1 or parts[0] != "state.db" or not member.isreg():
            fail("archive must contain exactly one bounded state.db regular file")
        if member.size <= 0 or member.size > STATE_DB_MAX_BYTES:
            fail("archive state payload exceeds its bounded size limit")
        if payload_name is not None:
            fail("archive contains more than one state payload")
        total_size += member.size
        if total_size > max_uncompressed:
            fail("archive exceeds the uncompressed state size limit")
        payload_name = parts[0]

    if payload_name is None:
        fail("archive must contain exactly one state.db payload")

def make_parent(target: Path, destination: Path) -> None:
    parent = target.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent.is_dir() or parent.is_symlink() or destination not in (parent, *parent.parents):
        fail("archive extraction escaped its staging directory")


def copy_regular(member: tarfile.TarInfo, archive: tarfile.TarFile, target: Path) -> None:
    source = archive.extractfile(member)
    if source is None:
        fail("archive regular file could not be read")
    remaining = member.size
    try:
        with source, target.open("xb") as output:
            while remaining:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    fail("archive regular file was truncated")
                output.write(chunk)
                remaining -= len(chunk)
        target.chmod(0o600)
    except OSError as error:
        fail(f"could not extract state archive: {error}")


def extract(archive: tarfile.TarFile, destination: Path) -> None:
    for member in archive:
        parts = canonical_parts(member.name)
        if not parts:
            continue
        target = destination.joinpath(*parts)
        if member.isdir():
            try:
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as error:
                fail(f"could not extract state archive: {error}")
            if not target.is_dir() or target.is_symlink():
                fail("archive contains duplicate or colliding entries")
            target.chmod(0o700)
            continue
        make_parent(target, destination)
        copy_regular(member, archive, target)


def reset_stream(stream: BinaryIO) -> None:
    stream.seek(0)


def snapshot_archive(archive_path: Path, destination: Path, max_archive: int) -> Path:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(archive_path, flags)
    except OSError as error:
        fail(f"cannot open archive safely: {error}")

    try:
        snapshot_descriptor, snapshot_name = tempfile.mkstemp(prefix=".kfadapter-archive.", dir=destination.parent)
    except OSError as error:
        os.close(descriptor)
        fail(f"could not reserve a protected archive snapshot: {error}")
    snapshot = Path(snapshot_name)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as source, os.fdopen(snapshot_descriptor, "wb", closefd=True) as output:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                fail("archive does not exist or is not a regular file")
            if metadata.st_size > max_archive:
                fail("archive exceeds the compressed size limit")
            remaining = max_archive + 1
            while remaining:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                output.write(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                fail("archive exceeds the compressed size limit")
        return snapshot
    except (OSError, ArchiveError):
        snapshot.unlink(missing_ok=True)
        raise


def run(archive_path: Path, destination: Path, max_archive: int, max_uncompressed: int) -> None:
    snapshot = snapshot_archive(archive_path, destination, max_archive)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(snapshot, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            with tarfile.open(fileobj=stream, mode="r|gz") as tar:
                inspect(tar, max_uncompressed)
            reset_stream(stream)
            with tarfile.open(fileobj=stream, mode="r|gz") as tar:
                extract(tar, destination)
    except (tarfile.TarError, EOFError, OSError) as error:
        fail(f"archive is not a valid bounded gzip tar file: {error}")
    finally:
        snapshot.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--max-archive-bytes", required=True)
    parser.add_argument("--max-uncompressed-bytes", required=True)
    args = parser.parse_args()

    max_archive = positive_limit(args.max_archive_bytes, "--max-archive-bytes")
    max_uncompressed = positive_limit(args.max_uncompressed_bytes, "--max-uncompressed-bytes")
    if not args.destination.is_dir() or args.destination.is_symlink():
        fail("restore staging directory is invalid")
    if any(args.destination.iterdir()):
        fail("restore staging directory must be empty")
    run(args.archive, args.destination, max_archive, max_uncompressed)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArchiveError as error:
        print(f"restore-state: {error}", file=sys.stderr)
        raise SystemExit(1)
