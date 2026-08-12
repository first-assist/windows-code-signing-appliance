#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import tarfile
from pathlib import Path

LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
INVENTORY_LINE = re.compile(
    r"([0-9a-f]{64}) ([1-9][0-9]{0,9}) "
    r"((?:Gateway|Worker|config|installer)/[A-Za-z0-9._/-]+|profiles/profile-set\.lock|deployment\.txt)"
)
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 256


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def direct_file(path: Path) -> os.stat_result:
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or path.is_symlink()
    ):
        raise RuntimeError("A release source is not a direct single-link regular file")
    return value


def read_inventory(root: Path) -> list[tuple[str, int, str, Path]]:
    inventory = root / "release-inventory.txt"
    direct_file(inventory)
    raw = inventory.read_bytes()
    if not raw or len(raw) > 1024 * 1024 or b"\r" in raw or not raw.endswith(b"\n"):
        raise RuntimeError("The release inventory is not canonical")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("The release inventory is not ASCII") from exc
    entries: list[tuple[str, int, str, Path]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = INVENTORY_LINE.fullmatch(line)
        if match is None:
            raise RuntimeError("The release inventory has an invalid entry")
        digest, length_text, relative = match.groups()
        if relative in seen or "//" in relative or ".." in relative.split("/"):
            raise RuntimeError("The release inventory is ambiguous")
        seen.add(relative)
        path = root.joinpath(*relative.split("/"))
        value = direct_file(path)
        length = int(length_text)
        if value.st_size != length or sha256_file(path) != digest:
            raise RuntimeError("A release source does not match its inventory")
        entries.append((digest, length, relative, path))
    if not 5 <= len(entries) <= MAX_ENTRIES:
        raise RuntimeError("The release inventory count is invalid")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "release-inventory.txt"
    }
    if actual != seen:
        raise RuntimeError("The release source contains unexpected or missing files")
    return entries


def create_archive(root: Path, output: Path) -> str:
    if output.exists():
        raise RuntimeError("The release archive already exists")
    entries = read_inventory(root)
    ordered = [
        ("release-inventory.txt", root / "release-inventory.txt"),
        *((relative, path) for _, _, relative, path in entries),
    ]
    with tarfile.open(output, "x", format=tarfile.USTAR_FORMAT) as archive:
        for relative, path in sorted(ordered):
            value = direct_file(path)
            info = tarfile.TarInfo(relative)
            info.size = value.st_size
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.type = tarfile.REGTYPE
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    if output.stat().st_size > MAX_PACKAGE_BYTES:
        output.unlink()
        raise RuntimeError("The release archive is oversized")
    return sha256_file(output)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    root = Path(arguments.package_root).resolve(strict=True)
    output = Path(arguments.output).resolve()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("The release source root is invalid")
    print(create_archive(root, output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
