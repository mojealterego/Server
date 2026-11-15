#!/usr/bin/env python3
"""Safely import the exact verified OMEGA-X v4 source bundle into main.

This script never downloads weights, handles GitHub credentials, or force-pushes.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import zipfile

EXPECTED_ZIP_SHA256 = "c45d249ee11ca6103d970942f943634842779bd8e2bc81d3db9fb3e735be87d8"
ARCHIVE_PREFIX = "OMEGA_STORAGE_AI_v4.0.0/"
EXPECTED_FILES = 91


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False,
    )
    if proc.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def validated_entries(archive: Path, *, expected_sha: str = EXPECTED_ZIP_SHA256) -> list[tuple[str, bytes]]:
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected_sha:
        raise ValueError("ZIP checksum mismatch; refusing to import")
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise ValueError("ZIP CRC check failed")
        infos = bundle.infolist()
        if len(infos) != EXPECTED_FILES:
            raise ValueError(f"Archive has {len(infos)} entries; expected {EXPECTED_FILES}")
        entries: dict[str, bytes] = {}
        for info in infos:
            name = info.filename
            if not name.startswith(ARCHIVE_PREFIX):
                raise ValueError(f"Unexpected archive root: {name}")
            relative = name[len(ARCHIVE_PREFIX):]
            path = PurePosixPath(relative)
            if not relative or relative.startswith("/") or ".." in path.parts or "\\" in relative:
                raise ValueError(f"Unsafe archive path: {name}")
            if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError(f"Directory/symlink archive entry forbidden: {name}")
            if any(part in {".git", "secrets", "__pycache__", ".ssh"} for part in path.parts):
                raise ValueError(f"Forbidden archive path: {name}")
            if relative in entries:
                raise ValueError(f"Duplicate archive path: {relative}")
            entries[relative] = bundle.read(info)
        sha_text = entries.pop("SHA256SUMS").decode("utf-8")
        for row in sha_text.splitlines():
            expected, sep, path = row.partition("  ")
            if not sep or path not in entries:
                raise ValueError(f"Invalid SHA256SUMS row: {row[:120]}")
            if hashlib.sha256(entries[path]).hexdigest() != expected:
                raise ValueError(f"File mismatch: {path}")
        if len(sha_text.splitlines()) != len(entries):
            raise ValueError("SHA256SUMS does not cover every file")
        entries["SHA256SUMS"] = sha_text.encode("utf-8")
        return sorted(entries.items())


def import_bundle(archive: Path, repo: Path, *, commit: bool, push: bool) -> int:
    if push and not commit:
        raise ValueError("--push requires --commit")
    if not archive.is_file() or not (repo / ".git").exists():
        raise ValueError("Archive file and Git checkout are both required")
    if git(repo, "branch", "--show-current") != "main":
        raise ValueError("Only main branch is supported")
    if git(repo, "status", "--porcelain"):
        raise ValueError("Working tree must be clean before import")
    entries = validated_entries(archive)
    for name, data in entries:
        target = repo / name
        if target.exists() and target.is_symlink():
            raise ValueError(f"Symlink target forbidden: {name}")
        if target.exists() and target.read_bytes() != data and name != "README.md":
            raise FileExistsError(f"Existing file differs: {name}")
        if not target.parent.resolve().is_relative_to(repo.resolve()):
            raise ValueError(f"Target escapes repository: {name}")
    for name, data in entries:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    git(repo, "add", "--", *[name for name, _ in entries])
    staged = git(repo, "diff", "--cached", "--name-only")
    print(f"Validated {len(entries)} archive files, staged {len(staged.splitlines())} paths")
    if commit and staged:
        git(repo, "commit", "-m", "feat: import verified OMEGA-X v4 PHASESHIFT sources")
    if push:
        git(repo, "push", "origin", "main")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--commit", action="store_true")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    try:
        return import_bundle(args.archive.resolve(), args.repo.resolve(), commit=args.commit, push=args.push)
    except (ValueError, RuntimeError, FileExistsError, OSError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
