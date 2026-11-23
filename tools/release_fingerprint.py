"""Offline source and release-input fingerprint, not an independent signature.

Only the caller's explicit packaging allowlist is fingerprinted. Any release
approval still requires independently trusted source and device evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Callable

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DEFAULT_FILE_LIMIT = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 10_000
READ_CHUNK = 1024 * 1024


class FingerprintError(ValueError):
    """A verified source tree cannot be established."""


def _require(value: bool, reason: str) -> None:
    if not value:
        raise FingerprintError(reason)


def _file_hash(path: Path, max_size: int) -> tuple[bytes, int]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise FingerprintError('Source file is not safely readable') from exc
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                 'Source must be a regular, non-hardlinked file')
        _require(0 <= before.st_size <= max_size, 'Source size limit exceeded')
        digest = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK, max_size - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            _require(consumed <= max_size, 'Source grew beyond size limit')
            digest.update(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        _require(consumed == before.st_size and identity(before) == identity(after),
                 'Source mutated during verification')
        return digest.digest(), consumed
    finally:
        os.close(fd)


def fingerprint(root: Path, allowed: Callable[[Path], bool], *,
                max_file_bytes: int = DEFAULT_FILE_LIMIT) -> dict:
    """Deterministically hash path, size and bytes of every allowlisted input.

    The optional allowlist must exclude this fingerprint's containing report
    (e.g. reports/verification.json) to avoid self-referential hashes.
    """
    root = Path(root)
    _require(root.is_dir() and not root.is_symlink(), 'Invalid checkout root')
    _require(type(max_file_bytes) is int and 1 <= max_file_bytes <= MAX_TOTAL_BYTES,
             'Invalid source bound')
    records = sorted((p for p in root.rglob('*') if allowed(p)),
                     key=lambda p: p.relative_to(root).as_posix())
    _require(0 < len(records) <= MAX_FILES, 'Unexpected source file count')
    total = 0
    tree = hashlib.sha256(b'OMEGA-RELEASE-SOURCE-V1\x00')
    for path in records:
        rel = path.relative_to(root).as_posix().encode('utf-8')
        _require(0 < len(rel) <= 4096, 'Invalid source relative path')
        file_digest, size = _file_hash(path, max_file_bytes)
        total += size
        _require(total <= MAX_TOTAL_BYTES, 'Source tree exceeds total size limit')
        tree.update(len(rel).to_bytes(4, 'big'))
        tree.update(rel)
        tree.update(size.to_bytes(8, 'big'))
        tree.update(file_digest)
    tree.update(len(records).to_bytes(8, 'big'))
    return {'sha256': tree.hexdigest(), 'files': len(records)}


def verify_pin(root: Path, allowed: Callable[[Path], bool], pin: dict) -> dict:
    """Reject missing/stale report pins, even when a prior test report said PASS."""
    _require(type(pin) is dict and set(pin) == {'sha256', 'files'},
             'Missing or malformed verified source pin')
    _require(type(pin['sha256']) is str and HEX64.fullmatch(pin['sha256']) is not None
             and type(pin['files']) is int and 0 < pin['files'] <= MAX_FILES,
             'Invalid verified source pin')
    current = fingerprint(root, allowed)
    _require(current['files'] == pin['files'] and
             hmac.compare_digest(current['sha256'], pin['sha256']),
             'Source tree changed since verification; rerun the full tests')
    return current
