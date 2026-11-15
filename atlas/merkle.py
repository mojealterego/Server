"""Bounded-memory, independently verifiable chunk staging for model artifacts.

This is file-based resumable staging, not remote mmap or live tensor paging.
A destination is published only after full SHA-256 and Merkle verification.
"""
from __future__ import annotations
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
from typing import Any

HEX64 = re.compile(r'^[a-f0-9]{64}$')
DEFAULT_CHUNK = 4 * 1024 * 1024
MAX_CHUNKS = 2_000_000

class ManifestError(ValueError):
    pass


def _digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _merkle_root(chunks: list[str]) -> str:
    if not chunks:
        return _digest(b'')
    level = [bytes.fromhex(d) for d in chunks]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b'\x01' + level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _check_regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f'Expected regular, non-symlink file: {path}')


def make_manifest(source: Path, *, chunk_size: int = DEFAULT_CHUNK) -> dict[str, Any]:
    source = Path(source)
    _check_regular(source)
    if type(chunk_size) is not int or not 64 <= chunk_size <= 64 * 1024 * 1024:
        raise ManifestError('chunk_size outside 64..67108864 bytes')
    size = source.stat().st_size
    if math.ceil(size / chunk_size) > MAX_CHUNKS:
        raise ManifestError('Too many chunks for manifest')
    full = hashlib.sha256()
    chunks: list[str] = []
    with source.open('rb') as file:
        while data := file.read(chunk_size):
            full.update(data)
            chunks.append(_digest(data))
    if source.stat().st_size != size:
        raise ManifestError('Source size changed while hashing')
    return {'schema': 'omega.atlas.merkle.v1', 'filename': source.name,
            'size_bytes': size, 'chunk_size': chunk_size, 'chunks': chunks,
            'sha256': full.hexdigest(), 'merkle_root': _merkle_root(chunks)}


def validate_manifest(m: dict[str, Any]) -> None:
    if not isinstance(m, dict) or set(m) != {'schema', 'filename', 'size_bytes', 'chunk_size', 'chunks', 'sha256', 'merkle_root'}:
        raise ManifestError('Unexpected manifest fields')
    if m['schema'] != 'omega.atlas.merkle.v1':
        raise ManifestError('Unsupported manifest schema')
    if not isinstance(m['filename'], str) or not m['filename'] or '/' in m['filename'] or '\\' in m['filename'] or m['filename'] in ('.', '..'):
        raise ManifestError('Unsafe filename')
    size, step = m['size_bytes'], m['chunk_size']
    if type(size) is not int or size < 0 or type(step) is not int or not 64 <= step <= 64 * 1024 * 1024:
        raise ManifestError('Invalid size or chunk size')
    expected = math.ceil(size / step)
    if expected > MAX_CHUNKS or not isinstance(m['chunks'], list) or len(m['chunks']) != expected:
        raise ManifestError('Invalid chunk count')
    if any(not isinstance(x, str) or not HEX64.fullmatch(x) for x in [*m['chunks'], m['sha256'], m['merkle_root']]):
        raise ManifestError('Invalid SHA-256 encoding')
    if _merkle_root(m['chunks']) != m['merkle_root']:
        raise ManifestError('Merkle root mismatch')


def verify_file(path: Path, manifest: dict[str, Any]) -> bool:
    validate_manifest(manifest)
    _check_regular(Path(path))
    if Path(path).stat().st_size != manifest['size_bytes']:
        return False
    full = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for expected in manifest['chunks']:
            data = handle.read(manifest['chunk_size'])
            if not data or _digest(data) != expected:
                return False
            full.update(data)
        if handle.read(1):
            return False
    return full.hexdigest() == manifest['sha256']


def _fsync_dir(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def stage_from_reader(dest: Path, manifest: dict[str, Any], read_chunk) -> dict[str, Any]:
    """Stage a model from an offset/length reader; no-overwrite atomic publication.

    read_chunk(offset, length) must return exactly that many verified source bytes.
    Readers can be local files or authenticated Rclone range reads.
    """
    validate_manifest(manifest)
    dest = Path(dest)
    if not dest.parent.is_dir() or dest.parent.is_symlink():
        raise ManifestError('Destination parent must be a real directory')
    lock_path = dest.with_name(dest.name + '.omega-lock')
    if lock_path.is_symlink():
        raise ManifestError('Unsafe lock symlink')
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink():
                raise ManifestError('Destination symlink rejected')
            if verify_file(dest, manifest):
                return {'status': 'ALREADY_PRESENT', 'copied_chunks': 0,
                        'reused_chunks': len(manifest['chunks']), 'sha256': manifest['sha256']}
            raise FileExistsError('Destination exists with different content')
        partial = dest.with_name(dest.name + '.omega-part')
        if partial.is_symlink():
            raise ManifestError('Partial file symlink rejected')
        fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        copied, reused = 0, 0
        try:
            st = os.fstat(fd)
            if not os.path.isfile(partial) or st.st_nlink != 1:
                raise ManifestError('Partial target is not a private regular file')
            current = st.st_size
            if current > manifest['size_bytes']:
                raise ManifestError('Partial file larger than manifest')
            for i, expected in enumerate(manifest['chunks']):
                off = i * manifest['chunk_size']
                n = min(manifest['chunk_size'], manifest['size_bytes'] - off)
                if current >= off + n and _digest(os.pread(fd, n, off)) == expected:
                    reused += 1
                    continue
                data = read_chunk(off, n)
                if len(data) != n or _digest(data) != expected:
                    raise ManifestError(f'Source chunk {i} does not match trusted manifest')
                written = 0
                while written < n:
                    count = os.pwrite(fd, data[written:], off + written)
                    if count <= 0:
                        raise OSError('Short write during staging')
                    written += count
                copied += 1
            os.fsync(fd)
        finally:
            os.close(fd)
        if not verify_file(partial, manifest):
            raise ManifestError('Staged file failed full integrity verification')
        # Fail closed when hard links are unavailable (e.g. some Android FUSE mounts).
        os.link(partial, dest, follow_symlinks=False)
        _fsync_dir(dest.parent)
        partial.unlink()
        _fsync_dir(dest.parent)
        return {'status': 'STAGED', 'copied_chunks': copied,
                'reused_chunks': reused, 'sha256': manifest['sha256']}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def stage_file(source: Path, dest: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Resume from a local file, without trusting a filename or a matching size."""
    validate_manifest(manifest)
    source, dest = Path(source), Path(dest)
    _check_regular(source)
    if source.resolve() == dest.resolve():
        raise ManifestError('Source and destination are identical')
    if source.stat().st_size != manifest['size_bytes']:
        raise ManifestError('Source size differs from manifest')
    with source.open('rb') as handle:
        def reader(offset: int, length: int) -> bytes:
            handle.seek(offset)
            return handle.read(length)
        return stage_from_reader(dest, manifest, reader)
