"""Rclone-backed, verifiable remote model fingerprinting and range staging.

Reads authenticated Rclone remotes configured by the operator. Never embeds
Google credentials, executes a shell, or treats Drive file names as model hashes.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
from typing import Any
from .merkle import ManifestError, _digest, _merkle_root, stage_from_reader, validate_manifest

REMOTE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]*:([A-Za-z0-9_][A-Za-z0-9_ .()/+-]*/)*[A-Za-z0-9_][A-Za-z0-9_ .()+-]*$')


def validate_remote(remote: str) -> str:
    if not isinstance(remote, str) or not REMOTE_RE.fullmatch(remote):
        raise ValueError('Expected a named Rclone remote with a relative file path')
    path = remote.split(':', 1)[1]
    if any(seg in ('', '.', '..') for seg in path.split('/')) or len(remote) > 1024:
        raise ValueError('Unsafe Rclone path')
    return remote


def _read_remote_stream(remote: str, *, rclone: str, env: dict | None, timeout: int,
                        expected_size: int, chunk_size: int) -> tuple[list[str], str]:
    """Read remote sequentially once, bounded memory, with an overall timeout."""
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen([rclone, 'cat', remote], stdout=subprocess.PIPE,
                                stderr=err, stdin=subprocess.DEVNULL, env=env)
        full = hashlib.sha256()
        chunks: list[str] = []
        pending = bytearray()
        total = 0
        deadline = time.monotonic() + timeout
        try:
            assert proc.stdout is not None
            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Rclone stream timeout')
                    if not sel.select(remaining):
                        raise TimeoutError('Rclone stream timeout')
                    data = os.read(proc.stdout.fileno(), min(chunk_size, 1024 * 1024))
                    if not data:
                        break
                    total += len(data)
                    if total > expected_size:
                        raise ManifestError('Remote returned more bytes than declared')
                    full.update(data)
                    pending.extend(data)
                    while len(pending) >= chunk_size:
                        chunks.append(_digest(bytes(pending[:chunk_size])))
                        del pending[:chunk_size]
                if pending:
                    chunks.append(_digest(bytes(pending)))
            finally:
                sel.close()
            remaining = deadline - time.monotonic()
            if proc.wait(timeout=max(0.1, remaining)) != 0:
                raise RuntimeError('Rclone remote read failed; check configuration and access')
            if total != expected_size:
                raise ManifestError(f'Remote size mismatch: got {total}, expected {expected_size}')
            return chunks, full.hexdigest()
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout:
                proc.stdout.close()


def make_remote_manifest(remote: str, expected_size: int, *, rclone: str = 'rclone',
                         env: dict | None = None, chunk_size: int = 4 * 1024 * 1024,
                         timeout: int = 3600) -> dict[str, Any]:
    validate_remote(remote)
    if type(expected_size) is not int or expected_size < 0 or expected_size > 2**60:
        raise ValueError('Invalid remote size')
    if type(chunk_size) is not int or not 64 <= chunk_size <= 64 * 1024 * 1024:
        raise ValueError('Invalid chunk size')
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('Invalid timeout')
    if (expected_size + chunk_size - 1) // chunk_size > 2_000_000:
        raise ValueError('Too many chunks')
    chunks, sha = _read_remote_stream(remote, rclone=rclone, env=env, timeout=timeout,
                                      expected_size=expected_size, chunk_size=chunk_size)
    manifest = {'schema': 'omega.atlas.merkle.v1', 'filename': remote.rsplit('/', 1)[-1].split(':')[-1],
                'size_bytes': expected_size, 'chunk_size': chunk_size,
                'chunks': chunks, 'sha256': sha, 'merkle_root': _merkle_root(chunks)}
    validate_manifest(manifest)
    return manifest


def stage_remote(remote: str, dest: Path, manifest: dict[str, Any], *, rclone: str = 'rclone',
                 env: dict | None = None, timeout_per_chunk: int = 120, retries: int = 2) -> dict[str, Any]:
    validate_remote(remote)
    validate_manifest(manifest)
    if type(timeout_per_chunk) is not int or not 1 <= timeout_per_chunk <= 3600:
        raise ValueError('Invalid chunk timeout')
    if type(retries) is not int or not 0 <= retries <= 5:
        raise ValueError('Invalid retry count')
    def reader(offset: int, length: int) -> bytes:
        for attempt in range(retries + 1):
            try:
                result = subprocess.run([rclone, 'cat', remote, '--offset', str(offset), '--count', str(length)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                        timeout=timeout_per_chunk, check=False)
                if result.returncode != 0:
                    raise RuntimeError('Rclone ranged read failed')
                if len(result.stdout) != length:
                    raise ManifestError('Remote range length mismatch')
                return result.stdout
            except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
                if attempt == retries:
                    raise RuntimeError(f'Rclone range read failed after {retries+1} attempts') from exc
                time.sleep(min(2.0, 0.25 * 2 ** attempt))
        raise AssertionError('unreachable')
    return stage_from_reader(Path(dest), manifest, reader)
