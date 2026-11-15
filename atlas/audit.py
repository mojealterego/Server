"""Locally authenticated, append-only execution records with a hash chain.

HMAC is tamper evidence for holders of the shared secret, NOT a public C2PA
signature, a trusted hardware attestation, or proof a model actually ran.
"""
from __future__ import annotations
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

class AuditError(ValueError):
    pass


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def _sha_file(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise AuditError('Unsafe output path')
    h = hashlib.sha256()
    with path.open('rb') as file:
        while chunk := file.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest(), path.stat().st_size


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 16:
        raise AuditError('HMAC key must contain at least 16 bytes')


def _parse_verify(raw: bytes, key: bytes, verify_outputs: bool = False) -> dict[str, Any]:
    if len(raw) > 32 * 1024 * 1024:
        raise AuditError('Audit log exceeds 32 MiB; rotate and archive with explicit procedure')
    if raw and not raw.endswith(b'\n'):
        raise AuditError('Truncated audit record')
    prev = '0' * 64
    count = 0
    for line in raw.splitlines():
        if len(line) > 32768:
            raise AuditError('Oversized audit record')
        try:
            obj = json.loads(line)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditError('Invalid audit JSON') from exc
        if not isinstance(obj, dict) or set(obj) != {'seq', 'prev', 'payload', 'mac'}:
            raise AuditError('Unexpected audit fields')
        if obj['seq'] != count or obj['prev'] != prev or not isinstance(obj['payload'], dict):
            raise AuditError('Audit chain broken')
        unsigned = {k: obj[k] for k in ('seq', 'prev', 'payload')}
        expected = hmac.new(key, _canon(unsigned), hashlib.sha256).hexdigest()
        if not isinstance(obj['mac'], str) or not hmac.compare_digest(expected, obj['mac']):
            raise AuditError('Audit HMAC mismatch')
        if verify_outputs and 'output_path' in obj['payload']:
            path = Path(obj['payload']['output_path'])
            digest, size = _sha_file(path)
            if digest != obj['payload'].get('output_sha256') or size != obj['payload'].get('output_bytes'):
                raise AuditError('Output integrity mismatch')
        prev = hashlib.sha256(_canon(obj)).hexdigest()
        count += 1
    return {'records': count, 'head': prev, 'verified_outputs': verify_outputs}


def verify_log(path: Path, key: bytes, *, verify_outputs: bool = False, expected_head: str | None = None) -> dict[str, Any]:
    _check_key(key)
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AuditError('Missing or symlinked audit log')
    with path.open('rb') as handle:
        fcntl.flock(handle, fcntl.LOCK_SH)
        result = _parse_verify(handle.read(), key, verify_outputs)
    if expected_head is not None and not hmac.compare_digest(result['head'], expected_head):
        raise AuditError('Audit head mismatch: possible truncation or replacement')
    return result


def append_record(path: Path, key: bytes, payload: dict[str, Any], *, output: Path | None = None) -> dict[str, Any]:
    _check_key(key)
    if not isinstance(payload, dict) or not isinstance(payload.get('stage'), str) or not isinstance(payload.get('status'), str):
        raise AuditError('Missing stage or status')
    if len(_canon(payload)) > 16384:
        raise AuditError('Oversized payload')
    sanitized = dict(payload)
    if 'prompt' in sanitized:
        prompt = sanitized.pop('prompt')
        if not isinstance(prompt, str):
            raise AuditError('Prompt must be text')
        sanitized['prompt_sha256'] = hashlib.sha256(prompt.encode('utf-8')).hexdigest()
    if output is not None:
        output = Path(output)
        digest, size = _sha_file(output)
        sanitized.update(output_path=str(output.resolve()), output_sha256=digest, output_bytes=size)
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise AuditError('Unsafe audit log path')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), 'rb') as reader:
            raw = reader.read()
        state = _parse_verify(raw, key)
        unsigned = {'seq': state['records'], 'prev': state['head'], 'payload': sanitized}
        record = {**unsigned, 'mac': hmac.new(key, _canon(unsigned), hashlib.sha256).hexdigest()}
        line = _canon(record) + b'\n'
        if len(line) > 32768 or len(raw) + len(line) > 32 * 1024 * 1024:
            raise AuditError('Audit record or log exceeds limit')
        os.lseek(fd, 0, os.SEEK_END)
        if os.write(fd, line) != len(line):
            raise OSError('Short audit log write')
        os.fsync(fd)
        return record
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def create_key(path: Path) -> None:
    path = Path(path)
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise AuditError('Unsafe key location')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(os.urandom(32))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
