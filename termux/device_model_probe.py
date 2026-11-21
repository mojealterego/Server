#!/usr/bin/env python3
"""Read-only device/model preflight: evidence, not inference or benchmark certification.

This tool never changes weights, launches a model, installs dependencies, modifies
Android settings, or marks S24/mobile E2E as passed. It uses the existing
model_inventory parser and deliberately does not infer filenames or mmproj lineage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from typing import Any, Callable

EXTENSIONS = frozenset({'.gguf', '.safetensors'})
MAX_MODELS = 256
READ_CHUNK = 4 * 1024 * 1024


def _sample_fd(fd: int, size: int, hash_file: bool) -> tuple[bool, str | None]:
    if size <= 0:
        raise ValueError('Empty model file')
    # Touch one mapped page only. This is a capability probe, not an assertion
    # of zero-copy behaviour, low-RSS residency, or inference performance.
    with mmap.mmap(fd, min(size, mmap.PAGESIZE), access=mmap.ACCESS_READ) as mapping:
        _ = mapping[0]
    if not hash_file:
        return True, None
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while buf := os.read(fd, READ_CHUNK):
        h.update(buf)
    return True, h.hexdigest()


def _model_metadata(path: Path) -> dict[str, Any]:
    # Import existing bounded GGUF v2/v3 + Safetensors parser, not a fork.
    from model_inventory import inspect_binary_header
    return inspect_binary_header(path)


def probe(directory: Path, *, expected_count: int | None = None,
          sha256: bool = False, metadata_reader: Callable[[Path], dict[str, Any]] | None = None,
          get_affinity: Callable[[], set[int]] | None = None,
          clock: Callable[[], float] = time.time) -> dict[str, Any]:
    if type(sha256) is not bool or (expected_count is not None and
        (type(expected_count) is not int or not 1 <= expected_count <= MAX_MODELS)):
        raise ValueError('Invalid probe options')
    directory = Path(directory).expanduser()
    if not directory.is_dir():
        raise ValueError('Model directory is not accessible')
    reader = metadata_reader or _model_metadata
    errors: list[str] = []
    models: list[dict[str, Any]] = []
    candidates = sorted((p for p in directory.iterdir() if p.suffix.lower() in EXTENSIONS),
                        key=lambda p: p.name.casefold())
    if not candidates or len(candidates) > MAX_MODELS:
        raise ValueError('Expected 1..256 model files')
    if expected_count is not None and len(candidates) != expected_count:
        errors.append('Model count mismatch: observed %d, expected %d' % (len(candidates), expected_count))
    for path in candidates:
        row: dict[str, Any] = {'filename': path.name}
        fd: int | None = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('Not a regular file')
            if before.st_size <= 0:
                raise ValueError('Empty model')
            hdr = reader(path)
            if not isinstance(hdr, dict) or hdr.get('format') not in ('gguf', 'safetensors'):
                raise ValueError('Unsupported model header')
            mapped, hexdigest = _sample_fd(fd, before.st_size, sha256)
            after = os.fstat(fd)
            now = os.stat(path, follow_symlinks=False)
            for other in (after, now):
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    other.st_dev, other.st_ino, other.st_size, other.st_mtime_ns):
                    raise ValueError('Model changed during probe')
            row.update(status='PASS_READONLY_PROBE', bytes=before.st_size,
                       format=hdr['format'], architecture=str(hdr.get('architecture', 'unknown')),
                       tensor_count=hdr.get('tensor_count'), mmap_read_page=mapped,
                       sha256=hexdigest)
        except (OSError, ValueError, BufferError, RuntimeError, UnicodeError) as exc:
            row.update(status='FAIL', error=type(exc).__name__ + ': ' + str(exc))
            errors.append('Model probe failed: ' + path.name)
        finally:
            if fd is not None:
                os.close(fd)
        models.append(row)
    try:
        allowed = sorted((get_affinity or (lambda: os.sched_getaffinity(0)))())
    except (OSError, AttributeError):
        allowed = None
    return {
        'schema': 'omega.device-model-preflight.v1',
        'status': 'PASS_READONLY_PROBES' if not errors else 'FAIL',
        'observed_unix_seconds': int(clock()),
        'model_directory': str(directory),
        'observed_file_count': len(models),
        'expected_file_count': expected_count,
        'process_allowed_cpus': allowed,
        'models': models,
        'errors': errors,
        'evidence_scope': {
            'mmap_first_page_read': True,
            'full_file_sha256': sha256,
            'mmproj_lineage_compatibility': 'NOT_VERIFIED',
            'actual_llm_inference': 'NOT_RUN',
            'Wan_LTX_inference': 'NOT_RUN',
            'OpenCL_NPU_acceleration': 'NOT_RUN',
            'TTFT_and_thermal_benchmark': 'NOT_RUN',
            'S24_mobile_e2e': 'NOT_RUN',
        },
        'note': 'Read-only parse and page mapping do not prove zero-copy, CPU pinning of llama-server, or device certification.'
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dir', type=Path)
    ap.add_argument('--expect-count', type=int)
    ap.add_argument('--sha256', action='store_true', help='Stream full weights; may take significant time')
    ap.add_argument('--json-out', type=Path)
    args = ap.parse_args(argv)
    try:
        from model_inventory import resolve_default_model_dir
        report = probe(args.dir or resolve_default_model_dir(),
                       expected_count=args.expect_count, sha256=args.sha256)
    except (ValueError, OSError, ImportError) as exc:
        print('MODEL PREFLIGHT FAILED: ' + str(exc), file=sys.stderr)
        return 2
    raw = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    if args.json_out:
        # Keep the report private; do not claim an existing report is attested.
        output = args.json_out
        if not output.parent.is_dir() or output.is_symlink():
            print('Unsafe report destination', file=sys.stderr)
            return 2
        name: str | None = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', prefix='.omega-probe-',
                                             dir=output.parent, delete=False) as tmp:
                name = tmp.name
                os.fchmod(tmp.fileno(), 0o600)
                tmp.write(raw)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(name, output)
        finally:
            if name is not None and os.path.exists(name):
                os.unlink(name)
    else:
        print(raw, end='')
    return 0 if report['status'] == 'PASS_READONLY_PROBES' else 1


if __name__ == '__main__':
    sys.exit(main())
