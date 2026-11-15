#!/usr/bin/env python3
"""OMEGA-X ATLAS command line interface; Python stdlib only, Termux-compatible."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any
from . import audit, merkle, planner, remote, runner

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / 'catalog' / 'model_roles.json'


def _read_json(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError('Missing, symlinked or oversized JSON input')
    return json.loads(path.read_text(encoding='utf-8'))


def _write_json(path: Path, data: Any) -> None:
    if path.is_symlink() or path.exists():
        raise FileExistsError(f'Refusing to overwrite {path}')
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError('Unsafe output directory')
    encoded = (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise audit.AuditError('Missing HMAC key')
    if path.stat().st_mode & 0o077:
        raise audit.AuditError('HMAC key permissions must be 0600')
    key = path.read_bytes()
    if len(key) != 32:
        raise audit.AuditError('HMAC key must be exactly 32 bytes')
    return key


def doctor(directory: Path, catalog: dict[str, dict]) -> dict:
    planner.validate_catalog(catalog)
    directory = Path(directory)
    if not directory.is_dir():
        return {'status': 'MODEL_DIRECTORY_MISSING', 'directory': str(directory), 'items': []}
    found = {}
    for p in directory.iterdir():
        if p.is_file() and not p.is_symlink():
            found[p.name] = p.stat().st_size
    entries = []
    for model_id, info in sorted(catalog.items()):
        name = info.get('filename', '')
        actual = found.get(name)
        status = 'MISSING' if actual is None else ('SIZE_MATCH_METADATA_ONLY' if actual == info['bytes'] else 'SIZE_MISMATCH')
        entries.append({'model_id': model_id, 'filename': name, 'status': status,
                        'expected_bytes': info['bytes'], 'actual_bytes': actual,
                        'lineage_verified': bool(info.get('lineage_verified', False))})
    return {'status': 'INVENTORIED', 'directory': str(directory), 'items': entries,
            'size_matches': sum(e['status'] == 'SIZE_MATCH_METADATA_ONLY' for e in entries),
            'warning': 'Matching name and size do not establish hash, lineage, compatibility or executability.'}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='OMEGA-X ATLAS: verifiable model logistics and compute placement')
    sub = parser.add_subparsers(dest='command', required=True)
    inv = sub.add_parser('inventory', help='Compare local model files with Drive metadata')
    inv.add_argument('--model-dir', type=Path, required=True)
    inv.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG)
    p = sub.add_parser('plan', help='Deterministic, privacy-aware placement plan')
    p.add_argument('--tasks', type=Path, required=True)
    p.add_argument('--nodes', type=Path, required=True)
    p.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG)
    m = sub.add_parser('manifest', help='Hash large model by chunks and write Merkle manifest')
    m.add_argument('source', type=Path)
    m.add_argument('output', type=Path)
    m.add_argument('--chunk-mib', type=int, default=4)
    rm = sub.add_parser('remote-manifest', help='Stream model from configured Rclone remote, without saving weights')
    rm.add_argument('remote')
    rm.add_argument('output', type=Path)
    rm.add_argument('--expected-bytes', type=int, required=True)
    rm.add_argument('--expected-sha256')
    rm.add_argument('--chunk-mib', type=int, default=4)
    rm.add_argument('--timeout', type=int, default=3600)
    sr = sub.add_parser('stage-remote', help='Fetch only missing blocks using Rclone cat ranges')
    sr.add_argument('remote')
    sr.add_argument('destination', type=Path)
    sr.add_argument('manifest', type=Path)
    sr.add_argument('--chunk-timeout', type=int, default=120)
    v = sub.add_parser('verify-model', help='Verify every byte against Merkle manifest')
    v.add_argument('file', type=Path)
    v.add_argument('manifest', type=Path)
    s = sub.add_parser('stage', help='Resume and verify local/mounted model staging')
    s.add_argument('source', type=Path)
    s.add_argument('destination', type=Path)
    s.add_argument('manifest', type=Path)
    keygen = sub.add_parser('audit-keygen', help='Create local 0600 HMAC key (never package it)')
    keygen.add_argument('key', type=Path)
    attest = sub.add_parser('attest', help='Append authenticated execution record')
    attest.add_argument('--log', type=Path, required=True)
    attest.add_argument('--key', type=Path, required=True)
    attest.add_argument('--record', type=Path, required=True)
    attest.add_argument('--output', type=Path)
    verify = sub.add_parser('verify-audit', help='Verify hash chain and HMAC')
    verify.add_argument('--log', type=Path, required=True)
    verify.add_argument('--key', type=Path, required=True)
    verify.add_argument('--outputs', action='store_true')
    verify.add_argument('--expected-head', help='Previously anchored audit chain head (detects truncation)')
    run = sub.add_parser('run-local', help='Call a verified local llama-server ID and audit output')
    run.add_argument('--prompt-file', type=Path, required=True)
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--model-id', required=True)
    run.add_argument('--url', default='http://127.0.0.1:8082')
    run.add_argument('--log', type=Path, required=True)
    run.add_argument('--key', type=Path, required=True)
    run.add_argument('--max-tokens', type=int, default=256)
    run.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args(argv)
    try:
        if args.command == 'inventory':
            result = doctor(args.model_dir, _read_json(args.catalog))
        elif args.command == 'plan':
            result = planner.plan(_read_json(args.tasks), _read_json(args.nodes), _read_json(args.catalog))
        elif args.command == 'manifest':
            result = merkle.make_manifest(args.source, chunk_size=args.chunk_mib * 1024 * 1024)
            _write_json(args.output, result)
        elif args.command == 'remote-manifest':
            result = remote.make_remote_manifest(args.remote, args.expected_bytes, chunk_size=args.chunk_mib * 1024 * 1024, timeout=args.timeout)
            if args.expected_sha256 and result['sha256'] != args.expected_sha256.lower():
                raise ValueError('Remote model SHA-256 differs from expected hash')
            _write_json(args.output, result)
        elif args.command == 'stage-remote':
            result = remote.stage_remote(args.remote, args.destination, _read_json(args.manifest))
        elif args.command == 'verify-model':
            ok = merkle.verify_file(args.file, _read_json(args.manifest))
            result = {'verified': ok}
            if not ok:
                print(json.dumps(result), file=sys.stderr)
                return 1
        elif args.command == 'stage':
            result = merkle.stage_file(args.source, args.destination, _read_json(args.manifest))
        elif args.command == 'audit-keygen':
            audit.create_key(args.key)
            result = {'created': True, 'path': str(args.key), 'mode': '0600'}
        elif args.command == 'attest':
            result = audit.append_record(args.log, _key(args.key), _read_json(args.record, max_bytes=16384), output=args.output)
        elif args.command == 'run-local':
            if args.prompt_file.is_symlink() or not args.prompt_file.is_file() or args.prompt_file.stat().st_size > 32768:
                raise ValueError('Unsafe prompt file')
            result = runner.run_local_chat(args.prompt_file.read_text(encoding='utf-8'), args.output, args.model_id, args.url, args.log, _key(args.key), max_tokens=args.max_tokens, timeout=args.timeout)
        elif args.command == 'verify-audit':
            result = audit.verify_log(args.log, _key(args.key), verify_outputs=args.outputs, expected_head=args.expected_head)
        else:
            parser.error('Unknown command')
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
        print(f'ATLAS ERROR: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
