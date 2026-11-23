"""E21: offline, externally pinned, one-use authorization for SMB recovery.

This does not implement WORM storage, quorum, online failover, or SMB VFS.
The restore is strictly offline and must be run against independently backed-up data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = 'omega.ransomware-recovery-permit.v1'
DOMAIN = b'OMEGA-E21-RESTORE\x00'
HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
NONCE = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z', re.ASCII)
MAX_PERMIT_BYTES = 4096
MAX_SET_BYTES = 32768
MAX_WINDOW_SECONDS = 86400
FIELDS = frozenset({'schema', 'tenant', 'set_sha256', 'checkpoint_tip',
                    'destination', 'nonce', 'issued_at', 'expires_at', 'signature'})


class RecoveryDenied(ValueError):
    """Fail-closed validation or authorization error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryDenied(message)


def canonical(value: dict) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, OverflowError) as exc:
        raise RecoveryDenied('Invalid JSON data') from exc
    require(len(raw) <= MAX_SET_BYTES, 'JSON exceeds size bound')
    return raw


def _unique(pairs):
    doc = {}
    for key, value in pairs:
        require(key not in doc, 'Duplicate JSON field')
        doc[key] = value
    return doc


def _digest(value: str) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def private_dir(directory: Path) -> Path:
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'Unsafe private directory')
    info = directory.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
            'Directory must be privately owned (0700)')
    return directory


def read_private(path: Path, limit: int, *, exact: int | None = None) -> bytes:
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.getuid() and not info.st_mode & 0o077
                and info.st_size <= limit and (exact is None or info.st_size == exact),
                'Unsafe, oversized or non-private file')
        content = os.read(fd, limit + 1)
        require(len(content) == info.st_size, 'File changed during read')
        return content
    finally:
        os.close(fd)


def parse_document(path: Path, *, limit: int) -> dict:
    raw = read_private(path, limit)
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda x: (_ for _ in ()).throw(RecoveryDenied('Nonfinite JSON')))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RecoveryDenied('Invalid JSON document') from exc
    require(type(value) is dict and canonical(value) == raw, 'JSON must be canonical')
    return value


def destination_path(value: str) -> Path:
    require(type(value) is str and 1 <= len(value) <= 1024 and '\x00' not in value,
            'Invalid destination')
    path = Path(value)
    require(path.is_absolute() and str(path) == value and
            os.path.normpath(value) == value and path.parent.resolve() == path.parent,
            'Destination must be absolute, canonical and without symlink ancestors')
    private_dir(path.parent)
    require(not path.exists() and not path.is_symlink(), 'Restore destination already exists')
    return path


def _validate_fields(doc: dict) -> None:
    require(type(doc) is dict and set(doc) == FIELDS and doc['schema'] == SCHEMA,
            'Invalid permit fields or schema')
    require(type(doc['tenant']) is str and IDENTITY.fullmatch(doc['tenant']) is not None,
            'Invalid tenant')
    require(_digest(doc['set_sha256']) and _digest(doc['checkpoint_tip']), 'Invalid pins')
    require(type(doc['nonce']) is str and NONCE.fullmatch(doc['nonce']) is not None,
            'Invalid nonce')
    require(type(doc['destination']) is str and 1 <= len(doc['destination']) <= 1024
            and doc['destination'].startswith('/') and '\x00' not in doc['destination'],
            'Invalid destination field')
    issued, expires = doc['issued_at'], doc['expires_at']
    require(type(issued) is int and type(expires) is int
            and 0 <= issued < expires <= (1 << 63) - 1
            and expires - issued <= MAX_WINDOW_SECONDS, 'Invalid permit time window')
    require(type(doc['signature']) is str and len(doc['signature']) == 128
            and all(c in '0123456789abcdef' for c in doc['signature']),
            'Invalid permit signature encoding')


def issue(key_path: Path, *, tenant: str, set_sha256: str, checkpoint_tip: str,
          destination: str, nonce: str, issued_at: int, expires_at: int) -> dict:
    """Offline signer only: the key must never be on the restore target."""
    raw = read_private(key_path, 32, exact=32)
    unsigned = {'schema': SCHEMA, 'tenant': tenant, 'set_sha256': set_sha256,
                'checkpoint_tip': checkpoint_tip, 'destination': destination,
                'nonce': nonce, 'issued_at': issued_at, 'expires_at': expires_at}
    doc = {**unsigned, 'signature': '0' * 128}
    _validate_fields(doc)
    require(len(canonical(doc)) <= MAX_PERMIT_BYTES, 'Permit too large')
    # Validate destination lexical identity now, but not its existence on offline signer.
    require(os.path.normpath(destination) == destination and destination.startswith('/'),
            'Noncanonical destination')
    try:
        key = Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise RecoveryDenied('Invalid private key') from exc
    doc['signature'] = key.sign(DOMAIN + canonical(unsigned)).hex()
    return doc


def verify_permit(doc: dict, public_key: bytes, *, tenant: str, set_sha256: str,
                  checkpoint_tip: str, destination: str, now: int) -> str:
    _validate_fields(doc)
    require(type(public_key) is bytes and len(public_key) == 32, 'Missing public key pin')
    require(type(now) is int and 0 <= now <= (1 << 63)-1, 'Invalid current time')
    require(doc['tenant'] == tenant and doc['set_sha256'] == set_sha256
            and doc['checkpoint_tip'] == checkpoint_tip and doc['destination'] == destination,
            'Permit target, tenant or independent pin mismatch')
    require(doc['issued_at'] <= now <= doc['expires_at'], 'Permit is not currently valid')
    unsigned = {k: v for k, v in doc.items() if k != 'signature'}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(doc['signature']), DOMAIN + canonical(unsigned))
    except InvalidSignature as exc:
        raise RecoveryDenied('Invalid recovery permit signature') from exc
    return hashlib.sha256(canonical(doc)).hexdigest()


def _sync(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def claim_once(claims_dir: Path, receipt_sha256: str, permit: dict,
               recovery_public_key: bytes) -> None:
    """Durable fail-closed claim before any remote reads or disk restoration.

    A failed/uncertain restoration remains claimed; retry requires a new permit.
    """
    claims_dir = private_dir(claims_dir)
    require(_digest(receipt_sha256), 'Invalid claim key')
    # Fence the nonce, not just the signed permit bytes: a second differently
    # signed permit using the same nonce must not bypass replay protection.
    require(type(recovery_public_key) is bytes and len(recovery_public_key) == 32,
            'Invalid signer identity')
    replay_id = hashlib.sha256(DOMAIN + recovery_public_key +
        permit['tenant'].encode('ascii') + bytes.fromhex(permit['nonce'])).hexdigest()
    path = claims_dir / (replay_id + '.claim')
    raw = canonical({'permit_sha256': receipt_sha256,
                     'set_sha256': permit['set_sha256'], 'checkpoint_tip': permit['checkpoint_tip'],
                     'destination': permit['destination'], 'tenant': permit['tenant']})
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError as exc:
        raise RecoveryDenied('Authorization already used or outcome uncertain') from exc
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        _sync(claims_dir)
    except BaseException:
        # Never delete a possibly durable claim after an ambiguous write.
        raise


def restore_authorized(*, permit: dict, recovery_public_key: bytes,
                       authority_public_key: bytes, checkpoint_dir: Path,
                       checkpoint_tip: str, tenant: str, recovery_set: dict,
                       set_sha256: str, destination: Path, claims_dir: Path,
                       retrieve, inspect, restore, now: int | None = None) -> dict:
    """Require verified E20 history and one-use E21 permit before real E15/SMB restore."""
    from .authority_checkpoint import verify as verify_chain
    from .storage_recovery import validate, restore_set
    require(_digest(checkpoint_tip) and _digest(set_sha256), 'Invalid external hash pins')
    require(type(tenant) is str and IDENTITY.fullmatch(tenant) is not None, 'Invalid tenant')
    require(type(recovery_public_key) is bytes and type(authority_public_key) is bytes
            and recovery_public_key != authority_public_key,
            'Recovery and checkpoint authorization keys must be separate')
    dest = destination_path(str(destination))
    private_dir(claims_dir)
    validate(recovery_set, set_sha256)  # Exactly three shares, correct pinned receipt.
    effective_now = int(time.time()) if now is None else now
    permit_hash = verify_permit(permit, recovery_public_key, tenant=tenant,
                                set_sha256=set_sha256, checkpoint_tip=checkpoint_tip,
                                destination=str(dest), now=effective_now)
    chain = verify_chain(checkpoint_dir, authority_public_key, checkpoint_tip)
    require(chain['digest'] == checkpoint_tip and chain['length'] > 0,
            'No externally pinned authority history')
    require(chain.get('tenant') == tenant,
            'Checkpoint tenant differs from authorized recovery tenant')
    # Claim before remote I/O. There is intentionally no automatic reuse after failure.
    claim_once(claims_dir, permit_hash, permit, recovery_public_key)
    result = restore_set(recovery_set, set_sha256, dest,
                         retrieve=retrieve, inspect=inspect, restore=restore)
    require(result['status'] == 'RECOVERED_OFFLINE' and
            result['set_sha256'] == set_sha256, 'Unexpected restore result')
    return {**result, 'permit_sha256': permit_hash,
            'checkpoint_tip': checkpoint_tip, 'authorization': 'CONSUMED'}


def _pub(hex_key: str) -> bytes:
    require(type(hex_key) is str and len(hex_key) == 64
            and all(c in '0123456789abcdef' for c in hex_key),
            'Invalid independently pinned Ed25519 public key')
    return bytes.fromhex(hex_key)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    signer = sub.add_parser('issue', help='Run on an isolated offline signer')
    signer.add_argument('--key', required=True, type=Path)
    signer.add_argument('--tenant', required=True)
    signer.add_argument('--set-sha256', required=True)
    signer.add_argument('--checkpoint-tip', required=True)
    signer.add_argument('--dest', required=True)
    signer.add_argument('--nonce', required=True)
    signer.add_argument('--issued-at', required=True, type=int)
    signer.add_argument('--expires-at', required=True, type=int)
    recovery = sub.add_parser('restore', help='Offline restore; never live SMB failover')
    for name in ('permit', 'set', 'vault', 'checkpoint-dir', 'claims-dir', 'dest'):
        recovery.add_argument('--' + name, required=True, type=Path)
    for name in ('tenant', 'set-sha256', 'checkpoint-tip', 'recovery-public-key', 'authority-public-key'):
        recovery.add_argument('--' + name, required=True)
    recovery.add_argument('--remote', required=True, action='append')
    args = parser.parse_args(argv)
    try:
        if args.action == 'issue':
            result = issue(args.key, tenant=args.tenant, set_sha256=args.set_sha256,
                           checkpoint_tip=args.checkpoint_tip, destination=args.dest,
                           nonce=args.nonce, issued_at=args.issued_at, expires_at=args.expires_at)
        else:
            from .artifacts import ArtifactStore
            from .storage_snapshot import encrypted_replicas, retrieve, load_index, restore
            private_dir(args.vault.parent)
            recovery_set = parse_document(args.set, limit=MAX_SET_BYTES)
            permit = parse_document(args.permit, limit=MAX_PERMIT_BYTES)
            # Initialize the storage data plane only AFTER authorization.
            storage = {}
            def handles():
                if not storage:
                    storage['cas'] = ArtifactStore(args.vault)
                    storage['replicas'] = encrypted_replicas(args.remote)
                return storage['cas'], storage['replicas']
            def fetch(sha, pin):
                cas, replicas = handles()
                return retrieve(cas, sha, pin, replicas)
            def index(sha):
                cas, _ = handles()
                return load_index(cas, sha)
            def recover(sha, target):
                cas, _ = handles()
                return restore(cas, sha, target)
            result = restore_authorized(
                permit=permit, recovery_public_key=_pub(args.recovery_public_key),
                authority_public_key=_pub(args.authority_public_key),
                checkpoint_dir=args.checkpoint_dir, checkpoint_tip=args.checkpoint_tip,
                tenant=args.tenant, recovery_set=recovery_set, set_sha256=args.set_sha256,
                destination=args.dest, claims_dir=args.claims_dir,
                retrieve=fetch, inspect=index, restore=recover)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RecoveryDenied, OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        print('E21 RECOVERY DENIED: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
