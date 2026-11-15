"""Durable, local SHA-256 content-addressed artifact storage.

Security boundary: one trusted local OS user, private root (0700), regular files
only, never follows a symlink in the object store, verifies before restoration.
A durable CAS is NOT distributed replication, remote attestation, or a global
exactly-once guarantee. Receipts are content integrity claims, not signatures.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat

CHUNK = 1024 * 1024
HEX_SHA256 = re.compile(r'^[0-9a-f]{64}$')
READ_FLAGS = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)

class ArtifactError(ValueError):
    pass


def _private_dir(p: Path) -> None:
    if p.is_symlink() or not p.is_dir():
        raise ArtifactError('Expected a non-symlink directory')
    info = p.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ArtifactError('CAS directories must be owned by the current user and private (0700)')


def _sync_directory(p: Path) -> None:
    # A filesystem can reject directory fsync; do not silently assert durability.
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _check_digest(value: str) -> None:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise ArtifactError('Invalid SHA-256 digest')


def _open_regular(path: Path):
    try:
        fd = os.open(path, READ_FLAGS)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ArtifactError('Object is not a regular file')
    except OSError as exc:
        raise ArtifactError('Cannot open regular file safely') from exc
    except BaseException:
        os.close(fd)
        raise
    return fd, before


def _check_unchanged(fd, before, size):
    after = os.fstat(fd)
    if (before.st_size != size or after.st_size != size or
        before.st_mtime_ns != after.st_mtime_ns or
        before.st_ino != after.st_ino or before.st_dev != after.st_dev):
        raise ArtifactError('File changed during read')


class ArtifactStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=False)
        _private_dir(self.root)
        self.objects = self.root / 'objects'
        if not self.objects.exists():
            self.objects.mkdir(mode=0o700)
            _sync_directory(self.root)
        _private_dir(self.objects)

    def _path(self, digest: str) -> Path:
        _check_digest(digest)
        _private_dir(self.objects)
        return self.objects / digest

    def _scan(self, path: Path, *, max_bytes: int) -> tuple[str,int]:
        fd, before = _open_regular(path)
        try:
            h = hashlib.sha256()
            size = 0
            with os.fdopen(os.dup(fd),'rb') as src:
                while data := src.read(CHUNK):
                    size += len(data)
                    if size > max_bytes:
                        raise ArtifactError('Artifact exceeds the configured limit')
                    h.update(data)
            _check_unchanged(fd,before,size)
            return h.hexdigest(),size
        finally:
            os.close(fd)

    def put(self, source: Path, *, max_bytes: int = 16*1024**3) -> dict:
        if type(max_bytes) is not int or max_bytes < 0:
            raise ArtifactError('Invalid maximum artifact size')
        _private_dir(self.objects)
        fd, before = _open_regular(Path(source))
        tmp = self.objects / ('.incoming-' + secrets.token_hex(20))
        staged = False
        try:
            try:
                output_fd = os.open(tmp, WRITE_FLAGS, 0o600)
                staged = True
            except OSError as exc:
                raise ArtifactError('Cannot stage artifact') from exc
            h=hashlib.sha256(); size=0
            with os.fdopen(os.dup(fd),'rb') as src, os.fdopen(output_fd,'wb') as dest:
                while data := src.read(CHUNK):
                    size += len(data)
                    if size > max_bytes:
                        raise ArtifactError('Artifact exceeds the configured limit')
                    h.update(data)
                    dest.write(data)
                dest.flush()
                os.fsync(dest.fileno())
            _check_unchanged(fd,before,size)
            digest=h.hexdigest()
            target=self._path(digest)
            try:
                os.link(tmp,target,follow_symlinks=False)
            except FileExistsError:
                # The existing object may be a symlink or corrupt; fail closed.
                old_digest,old_size=self._scan(target,max_bytes=max_bytes)
                if old_digest!=digest or old_size!=size:
                    raise ArtifactError('Existing content-addressed object is corrupt')
            _sync_directory(self.objects)
            return {'sha256':digest,'size_bytes':size}
        finally:
            os.close(fd)
            if staged:
                tmp.unlink(missing_ok=True)

    def verify(self, digest: str) -> bool:
        target=self._path(digest)
        got,_=self._scan(target,max_bytes=2**63-1)
        if got!=digest:
            raise ArtifactError('SHA-256 content mismatch')
        return True

    def restore(self, digest: str, destination: Path) -> dict:
        target=self._path(digest)
        destination=Path(destination)
        if destination.parent.is_symlink() or not destination.parent.is_dir():
            raise ArtifactError('Unsafe restoration directory')
        if destination.exists() or destination.is_symlink():
            raise ArtifactError('Restoration cannot overwrite an existing path')
        fd,before=_open_regular(target)
        tmp=destination.parent / ('.omega-restore-' + secrets.token_hex(16))
        staged=False
        try:
            h=hashlib.sha256(); size=0
            try:
                out_fd=os.open(tmp,WRITE_FLAGS,0o600)
                staged=True
            except OSError as exc:
                raise ArtifactError('Cannot stage restoration') from exc
            with os.fdopen(os.dup(fd),'rb') as src, os.fdopen(out_fd,'wb') as dst:
                while data:=src.read(CHUNK):
                    h.update(data);size+=len(data);dst.write(data)
                dst.flush();os.fsync(dst.fileno())
            _check_unchanged(fd,before,size)
            if h.hexdigest()!=digest:
                raise ArtifactError('SHA-256 mismatch while restoring')
            try:
                os.link(tmp,destination,follow_symlinks=False)
            except FileExistsError as exc:
                raise ArtifactError('Restoration target already exists') from exc
            _sync_directory(destination.parent)
            return {'sha256':digest,'size_bytes':size,'destination':str(destination)}
        finally:
            os.close(fd)
            if staged:
                tmp.unlink(missing_ok=True)
