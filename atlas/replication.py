"""Operator-authorized, resumable CAS replication over configured Rclone remotes.

Integrity is pinned by object AND manifest SHA-256. This is not consensus,
a distributed lease, or a guarantee of remote immutability or confidentiality.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time
from .artifacts import ArtifactStore, _private_dir, _sync_directory, _check_digest, _open_regular
from .merkle import DEFAULT_CHUNK, make_manifest, validate_manifest, stage_from_reader

CHUNK = DEFAULT_CHUNK
MAX_OBJECT = 16 * 1024**3
MAX_MANIFEST = 512 * 1024
ROOT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}:[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*\Z')
KEY = re.compile(r'(blocks/[a-f0-9]{64}|manifests/[a-f0-9]{64}\.json)\Z')

class ReplicationError(ValueError):
    pass

class Missing(ReplicationError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(manifest):
    return json.dumps(manifest,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


class Replica:
    def __init__(self, root, *, rclone='rclone', env=None, timeout=120):
        if not isinstance(root,str) or len(root)>512 or not ROOT.fullmatch(root):
            raise ReplicationError('Expected named Rclone remote with safe relative vault path')
        if type(timeout) is not int or not 1<=timeout<=3600:
            raise ReplicationError('Invalid per-operation timeout')
        self.root=root;self.rclone=rclone;self.env=env;self.timeout=timeout

    def path(self,key):
        if not isinstance(key,str) or not KEY.fullmatch(key):
            raise ReplicationError('Invalid CAS remote key')
        return self.root+'/'+key

    def read(self,key,limit):
        if type(limit) is not int or not 0<=limit<=CHUNK:
            raise ReplicationError('Invalid read limit')
        try:
            with subprocess.Popen([self.rclone,'cat',self.path(key)],stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,env=self.env) as proc:
                deadline=time.monotonic()+self.timeout;data=bytearray()
                try:
                    with selectors.DefaultSelector() as sel:
                        sel.register(proc.stdout,selectors.EVENT_READ)
                        while True:
                            remaining=deadline-time.monotonic()
                            if remaining<=0 or not sel.select(remaining):raise ReplicationError('Remote read timeout')
                            part=os.read(proc.stdout.fileno(),min(65536,limit+1-len(data)))
                            if not part:break
                            data.extend(part)
                            if len(data)>limit:raise ReplicationError('Remote response exceeds bound')
                    rc=proc.wait(timeout=max(.01,deadline-time.monotonic()))
                    if rc in (3,4) and not data:raise Missing('Remote object not found')
                    if rc!=0:raise ReplicationError('Remote read failed')
                    return bytes(data)
                finally:
                    if proc.poll() is None:proc.kill();proc.wait()
        except (OSError,subprocess.SubprocessError) as exc:
            raise ReplicationError('Remote read failed') from exc

    def ensure(self,key,data):
        # Only explicit NOT_FOUND permits writing; do not interpret auth/network
        # failures as absence. Verify existing and newly written bytes alike.
        try:
            if self.read(key,len(data))!=data:raise ReplicationError('Existing remote object differs')
            return False
        except Missing:
            pass
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'block';path.write_bytes(data)
            try:
                subprocess.run([self.rclone,'copyto',str(path),self.path(key),'--immutable'],
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    env=self.env,timeout=self.timeout,check=True)
            except (OSError,subprocess.SubprocessError) as exc:
                raise ReplicationError('Remote upload failed') from exc
        if self.read(key,len(data))!=data:raise ReplicationError('Remote read-back mismatch')
        return True


def _replicas(replicas):
    if not isinstance(replicas,list) or not 1<=len(replicas)<=8 or any(not isinstance(r,Replica) for r in replicas):
        raise ReplicationError('Expected 1..8 replicas')
    if len({r.root for r in replicas})!=len(replicas):raise ReplicationError('Duplicate replica roots')


def _manifest(store,sha):
    path=store._path(sha)
    fd,before=_open_regular(path)
    try:
        if before.st_size>MAX_OBJECT:raise ReplicationError('Artifact exceeds replication limit')
    finally:os.close(fd)
    m=make_manifest(path,chunk_size=CHUNK)
    if m['sha256']!=sha or m['size_bytes']>MAX_OBJECT:raise ReplicationError('Invalid local CAS object')
    return m


def push(store:ArtifactStore,sha,replicas):
    _replicas(replicas)
    path=store._path(sha);m=_manifest(store,sha);raw=encode(m)
    if len(raw)>MAX_MANIFEST:raise ReplicationError('Manifest exceeds bound')
    receipts=[]
    for replica in replicas:
        uploaded=0
        fd,before=_open_regular(path)
        try:
            with os.fdopen(os.dup(fd),'rb') as f:
                for i,h in enumerate(m['chunks']):
                    n=min(CHUNK,m['size_bytes']-i*CHUNK);data=f.read(n)
                    if len(data)!=n or digest(data)!=h:raise ReplicationError('Local object changed')
                    uploaded+=replica.ensure('blocks/'+h,data)
                if f.read(1):raise ReplicationError('Local object grew')
            after=os.fstat(fd)
            if (after.st_mtime_ns,after.st_size)!=(before.st_mtime_ns,before.st_size):raise ReplicationError('Local object changed')
        finally:os.close(fd)
        # The manifest is the last publication step for each replica.
        replica.ensure('manifests/'+sha+'.json',raw)
        receipts.append({'root':replica.root,'uploaded_blocks':uploaded,'status':'VERIFIED_READBACK'})
    return {'sha256':sha,'manifest_sha256':digest(raw),'size_bytes':m['size_bytes'],'replicas':receipts}


def _fetch(replicas,key,limit,expected,exact=None):
    for replica in replicas:
        try:
            data=replica.read(key,limit)
            if (exact is None or len(data)==exact) and digest(data)==expected:return data
        except ReplicationError:
            continue
    raise ReplicationError('No valid replica for '+key)


def _decode(raw,sha):
    try:
        m=json.loads(raw)
        # Bound before invoking the general-purpose Merkle validator.
        if not isinstance(m,dict) or type(m.get('size_bytes')) is not int or not 0<=m['size_bytes']<=MAX_OBJECT or m.get('chunk_size')!=CHUNK:
            raise ReplicationError('Invalid replication manifest bounds')
        validate_manifest(m)
        if m['sha256']!=sha or m['filename']!=sha or encode(m)!=raw:raise ReplicationError('Manifest identity/canonical encoding mismatch')
        return m
    except (ValueError,TypeError,KeyError,RecursionError,OverflowError) as exc:
        raise ReplicationError('Invalid pinned manifest') from exc


def pull(store:ArtifactStore,sha,manifest_sha,replicas):
    _replicas(replicas);_check_digest(sha);_check_digest(manifest_sha)
    target=store._path(sha)
    if target.exists() or target.is_symlink():
        m=_manifest(store,sha)
        if digest(encode(m))!=manifest_sha:raise ReplicationError('Local manifest pin mismatch')
        return {'status':'ALREADY_PRESENT','sha256':sha,'copied_chunks':0,'reused_chunks':len(m['chunks'])}
    m=_decode(_fetch(replicas,'manifests/'+sha+'.json',MAX_MANIFEST,manifest_sha),sha)
    staging=store.root/'replication';staging.mkdir(mode=0o700,exist_ok=True);_private_dir(staging)
    # Outer lock covers staging publication AND cleanup, including concurrent pulls.
    lock=os.open(staging/(sha+'.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        st=os.fstat(lock)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode&0o077:
            raise ReplicationError('Unsafe transfer lock')
        fcntl.flock(lock,fcntl.LOCK_EX)
        if target.exists() or target.is_symlink():
            if digest(encode(_manifest(store,sha)))!=manifest_sha:raise ReplicationError('Local manifest pin mismatch')
            return {'status':'ALREADY_PRESENT','sha256':sha,'copied_chunks':0,'reused_chunks':len(m['chunks'])}
        dest=staging/sha
        def reader(offset,length):
            h=m['chunks'][offset//CHUNK]
            return _fetch(replicas,'blocks/'+h,length,h,exact=length)
        result=stage_from_reader(dest,m,reader)
        # Same filesystem, no second copy of the complete artifact.
        try:os.link(dest,target,follow_symlinks=False)
        except FileExistsError:store.verify(sha)
        _sync_directory(store.objects);store.verify(sha)
        dest.unlink();_sync_directory(staging)
        return {**result,'status':'REPLICATED'}
    finally:os.close(lock)
