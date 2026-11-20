"""Immutable chunk archives on enrolled local volumes; not a live SMB filesystem."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from . import capacity_fabric as c
from .artifacts import ArtifactStore, _private_dir, _open_regular, _check_unchanged, _check_digest, _sync_directory

MAX_ARCHIVE_BLOCKS = 16384


def absent(path):
    _private_dir(path.parent)
    if path.exists() or path.is_symlink(): raise FileExistsError(str(path))


@contextmanager
def lock(root):
    fd=os.open(root/'.archive.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd)
        c.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and
                  info.st_nlink==1 and not info.st_mode&0o077,'Unsafe archive lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def store_at(root, host, expected, *, existing):
    root=Path(root); _private_dir(root)
    c.require(c.probe_local(root,host,0)['pool']==expected,'Volume identity mismatch')
    if existing: _private_dir(root/'objects')
    cas=ArtifactStore(root)
    c.require(root.stat().st_dev==cas.objects.stat().st_dev,'CAS is on a different volume')
    return cas


def publish_file(tmp,dest):
    os.link(tmp,dest,follow_symlinks=False)
    _sync_directory(dest.parent)


def read_block(cas,sha,length):
    fd,before=_open_regular(cas._path(sha))
    try:
        c.require(before.st_size==length,'Chunk size mismatch')
        with os.fdopen(os.dup(fd),'rb') as src: data=src.read(length+1)
        _check_unchanged(fd,before,len(data))
        c.require(len(data)==length and hashlib.sha256(data).hexdigest()==sha,'Chunk hash mismatch')
        return data
    finally: os.close(fd)


def ingest(source,manifest,policy,proposal,roots,host,now):
    policy=c.normalize(policy); c.verify(policy,proposal,now)
    c.require(c.identifier(host) and len(proposal['blocks'])<=MAX_ARCHIVE_BLOCKS,'Invalid archive limits')
    manifest=Path(manifest); absent(manifest)
    used={n for b in proposal['blocks'] for n in b['pools']}
    c.require(isinstance(roots,dict) and set(roots)==used,'Supply exactly the planned volume roots')
    policies={r['id']:r for r in policy['pools'] if r['id'] in used}
    c.require(all(r['kind']=='local' for r in policies.values()),'Write path accepts local pools only')
    sources={name:Path(roots[name]) for name in used}
    for name,root in sources.items():
        _private_dir(root)
        c.require(c.probe_local(root,host,now)['pool']==policies[name]['pool'],'Volume identity mismatch')
    fd,before=_open_regular(Path(source))
    try:
        c.require(before.st_size==proposal['size_bytes'],'Source size differs from plan')
        with ExitStack() as stack:
            for root in sorted(sources.values(),key=lambda p:str(p.resolve())): stack.enter_context(lock(root))
            stores={n:store_at(root,host,policies[n]['pool'],existing=False) for n,root in sources.items()}
            full=hashlib.sha256(); chunks=[]
            with tempfile.TemporaryDirectory(prefix='.archive-',dir=manifest.parent) as work:
                work=Path(work); stage=work/'chunk'; tmp=work/'manifest'
                with os.fdopen(os.dup(fd),'rb') as src:
                    for b in proposal['blocks']:
                        data=src.read(b['length']); c.require(len(data)==b['length'],'Source truncated')
                        sha=hashlib.sha256(data).hexdigest(); full.update(data)
                        # Immutable CAS dedup: do not write the same block twice on a volume.
                        stage.write_bytes(data)
                        for name in b['pools']:
                            cas=stores[name]; target=cas._path(sha)
                            if not target.exists() and not target.is_symlink():
                                live=c.probe_local(cas.root,host,now)
                                c.require(live['pool']==policies[name]['pool'],'Volume changed during ingestion')
                                c.require(live['free_bytes']>=len(data)+policies[name]['reserve_bytes'],'Live volume reserve denied')
                                receipt=cas.put(stage,max_bytes=len(data))
                                c.require(receipt['sha256']==sha and receipt['size_bytes']==len(data),'CAS receipt mismatch')
                            read_block(cas,sha,len(data))
                        chunks.append({**b,'sha256':sha})
                    c.require(not src.read(1),'Source grew')
                _check_unchanged(fd,before,proposal['size_bytes'])
                doc={'schema':'omega.pooled-archive.v1','host':host,'size_bytes':proposal['size_bytes'],
                     'chunk_bytes':policy['chunk_bytes'],'copies':policy['copies'],'sha256':full.hexdigest(),
                     'volumes':{n:policies[n]['pool'] for n in used},'blocks':chunks}
                validate_manifest(doc,c.digest(doc),host)
                raw=json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
                c.require(len(raw)<=16*c.MIB,'Manifest too large')
                with tmp.open('xb') as dst:
                    os.fchmod(dst.fileno(),0o600);dst.write(raw);dst.flush();os.fsync(dst.fileno())
                publish_file(tmp,manifest)
                return {'sha256':doc['sha256'],'manifest_sha256':c.digest(doc),'blocks':len(chunks)}
    finally: os.close(fd)


def validate_manifest(doc,pin,host):
    _check_digest(pin)
    c.require(isinstance(doc,dict) and set(doc)=={'schema','host','size_bytes','chunk_bytes','copies','sha256','volumes','blocks'} and
              doc['schema']=='omega.pooled-archive.v1' and c.digest(doc)==pin,'Manifest pin mismatch')
    c.require(c.identifier(host) and doc['host']==host and c.integer(doc['chunk_bytes'],c.MIB,64*c.MIB) and
              c.integer(doc['copies'],1,3),'Invalid manifest identity or settings')
    _check_digest(doc['sha256']); volumes=doc['volumes']; blocks=doc['blocks']
    c.require(isinstance(volumes,dict) and 1<=len(volumes)<=128 and
              all(c.identifier(k) and c.identifier(v) for k,v in volumes.items()) and
              len(set(volumes.values()))==len(volumes),'Invalid volume map')
    shape=list(c.geometry(doc,doc['size_bytes']))
    c.require(isinstance(blocks,list) and len(blocks)==len(shape)<=MAX_ARCHIVE_BLOCKS,'Invalid archive block count')
    used=set()
    for b,(off,n) in zip(blocks,shape):
        c.require(isinstance(b,dict) and set(b)=={'offset','length','pools','sha256'} and
                  c.integer(b['offset']) and c.integer(b['length'],1) and (b['offset'],b['length'])==(off,n),'Invalid archive block')
        _check_digest(b['sha256']); names=b['pools']
        c.require(isinstance(names,list) and len(names)==doc['copies'] and all(c.identifier(k) and k in volumes for k in names)
                  and len(set(names))==len(names),'Invalid block replicas');used.update(names)
    c.require(used==set(volumes),'Unused volume enrollment')


def restore(manifest,pin,dest,roots,host):
    doc=c.read_json(manifest);validate_manifest(doc,pin,host)
    dest=Path(dest);absent(dest)
    c.require(isinstance(roots,dict) and roots and set(roots)<=set(doc['volumes']),'Invalid restoration roots')
    stores={}
    for name,root in roots.items():
        try: stores[name]=store_at(root,host,doc['volumes'][name],existing=True)
        except (OSError,ValueError): continue
    full=hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='.archive-restore-',dir=dest.parent) as work:
        tmp=Path(work)/'output'
        with tmp.open('xb') as output:
            os.fchmod(output.fileno(),0o600)
            for b in doc['blocks']:
                for name in b['pools']:
                    if name not in stores: continue
                    try: data=read_block(stores[name],b['sha256'],b['length']);break
                    except (OSError,ValueError): continue
                else: raise c.PolicyError('No verified replica for block at '+str(b['offset']))
                output.write(data);full.update(data)
            output.flush();os.fsync(output.fileno())
        c.require(full.hexdigest()==doc['sha256'] and tmp.stat().st_size==doc['size_bytes'],'Restored file mismatch')
        publish_file(tmp,dest)
    return {'sha256':doc['sha256'],'size_bytes':doc['size_bytes'],'status':'RESTORED_OFFLINE'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='cmd',required=True)
    i=s.add_parser('ingest');r=s.add_parser('restore')
    for sub in (i,r):
        sub.add_argument('--manifest',required=True,type=Path);sub.add_argument('--roots',required=True,type=Path)
        sub.add_argument('--host',required=True)
    for name in ('source','policy','proposal'):i.add_argument('--'+name,required=True,type=Path)
    r.add_argument('--sha256',required=True);r.add_argument('--dest',required=True,type=Path)
    args=p.parse_args(argv)
    try:
        roots=c.read_json(args.roots)
        if args.cmd=='ingest': result=ingest(args.source,args.manifest,c.read_json(args.policy),c.read_json(args.proposal),roots,args.host,int(time.time()))
        else: result=restore(args.manifest,args.sha256,args.dest,roots,args.host)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,TypeError,KeyError,RecursionError) as exc:
        print('ARCHIVE ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
