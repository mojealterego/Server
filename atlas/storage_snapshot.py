"""Versioned, content-addressed SMB share snapshots in an independent private CAS."""
from __future__ import annotations
import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from .artifacts import ArtifactStore, _private_dir, _check_digest, _sync_directory
from .replication import Replica, push, pull, _manifest, encode, MAX_OBJECT
from tools.atomic_publish import publish

SCHEMA='omega.smb.snapshot.v1'
SHARES={'omega-compat':'smb-data/compat','omega-secure':'smb-data/secure','omega-models':'smb-models'}
MAX_INDEX=1024*1024
MAX_ENTRIES=4096
MAX_TOTAL=256*1024**3
VPS=Path(__file__).resolve().parents[1]/'vps'

class SnapshotError(ValueError):pass


def require(ok,msg):
    if not ok:raise SnapshotError(msg)


def path_ok(s):
    return isinstance(s,str) and 0<len(s.encode('utf-8'))<=512 and not any(ord(c)<32 or c=='\\' for c in s) and all(p not in ('','.','..') for p in s.split('/'))


def inventory(root):
    require(root.is_dir() and not root.is_symlink(),'Invalid share directory')
    dirs=[];files=[]
    def walk_error(exc):raise exc
    for base,ds,fs in os.walk(root,followlinks=False,onerror=walk_error):
        for name in ds+fs:
            p=Path(base)/name;rel=p.relative_to(root).as_posix();st=p.lstat()
            require(path_ok(rel),'Unsafe share path')
            if stat.S_ISDIR(st.st_mode):dirs.append(rel)
            elif stat.S_ISREG(st.st_mode):
                require(st.st_nlink==1 and st.st_size<=MAX_OBJECT,'Hardlink or oversized file')
                files.append((rel,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_ino,st.st_dev))
            else:raise SnapshotError('Nonregular share entry')
            require(len(dirs)+len(files)<=MAX_ENTRIES,'Snapshot entry budget exceeded')
    require(sum(f[1] for f in files)<=MAX_TOTAL,'Snapshot byte budget exceeded')
    return sorted(dirs),sorted(files)


def manifest_pin(cas,sha):return hashlib.sha256(encode(_manifest(cas,sha))).hexdigest()


def canonical_index(index):return json.dumps(index,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8')


def create(cas,source,share):
    require(share in SHARES,'Unknown SMB share');source=Path(source)
    require(not source.is_symlink(),'Share symlink refused')
    sr=source.resolve();vr=cas.root.resolve()
    require(not vr.is_relative_to(sr) and not sr.is_relative_to(vr),'Snapshot vault and share must be disjoint')
    dirs,files=inventory(source);rows=[]
    for rel,size,*_ in files:
        r=cas.put(source/rel,max_bytes=size);require(r['size_bytes']==size,'Source size changed')
        rows.append({'path':rel,'size':size,'sha256':r['sha256'],'manifest_sha256':manifest_pin(cas,r['sha256'])})
    require(inventory(source)==(dirs,files),'Share changed during capture; stop all writers')
    # Check contents again, not merely timestamps; a quiesced source is still required.
    for row in rows:require(cas._scan(source/row['path'],max_bytes=row['size'])==(row['sha256'],row['size']),'Source content changed')
    require(inventory(source)==(dirs,files),'Share changed during verification')
    index={'schema':SCHEMA,'share':share,'dirs':dirs,'files':rows};raw=canonical_index(index)
    require(len(raw)<=MAX_INDEX,'Snapshot index too large')
    with tempfile.TemporaryDirectory(dir=cas.root) as tmp:
        p=Path(tmp)/'index';p.write_bytes(raw);r=cas.put(p,max_bytes=MAX_INDEX)
    return {**r,'manifest_sha256':manifest_pin(cas,r['sha256']),'files':len(rows),'share':share}


def load_index(cas,sha):
    p=cas._path(sha);require(cas._scan(p,max_bytes=MAX_INDEX)[0]==sha,'Index digest mismatch')
    raw=p.read_bytes();x=json.loads(raw)
    require(isinstance(x,dict) and set(x)=={'schema','share','dirs','files'} and x['schema']==SCHEMA and x['share'] in SHARES,'Invalid snapshot index')
    require(canonical_index(x)==raw and isinstance(x['dirs'],list) and isinstance(x['files'],list) and len(x['dirs'])+len(x['files'])<=MAX_ENTRIES,'Invalid canonical index')
    paths=set();dirs=set()
    for d in x['dirs']:
        require(path_ok(d) and d not in paths,'Invalid directory path');paths.add(d);dirs.add(d)
    total=0;objects={}
    for row in x['files']:
        require(isinstance(row,dict) and set(row)=={'path','size','sha256','manifest_sha256'} and path_ok(row['path']) and row['path'] not in paths,'Invalid file row')
        require(type(row['size']) is int and 0<=row['size']<=MAX_OBJECT,'Invalid file size');total+=row['size']
        _check_digest(row['sha256']);_check_digest(row['manifest_sha256']);paths.add(row['path'])
        pair=(row['size'],row['manifest_sha256']);require(objects.setdefault(row['sha256'],pair)==pair,'Conflicting object receipt')
        require(row['sha256']!=sha,'Recursive snapshot object')
    require(total<=MAX_TOTAL,'Snapshot byte budget exceeded')
    require(all('/' not in s or s.rsplit('/',1)[0] in dirs for s in paths),'Missing parent directory')
    return x


def restore(cas,sha,dest):
    dest=Path(dest);_private_dir(dest.parent)
    if dest.exists() or dest.is_symlink():raise FileExistsError(str(dest))
    index=load_index(cas,sha)
    with tempfile.TemporaryDirectory(prefix='.smb-restore-',dir=dest.parent) as tmp:
        stage=Path(tmp)/'data';stage.mkdir(mode=0o700)
        for d in sorted(index['dirs'],key=lambda s:(s.count('/'),s)):(stage/d).mkdir(mode=0o700)
        for row in index['files']:
            r=cas.restore(row['sha256'],stage/row['path']);require(r['size_bytes']==row['size'],'Restored size mismatch')
        for d in sorted(index['dirs'],key=lambda s:-s.count('/')):_sync_directory(stage/d)
        _sync_directory(stage);publish(stage,dest)
    return {'status':'RESTORED','sha256':sha,'files':len(index['files'])}


def replicate(cas,sha,replicas):
    index=load_index(cas,sha);seen=set();results=[]
    require(1<=len(replicas)<=8 and len({r.root for r in replicas})==len(replicas),'Invalid replica set')
    for replica in replicas:
        seen.clear()
        for row in index['files']:
            if row['sha256'] in seen:continue
            require(manifest_pin(cas,row['sha256'])==row['manifest_sha256'],'Local object manifest mismatch')
            push(cas,row['sha256'],[replica]);seen.add(row['sha256'])
        results.append(push(cas,sha,[replica]))
    return {'sha256':sha,'manifest_sha256':manifest_pin(cas,sha),'replicas':results}


def retrieve(cas,sha,pin,replicas):
    pull(cas,sha,pin,replicas);index=load_index(cas,sha);seen=set()
    for row in index['files']:
        if row['sha256'] in seen:continue
        pull(cas,row['sha256'],row['manifest_sha256'],replicas);seen.add(row['sha256'])
    return {'status':'VERIFIED','sha256':sha,'objects':len(seen)}


def encrypted_replicas(roots):
    require(1<=len(roots)<=8 and len({r.split(':',1)[0] for r in roots})==len(roots),'Expected distinct encrypted remote aliases')
    out=[]
    for root in roots:
        r=Replica(root);name=root.split(':',1)[0]
        q=subprocess.run(['rclone','config','show',name],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,timeout=15,check=True)
        config=configparser.ConfigParser(interpolation=None)
        try:config.read_string(q.stdout.decode('utf-8'))
        except (configparser.Error,UnicodeError):raise SnapshotError('Invalid encrypted remote configuration') from None
        require(config.has_section(name) and config.get(name,'type',fallback='')=='crypt','Snapshot remote must be configured as crypt')
        out.append(r)
    return out


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',type=Path,required=True);sub=p.add_subparsers(dest='cmd',required=True)
    c=sub.add_parser('create');c.add_argument('--share',choices=sorted(SHARES),required=True);c.add_argument('--confirm-quiesced',action='store_true',required=True)
    r=sub.add_parser('restore');r.add_argument('sha256');r.add_argument('--dest',type=Path,required=True)
    for cmd in ('push','pull'):
        a=sub.add_parser(cmd);a.add_argument('sha256');a.add_argument('--remote',action='append',required=True)
        if cmd=='push':a.add_argument('--allow-export',action='store_true',required=True)
        else:a.add_argument('--manifest-sha256',required=True)
    a=p.parse_args(argv)
    try:
        cas=ArtifactStore(a.vault)
        if a.cmd=='create':
            source=VPS/SHARES[a.share]
            require(not any(p.is_symlink() for p in (source,*[p for p in source.parents if p!=VPS and VPS in p.parents])),'Share path symlink refused')
            result=create(cas,source,a.share)
        elif a.cmd=='restore':result=restore(cas,a.sha256,a.dest)
        elif a.cmd=='push':result=replicate(cas,a.sha256,encrypted_replicas(a.remote))
        else:result=retrieve(cas,a.sha256,a.manifest_sha256,encrypted_replicas(a.remote))
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError,RecursionError,configparser.Error) as exc:
        print('SMB SNAPSHOT ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
