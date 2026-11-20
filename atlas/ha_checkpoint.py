"""Quiesced coordinator recovery checkpoint; not distributed consensus or live HA."""
from __future__ import annotations
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time
from tools.atomic_publish import publish
from .ha_authority import authority

SCHEMA='omega.coordinator.checkpoint.v1'
HEX=re.compile(r'[a-f0-9]{64}\Z')
MAX_DB=256*1024**2
MAX_OBJECT=16*1024**3
MAX_TOTAL=256*1024**3
MAX_OBJECTS=4096
MAX_INDEX=1024*1024

class CheckpointError(ValueError):pass


def require(ok,msg):
    if not ok:raise CheckpointError(msg)


def private(path):
    s=path.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o077,'Expected private directory')


def regular(path):
    s=path.lstat();require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and not s.st_mode&0o077,'Expected private regular file')
    return s


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


def copy_file(src,dest,limit):
    before=regular(src);require(before.st_size<=limit,'File exceeds checkpoint limit')
    fd=os.open(src,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as inp:
        require(os.fstat(inp.fileno())==before,'File replaced before copy')
        out=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        h=hashlib.sha256();n=0
        with os.fdopen(out,'wb') as f:
            while data:=inp.read(1024*1024):
                n+=len(data);require(n<=limit,'File grew during copy');h.update(data);f.write(data)
            f.flush();os.fsync(f.fileno())
        after=os.fstat(inp.fileno())
        require((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(before.st_dev,before.st_ino,n,before.st_mtime_ns,before.st_ctime_ns) and n==before.st_size,'File changed during copy')
    return {'sha256':h.hexdigest(),'size':n}


def file_info(path,limit):
    st=regular(path);require(st.st_size<=limit,'File exceeds checkpoint limit')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        h=hashlib.sha256();n=0
        while data:=f.read(1024*1024):
            n+=len(data);require(n<=limit,'File grew');h.update(data)
        end=os.fstat(f.fileno());require(n==st.st_size and end.st_mtime_ns==st.st_mtime_ns and end.st_ctime_ns==st.st_ctime_ns and end.st_ino==st.st_ino and end.st_dev==st.st_dev,'File changed')
    return {'sha256':h.hexdigest(),'size':n}


def db_open(path):
    regular(path)
    for suffix in ('-wal','-shm','-journal'):
        p=Path(str(path)+suffix)
        if p.exists() or p.is_symlink():regular(p);require(p.stat().st_size<=MAX_DB,'SQLite sidecar exceeds limit')
    c=sqlite3.connect(path.absolute().as_uri()+'?mode=ro',uri=True,timeout=5)
    c.execute('PRAGMA trusted_schema=OFF');return c


def verify_db(path,lease):
    with closing(db_open(path)) as c:
        require(c.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQLite integrity check failed')
        if not lease:
            c.execute('SELECT node,issued_ns FROM accepted LIMIT 1').fetchall();return []
        for table,cols in [('node_registry','node_id,ram_capacity_mb,disk_free_bytes,trust'),('retired_plans','plan_hash,successor_hash,payload'),('attempt_limits','plan_hash,root_hash,max_attempts')]:
            c.execute('SELECT '+cols+' FROM '+table+' LIMIT 1').fetchall()
        require(not c.execute("SELECT 1 FROM leases WHERE state IS NULL OR state NOT IN ('LEASED','FAILED','COMPLETED') LIMIT 1").fetchone(),'Unknown lease state')
        require(not c.execute("SELECT 1 FROM leases WHERE state='LEASED' AND (expires_at IS NULL OR expires_at>?) LIMIT 1",(time.time(),)).fetchone(),'Active lease; stop workers and wait for expiry')
        rows=c.execute("SELECT DISTINCT output_sha256 FROM leases WHERE state='COMPLETED' LIMIT ?",(MAX_OBJECTS+1,)).fetchall()
        require(len(rows)<=MAX_OBJECTS and all(isinstance(r[0],str) and HEX.fullmatch(r[0]) for r in rows),'Invalid completed CAS references')
        return sorted(r[0] for r in rows)


def backup_db(src,dst):
    require(regular(src).st_size<=MAX_DB,'Database exceeds checkpoint limit')
    fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    end=time.monotonic()+60
    def progress(status,remaining,total):
        if time.monotonic()>end:raise CheckpointError('SQLite backup deadline exceeded')
        require(total*page_size<=MAX_DB,'Database exceeds checkpoint limit')
    with closing(db_open(src)) as original, closing(sqlite3.connect(dst)) as copy:
        page_size=original.execute('PRAGMA page_size').fetchone()[0]
        original.backup(copy,pages=128,progress=progress,sleep=.05)
        require(copy.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete','Standalone database required')
    with dst.open('rb') as f:os.fsync(f.fileno())


def capture(db,replay,cas,dest,*,quiesced=False):
    require(quiesced is True,'Explicit coordinator and worker quiescence required')
    with authority(db):return _capture(db,replay,cas,dest)


def _capture(db,replay,cas,dest):
    db,replay,cas,dest=map(Path,(db,replay,cas,dest));private(dest.parent);private(db.parent);private(replay.parent);private(cas);private(cas/'objects')
    require(not os.path.samefile(db,replay),'Separate lease and replay databases required')
    require(not dest.resolve().is_relative_to(cas.resolve()),'Keep checkpoint outside compute CAS')
    if dest.exists() or dest.is_symlink():raise FileExistsError(str(dest))
    with tempfile.TemporaryDirectory(prefix='.ha-',dir=dest.parent) as tmp:
        stage=Path(tmp)/'bundle';stage.mkdir(mode=0o700);(stage/'cas').mkdir(mode=0o700);(stage/'cas/objects').mkdir(mode=0o700)
        backup_db(db,stage/'leases.db');backup_db(replay,stage/'replay.db')
        shas=verify_db(stage/'leases.db',True);verify_db(stage/'replay.db',False)
        dbs={name:file_info(stage/name,MAX_DB) for name in ('leases.db','replay.db')}
        objects={};total=0
        for sha in shas:
            src=cas/'objects'/sha
            total+=regular(src).st_size;require(total<=MAX_TOTAL,'Checkpoint object budget exceeded')
            r=copy_file(src,stage/'cas/objects'/sha,MAX_OBJECT);require(r['sha256']==sha,'CAS digest mismatch');objects[sha]=r['size']
        index={'schema':SCHEMA,'databases':dbs,'objects':objects};raw=canonical(index);require(len(raw)<=MAX_INDEX,'Checkpoint index exceeds limit')
        fd=os.open(stage/'manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        for p in (stage/'cas/objects',stage/'cas',stage):sync_dir(p)
        publish(stage,dest)
    return {'status':'CHECKPOINTED_OFFLINE','sha256':hashlib.sha256(raw).hexdigest(),'objects':len(objects)}


def recover(bundle,pin,dest,*,fenced=False,no_newer_state=False):
    require(fenced is True and no_newer_state is True,'Confirm old authority fenced and no newer state exists')
    bundle,dest=Path(bundle),Path(dest);private(bundle);private(bundle/'cas');private(bundle/'cas/objects');private(dest.parent)
    require(not dest.resolve().is_relative_to(bundle.resolve()),'Destination must be outside checkpoint')
    if dest.exists() or dest.is_symlink():raise FileExistsError(str(dest))
    require(isinstance(pin,str) and HEX.fullmatch(pin),'Invalid manifest pin')
    path=bundle/'manifest.json';require(regular(path).st_size<=MAX_INDEX,'Checkpoint index exceeds limit');raw=path.read_bytes();require(len(raw)<=MAX_INDEX and hashlib.sha256(raw).hexdigest()==pin,'Checkpoint pin mismatch')
    index=json.loads(raw);require(isinstance(index,dict) and set(index)=={'schema','databases','objects'} and index['schema']==SCHEMA and canonical(index)==raw,'Invalid checkpoint manifest')
    dbs=index['databases'];objects=index['objects'];require(isinstance(dbs,dict) and set(dbs)=={'leases.db','replay.db'} and isinstance(objects,dict) and len(objects)<=MAX_OBJECTS,'Invalid checkpoint entries')
    require(all(HEX.fullmatch(k) and type(v) is int and 0<=v<=MAX_OBJECT for k,v in objects.items()) and sum(objects.values())<=MAX_TOTAL,'Invalid checkpoint object bounds')
    with tempfile.TemporaryDirectory(prefix='.ha-recover-',dir=dest.parent) as tmp:
        stage=Path(tmp)/'state';stage.mkdir(mode=0o700);(stage/'cas').mkdir(mode=0o700);(stage/'cas/objects').mkdir(mode=0o700)
        for name in dbs:require(copy_file(bundle/name,stage/name,MAX_DB)==dbs[name],'Database digest mismatch')
        require(set(verify_db(stage/'leases.db',True))==set(objects),'Checkpoint CAS set differs from completed leases');verify_db(stage/'replay.db',False)
        for sha,size in objects.items():require(copy_file(bundle/'cas/objects'/sha,stage/'cas/objects'/sha,size)=={'sha256':sha,'size':size},'CAS digest mismatch')
        with closing(sqlite3.connect(stage/'leases.db')) as c:
            c.execute("UPDATE leases SET state='FAILED',last_error='PROCESS_FAILED',expires_at=0,reserved_ram_mb=0 WHERE state='LEASED'");c.commit()
        with (stage/'leases.db').open('rb') as f:os.fsync(f.fileno())
        for p in (stage/'cas/objects',stage/'cas',stage):sync_dir(p)
        publish(stage,dest)
    return {'status':'RECOVERED_OFFLINE','checkpoint_sha256':pin,'objects':len(objects)}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True);c=sub.add_parser('capture');r=sub.add_parser('recover')
    for name in ('db','replay','cas','dest'):c.add_argument('--'+name,type=Path,required=True)
    c.add_argument('--confirm-quiesced',action='store_true',required=True)
    r.add_argument('--bundle',type=Path,required=True);r.add_argument('--sha256',required=True);r.add_argument('--dest',type=Path,required=True);r.add_argument('--confirm-fenced',action='store_true',required=True);r.add_argument('--confirm-no-newer-state',action='store_true',required=True)
    a=p.parse_args(argv)
    try:
        result=capture(a.db,a.replay,a.cas,a.dest,quiesced=a.confirm_quiesced) if a.cmd=='capture' else recover(a.bundle,a.sha256,a.dest,fenced=a.confirm_fenced,no_newer_state=a.confirm_no_newer_state)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,sqlite3.Error,TypeError,KeyError,RecursionError) as exc:print('HA CHECKPOINT ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
