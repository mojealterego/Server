"""E20a: independently pinned Ed25519 checkpoints for a single-host namespace.

A checkpoint is a verifiable *observation*, not a distributed transaction,
quorum, online authority or protection against losing the external head pin.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = 'omega.authority-checkpoint.v1'
ZERO = '0' * 64
HEX = re.compile(r'[0-9a-f]{64}\Z',re.ASCII)
ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z',re.ASCII)
FILENAME = re.compile(r'(\d{20})-([0-9a-f]{64})\.json\Z',re.ASCII)
MAX_RECEIPTS = 100_000
MAX_ROWS = 1_000_000
MAX_ROW_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 8192


class AuditError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:raise AuditError(reason)


def _canonical(value: dict | list) -> bytes:
    try:
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    except (ValueError,TypeError,OverflowError) as exc:
        raise AuditError('Invalid checkpoint metadata') from exc
    require(len(raw) <= MAX_ROW_BYTES,'Oversized checkpoint record')
    return raw


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result={}
    for k,v in pairs:
        require(k not in result, 'Duplicate checkpoint field')
        result[k]=v
    return result


def _directory(path: Path) -> Path:
    path=Path(path)
    require(path.is_dir() and not path.is_symlink(),'Missing private checkpoint directory')
    st=path.stat()
    require(st.st_uid==os.getuid() and not (st.st_mode & 0o077),
            'Checkpoint directory must be privately owned')
    return path


def _regular(path: Path, *, max_size: int, exact: int | None=None, read_content: bool=True) -> bytes:
    require(not path.is_symlink(),'Symlinks are not accepted')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==os.getuid()
                and not st.st_mode & 0o077 and st.st_size<=max_size and
                (exact is None or st.st_size==exact),'Non-private or oversized checkpoint file')
        if not read_content:return b''
        out=os.read(fd,max_size+1)
        require(len(out)==st.st_size,'Truncated checkpoint file')
        return out
    finally:os.close(fd)


def _rows_hash(db: sqlite3.Connection, sql: str, params: tuple) -> str:
    h=hashlib.sha256(b'OMEGA-E20a-ROWS\x00')
    n=0
    for row in db.execute(sql,params):
        n+=1
        require(n<=MAX_ROWS,'Metadata row count exceeds audit bounds')
        b=_canonical(list(row))
        h.update(len(b).to_bytes(4,'big'))
        h.update(b)
    h.update(n.to_bytes(8,'big'))
    return h.hexdigest()


def snapshot(db_path: Path, tenant: str) -> dict:
    """Read a consistent SQLite WAL snapshot and hash all tenant metadata."""
    require(type(tenant) is str and ID.fullmatch(tenant) is not None,'Invalid tenant identity')
    db_path=Path(db_path)
    _directory(db_path.parent)
    # Recheck by FD before SQLite opens its own read-only handle. This is not
    # a defense against an adversary with write privileges on the parent.
    _regular(db_path,max_size=4*1024**3,read_content=False)
    uri='file:'+quote(str(db_path.absolute()),safe='/')+'?mode=ro'
    try:
        with closing(sqlite3.connect(uri,uri=True,timeout=3)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            rows=db.execute('SELECT epoch,generation FROM authority WHERE id=1').fetchall()
            require(len(rows)==1 and all(type(i) is int and 0<=i<=2**63-1 for i in rows[0])
                    and rows[0][0]>=1,'Invalid namespace authority')
            epoch,generation=rows[0]
            entries=_rows_hash(db,'SELECT tenant,key,path,manifest_sha256,archive_sha256,'
                'policy_sha256,size_bytes,revision,deleted FROM entries WHERE tenant=? ORDER BY key',(tenant,))
            ops=_rows_hash(db,'SELECT tenant,operation_id,epoch,request_sha256,receipt '
                'FROM operations WHERE tenant=? ORDER BY operation_id',(tenant,))
            db.execute('COMMIT')
            return {'tenant':tenant,'epoch':epoch,'generation':generation,
                    'entries_sha256':entries,'operations_sha256':ops}
    except (sqlite3.DatabaseError,OSError) as exc:
        raise AuditError('Cannot read a consistent namespace snapshot') from exc


def _receipt_files(directory: Path) -> list[Path]:
    _directory(directory)
    files=[]
    for path in directory.iterdir():
        if path.name=='.lock':
            _regular(path,max_size=0,exact=0)
            continue
        require(FILENAME.fullmatch(path.name) is not None,'Unexpected audit directory entry')
        require(not path.is_symlink() and path.is_file(),'Invalid receipt type')
        files.append(path)
        require(len(files)<=MAX_RECEIPTS,'Audit chain exceeds maximum receipts')
    return sorted(files)


def _load(path: Path) -> dict:
    raw=_regular(path,max_size=MAX_RECEIPT_BYTES)
    try:
        doc=json.loads(raw,object_pairs_hook=_unique,
                       parse_constant=lambda x: (_ for _ in ()).throw(AuditError('Nonfinite checkpoint')))
    except (UnicodeError,json.JSONDecodeError) as exc:
        raise AuditError('Malformed checkpoint') from exc
    require(type(doc) is dict and set(doc)=={'schema','tenant','sequence','epoch','generation',
            'entries_sha256','operations_sha256','prev_sha256','observed_at','signature'},
            'Invalid checkpoint fields')
    require(_canonical(doc)==raw,'Checkpoint is not canonical JSON')
    return doc


def verify(directory: Path, public_key: bytes, expected_tip: str, *,
           db_path: Path | None=None, tenant: str | None=None, allow_empty: bool=False) -> dict:
    """Verify signed history AND an independently retained external head pin."""
    require(type(public_key) is bytes and len(public_key)==32,'Missing independently pinned public key')
    require(type(expected_tip) is str and HEX.fullmatch(expected_tip) is not None,'Invalid external head pin')
    pub=Ed25519PublicKey.from_public_bytes(public_key)
    files=_receipt_files(Path(directory))
    require(files or allow_empty,'Empty history cannot prove a checkpoint')
    prior=ZERO;previous_epoch=0;previous_generation=-1;previous_time=-1
    last=None
    for seq,path in enumerate(files,1):
        row=_load(path)
        receipt_sha=_hash(_canonical(row))
        require(path.name==f'{seq:020d}-{receipt_sha}.json','Missing or reordered checkpoint receipt')
        require(row['schema']==SCHEMA and type(row['tenant']) is str and ID.fullmatch(row['tenant']) is not None
                and type(row['sequence']) is int and row['sequence']==seq
                and type(row['epoch']) is int and row['epoch']>=1
                and type(row['generation']) is int and row['generation']>=0
                and type(row['observed_at']) is int and 0<=row['observed_at']<=2**63-1
                and all(type(row[k]) is str and HEX.fullmatch(row[k]) is not None
                        for k in ('entries_sha256','operations_sha256','prev_sha256'))
                and row['prev_sha256']==prior,'Malformed checkpoint chain')
        require(row['epoch']>=previous_epoch and row['generation']>previous_generation
                and row['observed_at']>=previous_time,'Regressing epoch, generation or time')
        if last is not None:require(row['tenant']==last['tenant'],'Checkpoint tenant changed')
        signature=row['signature']
        require(type(signature) is str and len(signature)==128 and
                all(x in '0123456789abcdef' for x in signature),'Invalid Ed25519 signature encoding')
        unsigned={k:v for k,v in row.items() if k!='signature'}
        try:pub.verify(bytes.fromhex(signature),b'OMEGA-E20a-CHECKPOINT\x00'+_canonical(unsigned))
        except InvalidSignature as exc:raise AuditError('Checkpoint signature invalid') from exc
        prior=receipt_sha;previous_epoch=row['epoch'];previous_generation=row['generation']
        previous_time=row['observed_at'];last=row
    require(prior==expected_tip,'History does not match independent external head pin')
    if db_path is not None:
        require(last is not None and type(tenant) is str and last['tenant']==tenant,
                'Tenant or chain missing for current-state comparison')
        state=snapshot(db_path,tenant)
        require(all(state[k]==last[k] for k in ('tenant','epoch','generation',
                       'entries_sha256','operations_sha256')),'Current namespace differs from signed checkpoint')
    return {'status':'MATCH' if db_path is not None else 'CHAIN_VALID',
            'length':len(files),'digest':prior,
            'tenant':last['tenant'] if last is not None else None}


def _signer(key_path: Path) -> Ed25519PrivateKey:
    raw=_regular(Path(key_path),max_size=32,exact=32)
    try:return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:raise AuditError('Invalid signer key') from exc


def _fsync_dir(path: Path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def append(db_path: Path, directory: Path, *, tenant: str, key_path: Path,
           expected_tip: str, now: int) -> dict:
    """Serialize writers; never truncate a checkpoint or silently move the head."""
    directory=_directory(directory)
    require(type(now) is int and 0<=now<=2**63-1,'Invalid timestamp')
    key=_signer(key_path)
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    lock_path=directory/'.lock'
    fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1
                and not st.st_mode&0o077 and st.st_size==0,'Unsafe lock')
        fcntl.flock(fd,fcntl.LOCK_EX)
        chain=verify(directory,public,expected_tip,allow_empty=True)
        files=_receipt_files(directory)
        prev=_load(files[-1]) if files else None
        state=snapshot(db_path,tenant)
        require(prev is None or (prev['tenant']==tenant and state['epoch']>=prev['epoch']
                and state['generation']>prev['generation'] and now>=prev['observed_at']),
                'No monotonic namespace progress')
        doc={'schema':SCHEMA,'tenant':tenant,'sequence':chain['length']+1,
             'epoch':state['epoch'],'generation':state['generation'],
             'entries_sha256':state['entries_sha256'],'operations_sha256':state['operations_sha256'],
             'prev_sha256':expected_tip,'observed_at':now}
        signed={**doc,'signature':key.sign(b'OMEGA-E20a-CHECKPOINT\x00'+_canonical(doc)).hex()}
        raw=_canonical(signed)
        require(len(raw)<=MAX_RECEIPT_BYTES,'Oversized receipt')
        receipt_sha=_hash(raw)
        dest=directory/f"{doc['sequence']:020d}-{receipt_sha}.json"
        tmp_fd,tmp=tempfile.mkstemp(prefix='.pending-',dir=directory)
        try:
            with os.fdopen(tmp_fd,'wb') as output:
                os.fchmod(output.fileno(),0o600)
                output.write(raw);output.flush();os.fsync(output.fileno())
            os.link(tmp,dest,follow_symlinks=False)
            _fsync_dir(directory)
        finally:Path(tmp).unlink(missing_ok=True)
        return {'sequence':doc['sequence'],'digest':receipt_sha,'epoch':state['epoch'],
                'generation':state['generation'],'status':'CHECKPOINT_WRITTEN_PIN_EXTERNALLY'}
    except (OSError,sqlite3.DatabaseError) as exc:
        raise AuditError('Audit append failed') from exc
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def main(argv=None)->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',required=True,type=Path)
    p.add_argument('--dir',required=True,type=Path)
    p.add_argument('--tenant',required=True)
    s=p.add_subparsers(dest='action',required=True)
    a=s.add_parser('append');a.add_argument('--key',required=True,type=Path)
    a.add_argument('--expected-tip',required=True);a.add_argument('--now',type=int,required=True)
    v=s.add_parser('verify');v.add_argument('--public-key',required=True)
    v.add_argument('--tip',required=True);v.add_argument('--match-current',action='store_true')
    args=p.parse_args(argv)
    try:
        if args.action=='append':result=append(args.db,args.dir,tenant=args.tenant,
            key_path=args.key,expected_tip=args.expected_tip,now=args.now)
        else:
            require(len(args.public_key)==64 and all(x in '0123456789abcdef' for x in args.public_key),
                    'Invalid independent Ed25519 key pin')
            result=verify(args.dir,bytes.fromhex(args.public_key),args.tip,
                          db_path=args.db if args.match_current else None,
                          tenant=args.tenant if args.match_current else None)
        print(json.dumps(result,sort_keys=True));return 0
    except (AuditError,OSError,sqlite3.Error) as exc:
        print('AUTHORITY CHECKPOINT ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
