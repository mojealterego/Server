"""E16a single-host transactional namespace for pinned encrypted archives.

Metadata only: NOT an SMB VFS, distributed lock service or tenant auth gateway.
Authorization to a tenant and exclusive database ownership are external duties.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z', re.ASCII)
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


class NamespaceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NamespaceError(message)


def identity(value: str) -> str:
    require(type(value) is str and ID.fullmatch(value) is not None, 'Invalid identity')
    return value


def path_key(path: str) -> str:
    require(type(path) is str and 0 < len(path) <= 1024 and path.isascii(), 'Invalid path')
    parts = path.split('/')
    reserved = {'con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),
                *(f'lpt{i}' for i in range(1,10))}
    require(len(parts) <= 16 and all(SEGMENT.fullmatch(p) is not None
        and p not in ('.','..') and not p.endswith('.')
        and p.split('.')[0].lower() not in reserved for p in parts),
        'Unsafe SMB path segment')
    return path.lower()


def hex_digest(value: str) -> str:
    require(type(value) is str and HEX.fullmatch(value) is not None, 'Invalid SHA-256')
    return value


def integer(value: int, low: int = 0) -> int:
    require(type(value) is int and low <= value <= (1 << 63)-1, 'Invalid integer')
    return value


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


class Namespace:
    """Single-authority, crash-consistent SQLite metadata map; a bound tenant is trusted.

    Same operation_id+request returns previous receipt in the same epoch.
    A request with a stale expected_revision fails rather than silently replacing data.
    """
    def __init__(self, db_path: Path, *, tenant: str):
        self.tenant = identity(tenant)
        self.db_path = Path(db_path)
        parent = self.db_path.parent
        require(parent.is_dir() and not parent.is_symlink(), 'Namespace directory missing')
        info = parent.stat()
        require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
                'Namespace root must be private and owned by this OS user')
        require(not self.db_path.is_symlink(), 'Namespace database cannot be a symlink')
        if self.db_path.exists():
            st = self.db_path.stat()
            require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
                    and not st.st_mode & 0o077, 'Unsafe database file')
        # Exclusive mode=0600 creation avoids changing the process-global umask.
        if not self.db_path.exists():
            try:
                fd=os.open(self.db_path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                raise NamespaceError('Namespace database created concurrently') from None
            else:
                os.close(fd)
        require(not self.db_path.is_symlink() and not self.db_path.stat().st_mode & 0o077,
                'Unsafe namespace database')
        self.db = sqlite3.connect(self.db_path, isolation_level=None, timeout=3)
        try:
            self.db.execute('PRAGMA busy_timeout=3000')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
CREATE TABLE IF NOT EXISTS authority (id INTEGER PRIMARY KEY CHECK(id=1),
                                       epoch INTEGER NOT NULL, generation INTEGER NOT NULL);
INSERT OR IGNORE INTO authority(id,epoch,generation) VALUES(1,1,0);
CREATE TABLE IF NOT EXISTS entries (
    tenant TEXT NOT NULL, key TEXT NOT NULL, path TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL, archive_sha256 TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
    revision INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(tenant,key));
CREATE TABLE IF NOT EXISTS operations (
    tenant TEXT NOT NULL, operation_id TEXT NOT NULL,
    epoch INTEGER NOT NULL, request_sha256 TEXT NOT NULL, receipt TEXT NOT NULL,
    PRIMARY KEY(tenant,operation_id));
''')
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _mutate(self, operation: str, args: dict, *, epoch: int,
                operation_id: str, action):
        integer(epoch,1)
        identity(operation_id)
        fingerprint = hashlib.sha256(_canonical({'action':operation,'args':args}).encode()).hexdigest()
        try:
            self.db.execute('BEGIN IMMEDIATE')
            current = self.db.execute('SELECT epoch,generation FROM authority WHERE id=1').fetchone()
            require(current is not None and current[0] == epoch, 'Stale writer epoch')
            found = self.db.execute('SELECT epoch,request_sha256,receipt FROM operations '
                                    'WHERE tenant=? AND operation_id=?',
                                    (self.tenant,operation_id)).fetchone()
            if found:
                require(found[0] == epoch and found[1] == fingerprint, 'Operation ID conflict')
                result = json.loads(found[2])
            else:
                result = action()
                self.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',
                                (self.tenant,operation_id,epoch,fingerprint,_canonical(result)))
                self.db.execute('UPDATE authority SET generation=generation+1 WHERE id=1')
            self.db.execute('COMMIT')
            return result
        except (NamespaceError,sqlite3.Error,ValueError,TypeError) as exc:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            if isinstance(exc,NamespaceError):raise
            raise NamespaceError('Namespace transaction aborted') from exc

    def put(self, path: str, manifest_sha256: str, archive_sha256: str,
            policy_sha256: str, size_bytes: int, *, epoch: int,
            expected_revision: int, operation_id: str) -> dict:
        key = path_key(path)
        for value in (manifest_sha256,archive_sha256,policy_sha256):hex_digest(value)
        integer(size_bytes,1);integer(expected_revision)
        args={'path':path,'manifest':manifest_sha256,'archive':archive_sha256,
              'policy':policy_sha256,'size':size_bytes,'expected_revision':expected_revision}
        def action():
            old=self.db.execute('SELECT revision FROM entries WHERE tenant=? AND key=?',
                                (self.tenant,key)).fetchone()
            actual=old[0] if old else 0
            require(actual==expected_revision, 'Stale object revision')
            revision=actual+1
            self.db.execute('INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,0) '
                            'ON CONFLICT(tenant,key) DO UPDATE SET path=excluded.path, '
                            'manifest_sha256=excluded.manifest_sha256, '
                            'archive_sha256=excluded.archive_sha256, '
                            'policy_sha256=excluded.policy_sha256, '
                            'size_bytes=excluded.size_bytes, revision=excluded.revision,deleted=0',
                            (self.tenant,key,path,manifest_sha256,archive_sha256,policy_sha256,
                             size_bytes,revision))
            return {'path':path,'revision':revision,'manifest_sha256':manifest_sha256}
        return self._mutate('put',args,epoch=epoch,operation_id=operation_id,action=action)

    def delete(self, path: str, *, epoch: int, expected_revision: int,
               operation_id: str) -> dict:
        key=path_key(path);integer(expected_revision,1)
        def action():
            old=self.db.execute('SELECT revision,deleted FROM entries WHERE tenant=? AND key=?',
                                (self.tenant,key)).fetchone()
            require(old is not None and old==(expected_revision,0), 'Stale or absent entry')
            revision=expected_revision+1
            self.db.execute('UPDATE entries SET deleted=1,revision=? WHERE tenant=? AND key=?',
                            (revision,self.tenant,key))
            return {'path':path,'revision':revision,'deleted':True}
        return self._mutate('delete',{'path':path,'revision':expected_revision},
                            epoch=epoch,operation_id=operation_id,action=action)

    def rename(self, source: str, target: str, *, epoch: int,
               expected_revision: int, operation_id: str) -> dict:
        source_key=path_key(source);target_key=path_key(target)
        require(source_key!=target_key,'No-op/ambiguous rename')
        integer(expected_revision,1)
        def action():
            row=self.db.execute('SELECT manifest_sha256,archive_sha256,policy_sha256,'
                                'size_bytes,revision,deleted FROM entries WHERE tenant=? AND key=?',
                                (self.tenant,source_key)).fetchone()
            require(row is not None and row[4:]==(expected_revision,0),'Stale source')
            require(self.db.execute('SELECT 1 FROM entries WHERE tenant=? AND key=?',
                                    (self.tenant,target_key)).fetchone() is None,
                    'Destination was previously allocated')
            self.db.execute('UPDATE entries SET deleted=1,revision=? WHERE tenant=? AND key=?',
                            (expected_revision+1,self.tenant,source_key))
            self.db.execute('INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,0)',
                            (self.tenant,target_key,target,*row[:4],1))
            return {'path':target,'revision':1,'manifest_sha256':row[0]}
        return self._mutate('rename',{'source':source,'target':target,'revision':expected_revision},
                            epoch=epoch,operation_id=operation_id,action=action)

    def fence(self, *, expected_epoch: int, new_epoch: int) -> int:
        integer(expected_epoch,1);integer(new_epoch,2)
        require(new_epoch>expected_epoch,'Epoch must increase')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            current=self.db.execute('SELECT epoch FROM authority WHERE id=1').fetchone()[0]
            require(current==expected_epoch,'Stale fencing authority')
            self.db.execute('UPDATE authority SET epoch=?,generation=generation+1 WHERE id=1',
                            (new_epoch,))
            self.db.execute('COMMIT')
            return new_epoch
        except (NamespaceError,sqlite3.Error) as exc:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            if isinstance(exc,NamespaceError):raise
            raise NamespaceError('Fencing transaction aborted') from exc

    def get(self, path: str) -> dict | None:
        key=path_key(path)
        row=self.db.execute('SELECT path,manifest_sha256,archive_sha256,policy_sha256,'
                            'size_bytes,revision FROM entries WHERE tenant=? AND key=? AND deleted=0',
                            (self.tenant,key)).fetchone()
        return dict(zip(('path','manifest_sha256','archive_sha256','policy_sha256',
                         'size_bytes','revision'),row)) if row else None

    def list(self, *, limit: int=100, after: str|None=None) -> list[dict]:
        integer(limit,1);require(limit<=1000,'List page too large')
        cursor='' if after is None else path_key(after)
        rows=self.db.execute('SELECT path,manifest_sha256,archive_sha256,policy_sha256,'
                             'size_bytes,revision FROM entries WHERE tenant=? AND key>? '
                             'AND deleted=0 ORDER BY key LIMIT ?',
                             (self.tenant,cursor,limit)).fetchall()
        return [dict(zip(('path','manifest_sha256','archive_sha256','policy_sha256',
                          'size_bytes','revision'),r)) for r in rows]

    def status(self) -> dict:
        epoch,generation=self.db.execute('SELECT epoch,generation FROM authority WHERE id=1').fetchone()
        count=self.db.execute('SELECT COUNT(*) FROM entries WHERE tenant=? AND deleted=0',
                              (self.tenant,)).fetchone()[0]
        return {'tenant':self.tenant,'epoch':epoch,'generation':generation,'active_entries':count,
                'authority':'SINGLE_HOST_ONLY'}


def main(argv=None) -> int:
    import argparse
    import sys
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db',type=Path,required=True)
    parser.add_argument('--tenant',required=True)
    actions=parser.add_subparsers(dest='action',required=True)
    for name in ('get','delete','rename','put'):
        a=actions.add_parser(name);a.add_argument('path')
        if name in ('put','delete','rename'):
            a.add_argument('--epoch',type=int,required=True)
            a.add_argument('--expect',type=int,required=True)
            a.add_argument('--op',required=True)
        if name=='put':
            for flag in ('manifest','archive','policy'):a.add_argument('--'+flag,required=True)
            a.add_argument('--bytes',type=int,required=True)
        if name=='rename':a.add_argument('--target',required=True)
    l=actions.add_parser('list');l.add_argument('--limit',type=int,default=100)
    l.add_argument('--after')
    actions.add_parser('status')
    f=actions.add_parser('fence');f.add_argument('--current',type=int,required=True)
    f.add_argument('--next',type=int,required=True)
    a=parser.parse_args(argv)
    try:
        with Namespace(a.db,tenant=a.tenant) as db:
            if a.action=='get':result=db.get(a.path)
            elif a.action=='list':result=db.list(limit=a.limit,after=a.after)
            elif a.action=='status':result=db.status()
            elif a.action=='fence':result={'epoch':db.fence(expected_epoch=a.current,new_epoch=a.next)}
            elif a.action=='put':result=db.put(a.path,a.manifest,a.archive,a.policy,a.bytes,
                epoch=a.epoch,expected_revision=a.expect,operation_id=a.op)
            elif a.action=='delete':result=db.delete(a.path,epoch=a.epoch,
                expected_revision=a.expect,operation_id=a.op)
            else:result=db.rename(a.path,a.target,epoch=a.epoch,
                expected_revision=a.expect,operation_id=a.op)
        print(_canonical(result));return 0
    except (NamespaceError,sqlite3.Error,OSError) as exc:
        print('NAMESPACE ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':
    raise SystemExit(main())
