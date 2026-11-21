"""E17a signed opt-in edge enrollment, bounded challenge and replay protection.

Authorizes a declared owner/node identity only. Does not attest hardware,
capacity, connectivity or independent failure domains. Local SQLite only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from .global_namespace import identity, integer

SCHEMA = 'omega.edge.grant.v1'
FIELDS = frozenset({'schema','grant_id','node_id','tenant','owner_id',
                    'node_public_key','domain_claim','max_bytes','not_before','expires_at'})


class EdgeError(ValueError):
    pass


def require(ok, message):
    if not ok: raise EdgeError(message)


def canon(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def _raw_public(value):
    require(type(value) is bytes and len(value)==32,'Invalid Ed25519 key')
    try: return Ed25519PublicKey.from_public_bytes(value)
    except ValueError:raise EdgeError('Invalid Ed25519 public key') from None


def _decode_hex(value,size):
    require(type(value) is str and len(value)==size*2 and
            all(x in '0123456789abcdef' for x in value),'Malformed signature or public key')
    return bytes.fromhex(value)


def issue_grant(operator_key:Ed25519PrivateKey, *, node_id:str, tenant:str,
                owner_id:str, node_public_key:bytes, domain_claim:str,
                max_bytes:int, not_before:int, expires_at:int)->dict:
    require(isinstance(operator_key,Ed25519PrivateKey),'Operator signer unavailable')
    try:
        for v in (node_id,tenant,owner_id,domain_claim): identity(v)
        integer(max_bytes,1);integer(not_before,1);integer(expires_at,1)
    except ValueError as exc:raise EdgeError('Invalid grant claim') from exc
    require(expires_at>not_before and expires_at-not_before<=31*86400,
            'Grant lifetime exceeds maximum')
    _raw_public(node_public_key)
    doc={'schema':SCHEMA,'grant_id':secrets.token_hex(16),'node_id':node_id,
         'tenant':tenant,'owner_id':owner_id,
         'node_public_key':node_public_key.hex(),'domain_claim':domain_claim,
         'max_bytes':max_bytes,'not_before':not_before,'expires_at':expires_at}
    return {**doc,'signature':operator_key.sign(canon(doc)).hex()}


def proof_for_challenge(node_key:Ed25519PrivateKey,grant:dict,challenge:str)->str:
    require(isinstance(node_key,Ed25519PrivateKey),'Node signer unavailable')
    return node_key.sign(b'OMEGA-E17a-PROOF\x00'+_decode_hex(challenge,32)+
                         hashlib.sha256(canon(grant)).digest()).hex()


class EdgeRegistry:
    def __init__(self,path:Path,operator_public_key:bytes):
        self.pub=operator_public_key
        _raw_public(self.pub)
        self.path=Path(path);parent=self.path.parent
        require(parent.is_dir() and not parent.is_symlink(),'Missing registry directory')
        info=parent.stat()
        require(info.st_uid==os.getuid() and not info.st_mode&0o077,'Registry parent not private')
        require(not self.path.is_symlink(),'Registry database cannot be a symlink')
        if self.path.exists():
            st=self.path.stat()
            require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and
                    not st.st_mode&0o077,'Unsafe registry database')
        else:
            try: fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            except FileExistsError: raise EdgeError('Concurrent registry creation') from None
            else:os.close(fd)
        self.db=sqlite3.connect(self.path,isolation_level=None,timeout=3)
        try:
            self.db.execute('PRAGMA busy_timeout=3000')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
CREATE TABLE IF NOT EXISTS authority(id INTEGER PRIMARY KEY CHECK(id=1),
                       epoch INTEGER NOT NULL, operator_pin TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY, node_id TEXT NOT NULL,
                                      expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS nodes(node_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,
                     owner_id TEXT NOT NULL,pubkey TEXT NOT NULL,domain_claim TEXT NOT NULL,
                     max_bytes INTEGER NOT NULL,expires_at INTEGER NOT NULL,
                     epoch INTEGER NOT NULL,grant_id TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
''')
            pin=hashlib.sha256(self.pub).hexdigest()
            self.db.execute('INSERT OR IGNORE INTO authority VALUES(1,1,?)',(pin,))
            require(self.db.execute('SELECT operator_pin FROM authority WHERE id=1').fetchone()==(pin,),
                    'Operator identity differs from pinned registry key')
        except BaseException:
            self.db.close();raise

    def close(self):self.db.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

    def challenge(self,node_id:str,*,now:int)->str:
        try:identity(node_id);integer(now,1)
        except ValueError as exc:raise EdgeError('Invalid challenge request') from exc
        nonce=secrets.token_hex(32)
        self.db.execute('INSERT INTO challenges VALUES(?,?,?,0)',(nonce,node_id,now+60))
        return nonce

    def enroll(self,grant:dict,challenge:str,proof:str,*,now:int,epoch:int)->dict:
        try:integer(now,1);integer(epoch,1)
        except ValueError as exc:raise EdgeError('Invalid timestamp or epoch') from exc
        require(type(grant) is dict and set(grant)==FIELDS|{'signature'} and
                grant.get('schema')==SCHEMA,'Invalid signed grant shape')
        try:
            for f in ('grant_id','node_id','owner_id','tenant','domain_claim'):identity(grant[f])
            integer(grant['max_bytes'],1);integer(grant['not_before'],1);integer(grant['expires_at'],1)
        except ValueError as exc:raise EdgeError('Invalid signed grant identity') from exc
        require(grant['expires_at']>grant['not_before'] and
                grant['expires_at']-grant['not_before']<=31*86400 and
                grant['not_before']<=now<grant['expires_at'], 'Expired or future grant')
        public=_decode_hex(grant['node_public_key'],32)
        op_sig=_decode_hex(grant['signature'],64)
        node_sig=_decode_hex(proof,64)
        token=_decode_hex(challenge,32)
        unsigned={k:v for k,v in grant.items() if k!='signature'}
        try:
            _raw_public(self.pub).verify(op_sig,canon(unsigned))
            _raw_public(public).verify(node_sig,b'OMEGA-E17a-PROOF\x00'+token+
                                       hashlib.sha256(canon(grant)).digest())
        except InvalidSignature:raise EdgeError('Grant or possession signature rejected') from None
        try:
            self.db.execute('BEGIN IMMEDIATE')
            current=self.db.execute('SELECT epoch FROM authority WHERE id=1').fetchone()[0]
            require(current==epoch,'Stale registry authority')
            row=self.db.execute('SELECT node_id,expires,used FROM challenges WHERE nonce=?',
                                (challenge,)).fetchone()
            require(row is not None and row[0]==grant['node_id'] and
                    row[1]>=now and row[2]==0,'Expired or replayed challenge')
            require(self.db.execute('SELECT 1 FROM nodes WHERE node_id=?',
                                   (grant['node_id'],)).fetchone() is None,
                    'Node already enrolled or revoked')
            self.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?,?,0)',
                            (grant['node_id'],grant['tenant'],grant['owner_id'],
                             grant['node_public_key'],grant['domain_claim'],grant['max_bytes'],
                             grant['expires_at'],epoch,grant['grant_id']))
            self.db.execute('UPDATE challenges SET used=1 WHERE nonce=?',(challenge,))
            self.db.execute('COMMIT')
            return {'node_id':grant['node_id'],'tenant':grant['tenant'],
                    'trust':'OPERATOR_AUTHORIZED_NOT_PHYSICALLY_ATTESTED'}
        except (EdgeError,sqlite3.Error) as exc:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            if isinstance(exc,EdgeError):raise
            raise EdgeError('Registry transaction aborted') from exc

    def status(self,node_id:str,*,tenant:str)->dict|None:
        try:identity(node_id);identity(tenant)
        except ValueError as exc:raise EdgeError('Invalid tenant scope') from exc
        row=self.db.execute('SELECT node_id,owner_id,domain_claim,max_bytes,expires_at '
                            'FROM nodes WHERE node_id=? AND tenant=? AND revoked=0',
                            (node_id,tenant)).fetchone()
        return dict(zip(('node_id','owner_id','domain_claim','max_bytes','expires_at'),row)) if row else None

    def revoke(self,node_id:str,*,epoch:int)->None:
        try:identity(node_id);integer(epoch,1)
        except ValueError as exc:raise EdgeError('Invalid revocation') from exc
        try:
            self.db.execute('BEGIN IMMEDIATE')
            current=self.db.execute('SELECT epoch FROM authority WHERE id=1').fetchone()[0]
            require(current==epoch,'Stale registry authority')
            changed=self.db.execute('UPDATE nodes SET revoked=1 WHERE node_id=? AND revoked=0',
                                    (node_id,)).rowcount
            require(changed==1,'Unknown or already revoked node')
            self.db.execute('COMMIT')
        except (EdgeError,sqlite3.Error) as exc:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            if isinstance(exc,EdgeError):raise
            raise EdgeError('Revocation transaction aborted') from exc

    def fence(self,*,expected_epoch:int,new_epoch:int)->int:
        try:integer(expected_epoch,1);integer(new_epoch,2)
        except ValueError as exc:raise EdgeError('Invalid fence epoch') from exc
        require(new_epoch>expected_epoch,'Nonmonotonic registry fence')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            current=self.db.execute('SELECT epoch FROM authority WHERE id=1').fetchone()[0]
            require(current==expected_epoch,'Stale authority')
            self.db.execute('UPDATE authority SET epoch=? WHERE id=1',(new_epoch,))
            self.db.execute('COMMIT');return new_epoch
        except (EdgeError,sqlite3.Error) as exc:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            if isinstance(exc,EdgeError):raise
            raise EdgeError('Fence transaction aborted') from exc
