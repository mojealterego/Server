#!/usr/bin/env python3
"""Ed25519 node declarations with operator policy and durable replay admission."""
from __future__ import annotations
import argparse
import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA = 'omega.capabilities.v1'
DOMAIN = b'OMEGA-X capability declaration v1\x00'
FIELDS = {'id','ram_available_mb','ram_headroom_mb','disk_free_bytes','thermal_c','capabilities','models'}
POLICY = {'public_key','trust','priority','max_ram_mb','min_headroom_mb','max_disk_bytes','capabilities','models'}
SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
MAX_INT = 2**63-1

class CapabilityError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise CapabilityError(message)

def canonical(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')

def integer(v, low=0, high=MAX_INT):
    return type(v) is int and low <= v <= high

def names(v):
    return (isinstance(v,list) and len(v)<=512 and all(isinstance(x,str) and SAFE.fullmatch(x) for x in v)
            and len(set(v))==len(v))

def validate_node(n):
    require(isinstance(n,dict) and set(n)==FIELDS,'Invalid node fields')
    require(isinstance(n['id'],str) and SAFE.fullmatch(n['id']) and ':' not in n['id'],'Invalid node ID')
    require(all(integer(n[k]) for k in ('ram_available_mb','ram_headroom_mb','disk_free_bytes')),'Invalid capacity')
    t=n['thermal_c']
    require(type(t) in (float,int) and -40<=t<=150 and math.isfinite(t),'Unknown or invalid thermal reading')
    require(names(n['capabilities']) and names(n['models']),'Invalid capability/model identifiers')

def decode(v, size):
    require(isinstance(v,str) and len(v)<=4*((size+2)//3),'Invalid base64 field')
    try: raw=base64.b64decode(v,validate=True)
    except (ValueError,binascii.Error) as exc: raise CapabilityError('Invalid base64') from exc
    require(len(raw)==size and base64.b64encode(raw).decode()==v,'Invalid encoding/length')
    return raw

def public(v):
    raw=decode(v,44)
    require(raw.startswith(bytes.fromhex('302a300506032b6570032100')),'Expected Ed25519 SPKI')
    return raw

def openssl(*args):
    try:
        r=subprocess.run(['openssl',*map(str,args)],stdin=subprocess.DEVNULL,capture_output=True,timeout=10,check=True)
        return r.stdout
    except (OSError,subprocess.SubprocessError) as exc:
        raise CapabilityError('OpenSSL Ed25519 operation failed') from exc

def sign(node, key: Path, issued_ns=None):
    validate_node(node)
    stamp=time.time_ns() if issued_ns is None else issued_ns
    require(integer(stamp,1),'Invalid issuance timestamp')
    st=key.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode&0o077,'Private key must be owner-only regular file')
    pub=base64.b64encode(openssl('pkey','-in',key,'-passin','pass:','-pubout','-outform','DER')).decode()
    public(pub)
    body={'schema':SCHEMA,'issued_ns':stamp,'public_key':pub,'node':json.loads(canonical(node))}
    with tempfile.TemporaryDirectory() as tmp:
        msg=Path(tmp)/'message';msg.write_bytes(DOMAIN+canonical(body))
        sig=openssl('pkeyutl','-sign','-inkey',key,'-passin','pass:','-rawin','-in',msg)
    require(len(sig)==64,'Unexpected Ed25519 signature size')
    return {**body,'signature':base64.b64encode(sig).decode()}

def verify(envelope, policy, now, ttl):
    require(isinstance(envelope,dict) and set(envelope)=={'schema','issued_ns','public_key','node','signature'},'Invalid envelope')
    require(envelope['schema']==SCHEMA,'Unsupported schema')
    stamp=envelope['issued_ns'];require(integer(stamp,1),'Invalid issuance timestamp')
    require(now-ttl*10**9<=stamp<=now+30*10**9,'Expired or future declaration')
    n=envelope['node'];validate_node(n)
    require(n['id'] in policy,'Unregistered node')
    p=policy[n['id']];require(isinstance(p,dict) and set(p)==POLICY,'Invalid operator policy')
    require(p['trust'] in ('local','trusted','untrusted') and integer(p['priority'],0,1000000),'Invalid trust/priority')
    require(all(integer(p[k]) for k in ('max_ram_mb','min_headroom_mb','max_disk_bytes')),'Invalid capacity policy')
    require(names(p['capabilities']) and names(p['models']),'Invalid allowlist')
    pub=public(p['public_key']);require(envelope['public_key']==p['public_key'],'Unpinned node key')
    require(n['ram_available_mb']<=p['max_ram_mb'] and n['ram_headroom_mb']>=p['min_headroom_mb']
            and n['disk_free_bytes']<=p['max_disk_bytes'],'Capacity exceeds operator policy')
    require(set(n['capabilities'])<=set(p['capabilities']) and set(n['models'])<=set(p['models']),'Unauthorized capability/model')
    sig=decode(envelope['signature'],64)
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);msg=root/'msg';key=root/'pub';signature=root/'sig'
        msg.write_bytes(DOMAIN+canonical({k:v for k,v in envelope.items() if k!='signature'}))
        key.write_bytes(pub);signature.write_bytes(sig)
        openssl('pkeyutl','-verify','-pubin','-keyform','DER','-inkey',key,'-rawin','-in',msg,'-sigfile',signature)
    return {**n,'trust':p['trust'],'priority':p['priority']},stamp

def admit(envelopes, policy, db: Path, *, now_ns=None, ttl=120):
    require(integer(ttl,1,300),'TTL must be 1..300 seconds')
    require(isinstance(envelopes,list) and 1<=len(envelopes)<=8,'Expected 1..8 declarations')
    require(isinstance(policy,dict) and 1<=len(policy)<=256,'Invalid trust registry')
    keys=[public(p['public_key']) for p in policy.values() if isinstance(p,dict) and 'public_key' in p]
    require(len(keys)==len(policy) and len(set(keys))==len(keys),'Each node needs a distinct pinned key')
    now=time.time_ns() if now_ns is None else now_ns
    require(integer(now,1),'Invalid clock')
    checked=[verify(e,policy,now,ttl) for e in envelopes]
    require(len({n['id'] for n,_ in checked})==len(checked),'Duplicate nodes in batch')
    # Operator owns this directory and DB; do not place in untrusted shared storage.
    parent=db.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and not parent.st_mode&0o077,'Replay DB requires private owner directory')
    fd=os.open(db,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode&0o077,'Replay DB must be private')
    finally:os.close(fd)
    connection=sqlite3.connect(db,timeout=5,isolation_level=None)
    try:
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('CREATE TABLE IF NOT EXISTS accepted(node TEXT PRIMARY KEY, issued_ns INTEGER NOT NULL)')
        connection.execute('BEGIN IMMEDIATE')
        for n,stamp in checked:
            row=connection.execute('SELECT issued_ns FROM accepted WHERE node=?',(n['id'],)).fetchone()
            require(row is None or stamp>row[0],'Replay or out-of-order declaration')
            connection.execute('INSERT INTO accepted VALUES(?,?) ON CONFLICT(node) DO UPDATE SET issued_ns=excluded.issued_ns',(n['id'],stamp))
        connection.execute('COMMIT')
    except BaseException:
        if connection.in_transaction:connection.rollback()
        raise
    finally:connection.close()
    return sorted((n for n,_ in checked),key=lambda n:n['id'])

def read_json(path):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'Duplicate JSON field');result[k]=v
        return result
    with path.open('rb') as f: raw=f.read(1024*1024+1)
    require(len(raw)<=1024*1024,'JSON exceeds 1 MiB')
    return json.loads(raw,object_pairs_hook=unique)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('sign');s.add_argument('--node',type=Path,required=True);s.add_argument('--key',type=Path,required=True)
    a=sub.add_parser('admit');a.add_argument('--envelopes',type=Path,required=True,nargs='+');a.add_argument('--policy',type=Path,required=True)
    a.add_argument('--db',type=Path,required=True);a.add_argument('--ttl',type=int,default=120)
    args=parser.parse_args(argv)
    try:
        out=sign(read_json(args.node),args.key) if args.cmd=='sign' else admit([read_json(x) for x in args.envelopes],read_json(args.policy),args.db,ttl=args.ttl)
        print(json.dumps(out,sort_keys=True,indent=2,allow_nan=False));return 0
    except (ValueError,OSError,sqlite3.Error,KeyError,TypeError,RecursionError) as exc:
        print('CAPCTL ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
