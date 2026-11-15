#!/usr/bin/env python3
"""OMEGA-X v2: streaming SHA-256 snapshot integrity and HMAC commit receipts.

This is an *offline authenticity check* with a locally held secret. It does not
prove remote cloud durability or 3-2-1 independence. No external dependencies.
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys

SCHEMA='omega.snapshot.v2'
META=frozenset({'SHA256SUMS','COMPLETE.json'})
LINE=re.compile(r'^([a-f0-9]{64})  (.+)$')
ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{5,79}$')


def hash_file(path:Path)->str:
    digest=hashlib.sha256()
    with path.open('rb') as src:
        for buf in iter(lambda:src.read(4*1024*1024),b''):
            digest.update(buf)
    return digest.hexdigest()


def safe_name(relative:str)->bool:
    if not relative or any(ch in relative for ch in ('\\','\r','\n','\x00')):
        return False
    pure=PurePosixPath(relative)
    return (not pure.is_absolute() and not any(x in ('','.','..') for x in relative.split('/'))
            and str(pure)==relative and relative.split('/')[0]!='.omega')


def files_in(root:Path,*,snapshot:bool=False)->list[tuple[str,Path]]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError('Source directory missing or symlink')
    out=[]
    for base, dirs, names in os.walk(root,followlinks=False):
        folder=Path(base)
        for d in dirs:
            if (folder/d).is_symlink():
                raise ValueError('Source contains symlink directory')
        for name in names:
            p=folder/name
            rel=p.relative_to(root).as_posix()
            if snapshot and rel in META:continue
            if not snapshot and rel in META:
                raise ValueError(f'Reserved snapshot metadata filename: {rel}')
            if not safe_name(rel):raise ValueError(f'Unsafe filename: {rel!r}')
            if p.is_symlink() or not p.is_file() or not stat.S_ISREG(p.stat().st_mode):
                raise ValueError(f'Source contains symlink or nonregular file: {rel}')
            out.append((rel,p))
    return sorted(out)


def create(root:Path,output:Path)->int:
    if output.is_relative_to(root):
        raise ValueError('Manifest output must be outside source directory')
    out=[]
    for rel,p in files_in(root):
        out.append(f'{hash_file(p)}  {rel}')
    # Use exclusive temp and atomic rename; caller isolates output path.
    tmp=output.with_name('.'+output.name+'.tmp-'+secrets.token_hex(4))
    try:
        with tmp.open('x',encoding='utf-8') as f:
            os.chmod(tmp,0o600)
            f.write('\n'.join(out)+'\n')
            f.flush();os.fsync(f.fileno())
        tmp.replace(output)
    finally:tmp.unlink(missing_ok=True)
    return len(out)


def entries(manifest:Path)->dict[str,str]:
    result={}
    for line in manifest.read_text(encoding='utf-8').splitlines():
        if not line:continue
        match=LINE.fullmatch(line)
        if not match:raise ValueError('Invalid manifest line')
        digest,rel=match.groups()
        if not safe_name(rel) or rel in META:raise ValueError('Unsafe path in manifest')
        if rel in result:raise ValueError('Duplicate path in manifest')
        result[rel]=digest
    return result


def verify_files(root:Path,manifest:Path,*,snapshot:bool=False)->int:
    records=entries(manifest)
    found={rel:p for rel,p in files_in(root,snapshot=snapshot)}
    if records.keys()!=found.keys():
        missing=set(records)-set(found)
        unexpected=set(found)-set(records)
        raise ValueError(f'Manifest set mismatch: missing={sorted(missing)} extra={sorted(unexpected)}')
    for rel,digest in records.items():
        if not hmac.compare_digest(hash_file(found[rel]),digest):
            raise ValueError(f'Content SHA-256 mismatch: {rel}')
    return len(records)


def keyfile(path:Path,*,generate:bool=False)->bytes:
    if generate and not path.exists():
        path.parent.mkdir(parents=True,exist_ok=True)
        os.chmod(path.parent,0o700)
        try:
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(secrets.token_bytes(32));f.flush();os.fsync(f.fileno())
        except FileExistsError:
            pass
    if path.is_symlink() or not path.is_file():
        raise ValueError('Private HMAC key missing or unsafe')
    if path.stat().st_mode & 0o077:
        raise ValueError('Private HMAC key file permissions must be 0600')
    key=path.read_bytes()
    if len(key)<32:raise ValueError('HMAC key requires at least 32 random bytes')
    return key


def signature_payload(snapshot_id:str,digest:str)->bytes:
    return f'{SCHEMA}\n{snapshot_id}\n{digest}\n'.encode('ascii')


def seal(folder:Path,snapshot_id:str,key_path:Path)->dict:
    if not ID.fullmatch(snapshot_id):raise ValueError('Invalid snapshot ID')
    if not (folder/'SHA256SUMS').is_file():raise ValueError('SHA256SUMS missing')
    key=keyfile(key_path)
    digest=hash_file(folder/'SHA256SUMS')
    record={'schema':SCHEMA,'snapshot_id':snapshot_id,'manifest_sha256':digest,
            'hmac_sha256':hmac.new(key,signature_payload(snapshot_id,digest),hashlib.sha256).hexdigest()}
    output=folder/'COMPLETE.json'
    if output.exists():raise ValueError('Commit record already exists')
    with output.open('x',encoding='utf-8') as f:
        os.chmod(output,0o600)
        json.dump(record,f,sort_keys=True,indent=2)
        f.write('\n');f.flush();os.fsync(f.fileno())
    return record


def verify(folder:Path,key_path:Path,expected_id:str|None=None)->int:
    marker=json.loads((folder/'COMPLETE.json').read_text(encoding='utf-8'))
    if not isinstance(marker,dict) or set(marker)!= {'schema','snapshot_id','manifest_sha256','hmac_sha256'}:
        raise ValueError('Invalid snapshot receipt structure')
    if marker['schema']!=SCHEMA or not isinstance(marker['snapshot_id'],str) or not ID.fullmatch(marker['snapshot_id']):
        raise ValueError('Invalid snapshot receipt')
    if expected_id is not None and marker['snapshot_id']!=expected_id:
        raise ValueError('Unexpected snapshot identifier')
    digest=hash_file(folder/'SHA256SUMS')
    if not hmac.compare_digest(marker['manifest_sha256'],digest):
        raise ValueError('Manifest hash mismatch')
    key=keyfile(key_path)
    mac=hmac.new(key,signature_payload(marker['snapshot_id'],digest),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(marker['hmac_sha256'],mac):
        raise ValueError('HMAC authentication failed')
    return verify_files(folder,folder/'SHA256SUMS',snapshot=True)


def main(argv=None)->int:
    p=argparse.ArgumentParser(description='OMEGA-X v2 authentic snapshots')
    sp=p.add_subparsers(dest='command',required=True)
    x=sp.add_parser('create');x.add_argument('source',type=Path);x.add_argument('manifest',type=Path)
    x=sp.add_parser('verify-files');x.add_argument('source',type=Path);x.add_argument('manifest',type=Path)
    x=sp.add_parser('keygen');x.add_argument('key',type=Path)
    x=sp.add_parser('seal');x.add_argument('folder',type=Path);x.add_argument('id');x.add_argument('key',type=Path)
    x=sp.add_parser('verify');x.add_argument('folder',type=Path);x.add_argument('key',type=Path);x.add_argument('--id')
    a=p.parse_args(argv)
    try:
        if a.command=='create':count=create(a.source,a.manifest)
        elif a.command=='verify-files':count=verify_files(a.source,a.manifest)
        elif a.command=='keygen':keyfile(a.key,generate=True);count=0
        elif a.command=='seal':seal(a.folder,a.id,a.key);count=0
        else:count=verify(a.folder,a.key,a.id)
        print(f'OMEGA SNAPSHOT {a.command} OK files={count}')
        return 0
    except (ValueError,OSError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print(f'OMEGA SNAPSHOT {a.command} FAIL: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
