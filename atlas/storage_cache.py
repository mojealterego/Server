"""Signed model manifests, bounded SMB/Rclone range reads and local verified cache."""
from __future__ import annotations
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from .artifacts import _private_dir, _check_digest
from .merkle import DEFAULT_CHUNK, make_manifest, validate_manifest, stage_from_reader
from tools.capctl import canonical, public, decode, openssl, read_json

SCHEMA='omega.storage.model.v1'
DOMAIN=b'OMEGA STORAGE model manifest v1\x00'
MAX_SIZE=32*1024**3
NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9_. +()-]{0,235}\.(?:gguf|safetensors|sft|onnx)\Z')
REMOTE=re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')

class CacheError(ValueError):pass


def require(ok,msg):
    if not ok:raise CacheError(msg)


def checked(m):
    require(isinstance(m,dict) and type(m.get('size_bytes')) is int and 0<m['size_bytes']<=MAX_SIZE and m.get('chunk_size')==DEFAULT_CHUNK,'Invalid model size or chunk geometry')
    require(isinstance(m.get('filename'),str) and NAME.fullmatch(m['filename']),'Unsafe model filename')
    validate_manifest(m)
    return m


def sign_manifest(source,key):
    source=Path(source);key=Path(key)
    require(NAME.fullmatch(source.name) and not source.is_symlink() and source.is_file() and 0<source.stat().st_size<=MAX_SIZE,'Invalid model source')
    st=key.lstat();require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode&0o077,'Private signing key required')
    pub=base64.b64encode(openssl('pkey','-in',key,'-passin','pass:','-pubout','-outform','DER')).decode();public(pub)
    body={'schema':SCHEMA,'public_key':pub,'manifest':checked(make_manifest(source))}
    with tempfile.TemporaryDirectory() as tmp:
        msg=Path(tmp)/'message';msg.write_bytes(DOMAIN+canonical(body))
        sig=openssl('pkeyutl','-sign','-inkey',key,'-passin','pass:','-rawin','-in',msg)
    require(len(sig)==64,'Invalid signature length')
    return {**body,'signature':base64.b64encode(sig).decode()}


def verify_manifest(envelope,pin,expected_sha):
    _check_digest(expected_sha);pub=public(pin)
    require(isinstance(envelope,dict) and set(envelope)=={'schema','public_key','manifest','signature'} and envelope['schema']==SCHEMA and envelope['public_key']==pin,'Untrusted model manifest')
    m=checked(envelope['manifest']);require(m['sha256']==expected_sha,'Model version SHA-256 pin mismatch')
    sig=decode(envelope['signature'],64)
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);msg=root/'message';key=root/'public';signature=root/'signature'
        msg.write_bytes(DOMAIN+canonical({k:v for k,v in envelope.items() if k!='signature'}));key.write_bytes(pub);signature.write_bytes(sig)
        openssl('pkeyutl','-verify','-pubin','-keyform','DER','-inkey',key,'-rawin','-in',msg,'-sigfile',signature)
    return json.loads(canonical(m))


def read_range(remote,offset,length,*,rclone='rclone',timeout=120):
    require(isinstance(remote,str) and ':' in remote and REMOTE.fullmatch(remote.split(':',1)[0]) and remote.split(':',1)[1].startswith('omega-models/') and NAME.fullmatch(remote.split('/',1)[1]),'Only an enrolled SMB model share is permitted')
    require(type(offset) is int and 0<=offset<MAX_SIZE and type(length) is int and 0<length<=DEFAULT_CHUNK and offset+length<=MAX_SIZE,'Invalid requested range')
    require(type(timeout) is int and 1<=timeout<=3600,'Invalid range timeout')
    try:
        with subprocess.Popen([rclone,'cat',remote,'--offset',str(offset),'--count',str(length)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as p:
            deadline=time.monotonic()+timeout;data=bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(p.stdout,selectors.EVENT_READ)
                    while True:
                        remaining=deadline-time.monotonic()
                        if remaining<=0 or not selector.select(remaining):raise CacheError('Range deadline exceeded')
                        chunk=os.read(p.stdout.fileno(),min(65536,length+1-len(data)))
                        if not chunk:break
                        data.extend(chunk);require(len(data)<=length,'Oversized range')
                require(p.wait(timeout=max(.01,deadline-time.monotonic()))==0 and len(data)==length,'Invalid remote range')
                return bytes(data)
            finally:
                if p.poll() is None:p.kill();p.wait()
    except (OSError,subprocess.SubprocessError) as exc:raise CacheError('Remote range failed') from exc


def stage(envelope,pin,expected_sha,cache,remotes,*,reader=read_range,reserve_bytes=512*1024**2):
    m=verify_manifest(envelope,pin,expected_sha);cache=Path(cache);_private_dir(cache)
    require(isinstance(remotes,list) and 1<=len(remotes)<=8 and all(isinstance(r,str) and REMOTE.fullmatch(r) for r in remotes) and len(set(remotes))==len(remotes),'Expected distinct configured remote names')
    require(type(reserve_bytes) is int and 0<=reserve_bytes<=MAX_SIZE,'Invalid disk reserve')
    final=cache/(m['sha256']+Path(m['filename']).suffix)
    lock=os.open(cache/'.storage-cache.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        st=os.fstat(lock);require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o077,'Unsafe cache lock')
        fcntl.flock(lock,fcntl.LOCK_EX)
        if not final.exists() and not final.is_symlink():
            # Conservative: reserve full object even if some partial bytes already exist.
            require(shutil.disk_usage(cache)[2]>=m['size_bytes']+reserve_bytes,'Insufficient cache free space')
        # Serial staging: prefer the last replica that supplied a verified block.
        preferred=remotes[0]
        def fetch(offset,length):
            nonlocal preferred
            want=m['chunks'][offset//DEFAULT_CHUNK]
            for alias in (preferred,*(r for r in remotes if r!=preferred)):
                try:
                    data=reader(alias+':omega-models/'+m['filename'],offset,length)
                    if isinstance(data,bytes) and len(data)==length and hashlib.sha256(data).hexdigest()==want:
                        preferred=alias
                        return data
                except (ValueError,OSError,RuntimeError,subprocess.SubprocessError):pass
            raise CacheError('No replica supplied a valid block at offset '+str(offset))
        result=stage_from_reader(final,m,fetch)
        return {**result,'path':str(final.absolute()),'filename':m['filename'],'size_bytes':m['size_bytes']}
    finally:os.close(lock)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('sign');s.add_argument('--source',type=Path,required=True);s.add_argument('--key',type=Path,required=True)
    v=sub.add_parser('verify');d=sub.add_parser('stage')
    for a in (v,d):
        a.add_argument('--manifest',type=Path,required=True);a.add_argument('--public-key',required=True);a.add_argument('--sha256',required=True)
    d.add_argument('--cache',type=Path,required=True);d.add_argument('--remote',action='append',required=True);d.add_argument('--reserve-mib',type=int,default=512)
    args=p.parse_args(argv)
    try:
        if args.cmd=='sign':result=sign_manifest(args.source,args.key)
        elif args.cmd=='verify':result=verify_manifest(read_json(args.manifest),args.public_key,args.sha256)
        else:result=stage(read_json(args.manifest),args.public_key,args.sha256,args.cache,args.remote,reserve_bytes=args.reserve_mib*1024**2)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,RuntimeError,TypeError,KeyError,RecursionError) as exc:
        print('STORAGE CACHE ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
