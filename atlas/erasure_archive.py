"""E15: authenticated encrypted erasure archive using local E14 CAS + E13 quotas.

Systematic RS 4+2/8+3 operates on E14 AES-GCM ciphertext, never plaintext.
A separate HMAC-authenticated and externally SHA-pinned manifest binds exact
shard digests, placement, policy and geometry. Local volumes must be private.

This is a real single-host implementation, NOT a distributed SMB filesystem,
cloud adapter, physical failure-domain proof or zero-cost provider guarantee.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from typing import Any

from . import reed_solomon as rs
from . import secure_fabric as secure
from . import quota_ledger as quotas
from . import provider_registry as providers

SCHEMA = 'omega.erasure-archive.v1'
MAX_BLOCKS = 16384
MAX_FILE = MAX_BLOCKS * secure.MAX_BLOCK


class ErasureArchiveError(ValueError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ErasureArchiveError(why)


def digest(doc: dict[str, Any]) -> str:
    return secure.hexdigest(secure.canon(doc))


def _mac_key(root: bytes) -> bytes:
    require(type(root) is bytes and len(root) == 32, 'Invalid root key')
    return hmac.digest(root, b'OMEGA-E15-MANIFEST-v1', 'sha256')


def sign(doc: dict[str, Any], root: bytes) -> dict[str, Any]:
    require(type(doc) is dict and 'mac' not in doc, 'Invalid unsigned manifest')
    return {**doc,'mac':hmac.new(_mac_key(root),secure.canon(doc),hashlib.sha256).hexdigest()}


def _profile(k: int, parity: int) -> None:
    require(type(k) is int and type(parity) is int and (k,parity) in rs.PROFILES,
            'Unsupported erasure profile')


def verify_manifest(doc: dict[str, Any], root: bytes, pin: str) -> None:
    require(type(doc) is dict and set(doc)=={'schema','archive','policy_sha256','size_bytes',
            'chunk_bytes','k','parity','sha256','key_id','stores','blocks','mac'},
            'Malformed erasure manifest')
    require(doc['schema']==SCHEMA and secure.valid_hex(pin) and
            secure.valid_archive(doc['archive']) and
            secure.valid_hex(doc['policy_sha256']) and secure.valid_hex(doc['sha256'])
            and doc['key_id']==secure.hexdigest(root)[:16], 'Invalid archive identity')
    _profile(doc['k'],doc['parity'])
    k,p=doc['k'],doc['parity']
    require(type(doc['chunk_bytes']) is int and secure.MIN_BLOCK<=doc['chunk_bytes']<=secure.MAX_BLOCK
            and type(doc['size_bytes']) is int and 0<doc['size_bytes']<=MAX_FILE,
            'Invalid manifest geometry')
    unsigned={key:value for key,value in doc.items() if key!='mac'}
    expected=hmac.new(_mac_key(root),secure.canon(unsigned),hashlib.sha256).hexdigest()
    require(secure.valid_hex(doc['mac']) and hmac.compare_digest(doc['mac'],expected)
            and hmac.compare_digest(digest(doc),pin), 'Unauthenticated erasure manifest')
    stores=doc['stores']
    require(type(stores) is list and len(stores)==k+p, 'Incorrect store inventory')
    names=[];domains=[]
    for row in stores:
        require(type(row) is dict and set(row)=={'pool','domain','adapter'}
                and isinstance(row['pool'],str) and providers.IDENT.fullmatch(row['pool'])
                and isinstance(row['domain'],str) and providers.IDENT.fullmatch(row['domain'])
                and row['adapter']=='local', 'Invalid enrolled local store')
        names.append(row['pool']);domains.append(row['domain'])
    require(len(set(names))==len(names) and len(set(domains))==len(domains),
            'Duplicate store or failure domain')
    blocks=doc['blocks']
    expected_count=(doc['size_bytes']+doc['chunk_bytes']-1)//doc['chunk_bytes']
    require(type(blocks) is list and 1<=len(blocks)==expected_count<=MAX_BLOCKS,
            'Invalid block count')
    consumed=0
    for idx, block in enumerate(blocks):
        require(type(block) is dict and set(block)=={'index','length','plain_sha256',
                'cipher_len','cipher_sha256','shards'},'Invalid block structure')
        length=min(doc['chunk_bytes'],doc['size_bytes']-consumed)
        cipher_len=length+len(secure.MAGIC)+28
        shard_len=(cipher_len+k-1)//k
        require(type(block['index']) is int and block['index']==idx
                and type(block['length']) is int and block['length']==length
                and type(block['cipher_len']) is int and block['cipher_len']==cipher_len
                and secure.valid_hex(block['cipher_sha256']) and
                secure.valid_hex(block['plain_sha256']), 'Invalid block geometry/digest')
        shards=block['shards']
        require(type(shards) is list and len(shards)==k+p,'Incomplete shard inventory')
        for j,entry in enumerate(shards):
            require(type(entry) is dict and set(entry)=={'pool','sha256','size'} and
                    type(entry['pool']) is str and entry['pool']==names[j] and
                    type(entry['size']) is int and entry['size']==shard_len and
                    secure.valid_hex(entry['sha256']), 'Invalid shard placement')
        consumed+=length
    require(consumed==doc['size_bytes'],'Incomplete file geometry')


def _stores(stores: dict[str,secure.LocalStore],k:int,parity:int) -> list[str]:
    _profile(k,parity)
    require(type(stores) is dict and len(stores)==k+parity,
            'Need exactly k+m registered local stores')
    names=sorted(stores)
    domains=[]
    for name in names:
        store=stores[name]
        require(isinstance(name,str) and providers.IDENT.fullmatch(name) and
                isinstance(store,secure.LocalStore) and store.pool==name and
                isinstance(store.domain,str) and providers.IDENT.fullmatch(store.domain) and
                store.adapter=='local', 'Invalid store enrollment')
        domains.append(store.domain)
    require(len(set(domains))==len(domains),'Shard stores share a declared failure domain')
    return names


def _invoice(stripes:list[tuple[int,int]],k:int)->dict[str,int]:
    count=len(stripes)
    needed=sum((n+len(secure.MAGIC)+28+k-1)//k for _,n in stripes)
    return {field:(needed if field in ('storage_bytes','write_bytes','read_bytes')
                   else count if field in ('write_ops','read_ops') else 0)
            for field in quotas.FIELDS}


def _geometry(size:int, chunk_bytes:int)->list[tuple[int,int]]:
    require(type(chunk_bytes) is int and secure.MIN_BLOCK<=chunk_bytes<=secure.MAX_BLOCK
            and type(size) is int and 0<size<=MAX_FILE,
            'Invalid stripe geometry')
    expected=(size+chunk_bytes-1)//chunk_bytes
    require(1<=expected<=MAX_BLOCKS,'Too many stripes')
    return [(index,min(chunk_bytes,size-index*chunk_bytes)) for index in range(expected)]


def _publish(payload:bytes,dest:Path) -> None:
    dest=Path(dest)
    require(dest.parent.is_dir() and not dest.parent.is_symlink()
            and dest.parent.stat().st_uid==os.getuid() and
            not dest.parent.stat().st_mode & 0o077 and
            not dest.exists() and not dest.is_symlink(), 'Unsafe output destination')
    handle,tmp=tempfile.mkstemp(prefix='.omega-e15-',dir=dest.parent)
    try:
        with os.fdopen(handle,'wb') as out:
            os.fchmod(out.fileno(),0o600)
            out.write(payload);out.flush();os.fsync(out.fileno())
        os.link(tmp,dest,follow_symlinks=False)
        secure._fsync_dir(dest.parent)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _read(doc:dict[str,Any], stores:dict[str,secure.LocalStore], index:int,
          key:bytes, *, all_shards:bool=False)->tuple[bytes,list[bytes],list[int]]:
    block=doc['blocks'][index]
    available={}; missing=[]
    for shard_index, entry in enumerate(block['shards']):
        pool=entry['pool']
        if pool not in stores:
            missing.append(shard_index);continue
        store=stores[pool]
        require(store.pool==pool and store.domain==doc['stores'][shard_index]['domain'] and
                store.adapter=='local','Store identity changed')
        try:
            data=store.get(doc['archive'],index,entry['sha256'],entry['size'])
            available[shard_index]=data
        except (OSError,ValueError):
            missing.append(shard_index)
    require(len(available)>=doc['k'] and len(missing)<=doc['parity'],
            'Not enough authenticated fragments')
    try:
        recovered=rs.recover(available,length=block['cipher_len'],k=doc['k'],parity=doc['parity'])
    except rs.ErasureError as exc:
        raise ErasureArchiveError('Erasure reconstruction failed') from exc
    for entry, data in zip(block['shards'],recovered):
        require(secure.hexdigest(data)==entry['sha256'], 'Reconstructed fragment hash mismatch')
    frame=b''.join(recovered[:doc['k']])[:block['cipher_len']]
    require(secure.hexdigest(frame)==block['cipher_sha256'], 'Ciphertext digest mismatch')
    try:
        plain=secure.decrypt_chunk(key,doc['archive'],index,doc['policy_sha256'],frame,block['length'])
    except (secure.InvalidTag,ValueError) as exc:
        raise ErasureArchiveError('Failed authenticated chunk decryption') from exc
    require(secure.hexdigest(plain)==block['plain_sha256'],'Plaintext digest mismatch')
    return plain,recovered,missing


def ingest(source:Path, manifest:Path, *, key_path:Path, policy_sha256:str,
           stores:dict[str,secure.LocalStore],ledger:quotas.Ledger,epoch:int,
           archive_id:str,chunk_bytes:int=4*1024*1024,k:int|None=None,parity:int|None=None,
           now:int|None=None)->dict[str,Any]:
    """Encrypted RS stripes written durably to exactly k+m private local CAS roots."""
    if k is None and parity is None:k,parity=rs.select_profile(len(stores))
    _profile(k,parity)
    names=_stores(stores,k,parity)
    require(secure.valid_archive(archive_id) and secure.valid_hex(policy_sha256),
            'Invalid archive or policy pin')
    source=Path(source);manifest=Path(manifest)
    require(source.is_file() and not source.is_symlink(),'Unsafe input')
    require(manifest.parent.is_dir() and not manifest.parent.is_symlink() and
            manifest.parent.stat().st_uid==os.getuid() and
            not manifest.parent.stat().st_mode & 0o077 and
            not manifest.exists() and not manifest.is_symlink(),'Manifest cannot overwrite')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode),'Source must be regular')
        stripes=_geometry(before.st_size,chunk_bytes)
    finally:os.close(fd)
    key=secure.private_key(key_path)
    timestamp=int(time.time()) if now is None else now
    charges=_invoice(stripes,k)
    reserved=[];touched=False
    clock=(lambda: int(time.time())) if now is None else (lambda: now)
    try:
        for pool in names:
            reservation=ledger.reserve(pool,archive_id,charges,epoch=epoch,ttl=3600,now=timestamp)
            require(reservation['state']=='HELD','Archive already committed')
            reserved.append(pool)
        fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            opened=os.fstat(fd)
            require((opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)==
                    (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),
                    'Source changed between admission and read')
            hasher=hashlib.sha256();blocks=[];renewal=timestamp
            with os.fdopen(os.dup(fd),'rb') as inp:
                for index,length in stripes:
                    current=clock()
                    if current-renewal>=600:
                        for pool in reserved:
                            ledger.renew(pool,archive_id,epoch=epoch,ttl=3600,now=current)
                        renewal=current
                    plain=inp.read(length)
                    require(len(plain)==length,'Truncated source')
                    hasher.update(plain)
                    frame=secure.encrypt_chunk(key,archive_id,index,policy_sha256,plain)
                    shards=rs.encode(frame,k=k,parity=parity)
                    entries=[]
                    for pool,shard in zip(names,shards):
                        ledger.require_active(pool,archive_id,epoch=epoch,now=clock())
                        value=secure.hexdigest(shard)
                        touched=True
                        stores[pool].put(archive_id,index,value,shard)
                        require(stores[pool].get(archive_id,index,value,len(shard))==shard,
                                'Shard failed readback')
                        entries.append({'pool':pool,'sha256':value,'size':len(shard)})
                    blocks.append({'index':index,'length':length,
                                   'plain_sha256':secure.hexdigest(plain),
                                   'cipher_len':len(frame),'cipher_sha256':secure.hexdigest(frame),
                                   'shards':entries})
                require(not inp.read(1),'Source grew')
            after=os.fstat(fd)
        finally:os.close(fd)
        require((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),
                'Source changed during read')
        doc={'schema':SCHEMA,'archive':archive_id,'policy_sha256':policy_sha256,
             'size_bytes':before.st_size,'chunk_bytes':chunk_bytes,'k':k,'parity':parity,
             'sha256':hasher.hexdigest(),'key_id':secure.hexdigest(key)[:16],
             'stores':[{'pool':name,'domain':stores[name].domain,'adapter':'local'} for name in names],
             'blocks':blocks}
        signed=sign(doc,key);pin=digest(signed)
        verify_manifest(signed,key,pin)
        for pool in reserved:ledger.commit(pool,archive_id,epoch=epoch,now=clock())
        _publish(secure.canon(signed),manifest)
        size=sum(e['size'] for block in blocks for e in block['shards'])
        return {'status':'STAGED_ERASURE_ENCRYPTED','manifest_sha256':pin,
                'sha256':hasher.hexdigest(),'profile':f'{k}+{parity}',
                'chunks':len(blocks),'stored_shard_bytes':size}
    except BaseException:
        for pool in reserved:
            try:
                if touched:ledger.uncertain(pool,archive_id,epoch=epoch,now=timestamp)
                else:ledger.release_unwritten(pool,archive_id,epoch=epoch,
                                              no_side_effects=True,now=timestamp)
            except (quotas.QuotaError,OSError):pass
        raise


def _verified(manifest:Path,pin:str,key_path:Path)->tuple[dict[str,Any],bytes]:
    try:
        raw=secure._read_manifest(manifest)
        def unique(pairs):
            out={}
            for k,v in pairs:
                require(k not in out,'Duplicate manifest JSON keys')
                out[k]=v
            return out
        def reject_nonfinite(_value: str):
            raise ErasureArchiveError('Non-finite JSON token')
        doc=json.loads(raw,object_pairs_hook=unique,parse_constant=reject_nonfinite)
        key=secure.private_key(key_path)
        verify_manifest(doc,key,pin)
        return doc,key
    except (ValueError,TypeError,UnicodeError,RecursionError) as exc:
        raise ErasureArchiveError('Invalid erasure manifest') from exc


def restore(manifest:Path,pin:str,destination:Path,*,key_path:Path,
            stores:dict[str,secure.LocalStore])->dict[str,Any]:
    doc,key=_verified(manifest,pin,key_path)
    target=Path(destination)
    require(target.parent.is_dir() and not target.parent.is_symlink() and
            target.parent.stat().st_uid==os.getuid() and not target.parent.stat().st_mode & 0o077
            and not target.exists() and not target.is_symlink(),'Unsafe recovery destination')
    require(type(stores) is dict and stores and
            set(stores)<=set(row['pool'] for row in doc['stores']),'Unenrolled recovery store')
    h=hashlib.sha256()
    handle,tmp=tempfile.mkstemp(prefix='.omega-e15-restore-',dir=target.parent)
    try:
        with os.fdopen(handle,'wb') as output:
            os.fchmod(output.fileno(),0o600)
            for index in range(len(doc['blocks'])):
                plain,_,_=_read(doc,stores,index,key)
                output.write(plain);h.update(plain)
            output.flush();os.fsync(output.fileno())
        require(h.hexdigest()==doc['sha256'] and os.stat(tmp).st_size==doc['size_bytes'],
                'Recovered file SHA-256 mismatch')
        os.link(tmp,target,follow_symlinks=False)
        secure._fsync_dir(target.parent)
        return {'status':'RESTORED_AUTHENTICATED','sha256':doc['sha256'],
                'size_bytes':doc['size_bytes'],'profile':f"{doc['k']}+{doc['parity']}"}
    finally:Path(tmp).unlink(missing_ok=True)


def repair(manifest:Path,pin:str,*,key_path:Path,stores:dict[str,secure.LocalStore],
           ledger:quotas.Ledger,epoch:int,repair_id:str,now:int|None=None)->dict[str,int]:
    """Repair absent shards only. Corrupt existing objects require manual quarantine."""
    doc,key=_verified(manifest,pin,key_path)
    names=_stores(stores,doc['k'],doc['parity'])
    require(names==[item['pool'] for item in doc['stores']] and
            all(stores[name].domain==row['domain'] for name,row in zip(names,doc['stores'])),
            'Repair store identities changed')
    require(isinstance(repair_id,str) and len(repair_id)<=40 and quotas.safe_id(repair_id),
            'Invalid repair id')
    # Inventory all missing blocks BEFORE attempting ANY re-replication.
    charges={name:{k:0 for k in quotas.FIELDS} for name in names}
    for index in range(len(doc['blocks'])):
        _,_,missing=_read(doc,stores,index,key)
        for shard_idx in missing:
            entry=doc['blocks'][index]['shards'][shard_idx]
            pool=entry['pool'];length=entry['size']
            for field in ('storage_bytes','write_bytes','read_bytes'):charges[pool][field]+=length
            for field in ('write_ops','read_ops'):charges[pool][field]+=1
            require(not (stores[pool].objects/entry['sha256']).exists(),
                    'Corrupt CAS object must be quarantined by operator')
    needed=[name for name in names if charges[name]['write_ops']]
    if not needed:return {'repaired_shards':0,'repaired_bytes':0}
    timestamp=int(time.time()) if now is None else now
    clock=(lambda:int(time.time())) if now is None else (lambda:now)
    tickets={name:f'{doc["archive"]}:repair:{repair_id}:{name}' for name in needed}
    reserved=[];touched=False;repaired=0;total=0
    try:
        for name in needed:
            ticket=ledger.reserve(name,tickets[name],charges[name],epoch=epoch,ttl=3600,now=timestamp)
            require(ticket['state']=='HELD','Repair id already committed')
            reserved.append(name)
        for index in range(len(doc['blocks'])):
            _,shards,missing=_read(doc,stores,index,key)
            for shard_idx in missing:
                entry=doc['blocks'][index]['shards'][shard_idx]
                pool=entry['pool'];data=shards[shard_idx]
                ledger.require_active(pool,tickets[pool],epoch=epoch,now=clock())
                touched=True
                stores[pool].put(doc['archive'],index,entry['sha256'],data)
                require(stores[pool].get(doc['archive'],index,entry['sha256'],len(data))==data,
                        'Repaired shard failed readback')
                total+=len(data);repaired+=1
        for pool in reserved:ledger.commit(pool,tickets[pool],epoch=epoch,now=clock())
        return {'repaired_shards':repaired,'repaired_bytes':total}
    except BaseException:
        for pool in reserved:
            try:
                if touched:ledger.uncertain(pool,tickets[pool],epoch=epoch,now=timestamp)
                else:ledger.release_unwritten(pool,tickets[pool],epoch=epoch,
                                              no_side_effects=True,now=timestamp)
            except (quotas.QuotaError,OSError):pass
        raise


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('manifest','key','ledger','stores'):
        p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--epoch',type=int,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    i=sub.add_parser('ingest')
    for name in ('source',):i.add_argument('--'+name,type=Path,required=True)
    i.add_argument('--policy-sha256',required=True)
    i.add_argument('--archive-id',required=True)
    i.add_argument('--chunk-bytes',type=int,default=4*1024*1024)
    i.add_argument('--profile',choices=['auto','4+2','8+3'],default='auto')
    r=sub.add_parser('restore');r.add_argument('--pin',required=True)
    r.add_argument('--destination',type=Path,required=True)
    a=sub.add_parser('repair');a.add_argument('--pin',required=True)
    a.add_argument('--repair-id',required=True)
    args=p.parse_args(argv)
    try:
        obj=providers.bounded_json(args.stores)
        require(type(obj) is dict and obj,'Invalid local stores JSON')
        stores={name:secure.LocalStore(Path(row['path']),pool=name,domain=row['domain'])
                for name,row in obj.items()}
        ledger=quotas.Ledger(args.ledger)
        if args.command=='ingest':
            k,parity=rs.select_profile(len(stores)) if args.profile=='auto' else tuple(map(int,args.profile.split('+')))
            result=ingest(args.source,args.manifest,key_path=args.key,policy_sha256=args.policy_sha256,
                          stores=stores,ledger=ledger,epoch=args.epoch,
                          archive_id=args.archive_id,chunk_bytes=args.chunk_bytes,k=k,parity=parity)
        elif args.command=='restore':
            result=restore(args.manifest,args.pin,args.destination,key_path=args.key,stores=stores)
        else:
            result=repair(args.manifest,args.pin,key_path=args.key,stores=stores,
                          ledger=ledger,epoch=args.epoch,repair_id=args.repair_id)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,TypeError,KeyError,RecursionError,rs.ErasureError) as exc:
        print('ERASURE ARCHIVE ERROR: '+type(exc).__name__,file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
