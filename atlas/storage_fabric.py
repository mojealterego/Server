"""Pinned model-cache and encrypted SMB recovery routing with no version fallback."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from dataclasses import dataclass

ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
ALIAS=re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')
SEGMENT=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
HEX=re.compile(r'[0-9a-f]{64}\Z')
MAX_CATALOG=1024*1024
ED25519_DER=bytes.fromhex('302a300506032b6570032100')

class FabricError(ValueError):pass

def require(condition,message):
    if not condition:raise FabricError(message)

def canonical(doc):
    try:raw=json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    except (ValueError,TypeError,RecursionError) as exc:raise FabricError('Invalid catalog JSON') from exc
    require(len(raw)<=MAX_CATALOG,'Catalog too large');return raw

def digest(doc):return hashlib.sha256(canonical(doc)).hexdigest()

def sha(value):return isinstance(value,str) and HEX.fullmatch(value)

def key(value):
    try:
        require(isinstance(value,str) and len(value)==60,'Invalid Ed25519 public key')
        raw=base64.b64decode(value,validate=True)
        require(len(raw)==44 and raw.startswith(ED25519_DER),'Invalid Ed25519 public key')
    except (ValueError,TypeError) as exc:raise FabricError('Invalid Ed25519 public key') from exc

def replicas(values,*,crypt=False):
    require(isinstance(values,list) and 1<=len(values)<=8,'Expected 1..8 replica aliases')
    aliases=[]
    for value in values:
        require(isinstance(value,str) and len(value)<=512,'Invalid remote')
        if crypt:
            alias,sep,path=value.partition(':')
            require(sep and 1<=len(path.split('/'))<=8 and all(SEGMENT.fullmatch(p) and p not in ('.','..') for p in path.split('/')),'Invalid crypt root')
        else:alias=value
        require(ALIAS.fullmatch(alias),'Invalid remote alias'); aliases.append(alias)
    require(len(set(aliases))==len(aliases),'Duplicate replica alias');return tuple(values)

@dataclass(frozen=True)
class ModelRoute:
    sha256:str
    public_key:str
    remotes:tuple[str,...]

class Fabric:
    def __init__(self,doc,pin):
        raw=canonical(doc);require(sha(pin) and hashlib.sha256(raw).hexdigest()==pin,'Catalog pin mismatch')
        doc=json.loads(raw)
        require(isinstance(doc,dict) and set(doc)=={'schema','models','recovery'} and doc['schema']=='omega.storage.fabric.v1','Invalid catalog schema')
        models=doc['models'];require(isinstance(models,dict) and 1<=len(models)<=256,'Invalid model inventory')
        routes={}
        for name,row in models.items():
            require(ID.fullmatch(name) and isinstance(row,dict) and set(row)=={'sha256','public_key','remotes'} and sha(row['sha256']),'Invalid model route');key(row['public_key'])
            routes[name]=ModelRoute(row['sha256'],row['public_key'],replicas(row['remotes']))
        recovery=doc['recovery']; require(isinstance(recovery,dict) and set(recovery)=={'sha256','remotes'} and sha(recovery['sha256']),'Invalid recovery route')
        self._routes=routes;self._recovery_pin=recovery['sha256'];self._recovery_remotes=replicas(recovery['remotes'],crypt=True);self.pin=pin
    def stage_model(self,name,envelope,cache,*,stage=None):
        require(isinstance(name,str) and name in self._routes,'Unknown model ID');route=self._routes[name]
        if stage is None:
            from .storage_cache import stage
        result=stage(envelope,route.public_key,route.sha256,cache,list(route.remotes))
        require(isinstance(result,dict) and result.get('sha256')==route.sha256,'Model stage receipt mismatch')
        return result
    def restore(self,receipt,vault,dest,*,restore=None):
        if restore is None:restore=restore_generation
        result=restore(receipt,self._recovery_pin,vault,dest,list(self._recovery_remotes))
        require(isinstance(result,dict) and result.get('status')=='RECOVERED_OFFLINE' and result.get('set_sha256')==self._recovery_pin,'Recovery receipt mismatch')
        return result

def restore_generation(receipt,pin,vault,dest,remotes):
    from .artifacts import ArtifactStore
    from .storage_recovery import validate,restore_set
    from .storage_snapshot import encrypted_replicas,retrieve,load_index,restore
    validate(receipt,pin)
    cas=ArtifactStore(Path(vault));target=Path(dest)
    require(not target.resolve().is_relative_to(cas.root.resolve()),'Destination must be outside snapshot CAS')
    enrolled=encrypted_replicas(remotes)
    return restore_set(receipt,pin,target,retrieve=lambda sha,merkle:retrieve(cas,sha,merkle,enrolled),inspect=lambda sha:load_index(cas,sha),restore=lambda sha,path:restore(cas,sha,path))

def read_document(path,limit):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'Duplicate JSON key');result[k]=v
        return result
    with Path(path).open('rb') as f:raw=f.read(limit+1)
    require(len(raw)<=limit,'Input document too large');return json.loads(raw,object_pairs_hook=unique)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--catalog',required=True,type=Path);p.add_argument('--catalog-sha256',required=True)
    s=p.add_subparsers(dest='cmd',required=True);a=s.add_parser('stage-model');a.add_argument('--model',required=True);a.add_argument('--manifest',required=True,type=Path);a.add_argument('--cache',required=True,type=Path)
    b=s.add_parser('restore');b.add_argument('--receipt',required=True,type=Path);b.add_argument('--vault',required=True,type=Path);b.add_argument('--dest',required=True,type=Path)
    a=p.parse_args(argv)
    try:
        fabric=Fabric(read_document(a.catalog,MAX_CATALOG),a.catalog_sha256)
        if a.cmd=='stage-model':result=fabric.stage_model(a.model,read_document(a.manifest,4*MAX_CATALOG),a.cache)
        else:result=fabric.restore(read_document(a.receipt,MAX_CATALOG),a.vault,a.dest)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,RuntimeError,TypeError,KeyError,RecursionError) as exc:print('STORAGE FABRIC ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
