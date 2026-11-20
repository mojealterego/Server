"""Pinned multi-share SMB recovery sets; staged offline recovery, not live switch."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from .ha_checkpoint import canonical, private, sync_dir, HEX
from tools.atomic_publish import publish

SCHEMA='omega.smb.recovery-set.v1'
SHARES=('omega-compat','omega-secure','omega-models')

class RecoveryError(ValueError):pass


def require(ok,msg):
    if not ok:raise RecoveryError(msg)


def recovery_set(rows,*,quiesced=False):
    require(quiesced is True,'Confirm all share writers quiesced')
    require(isinstance(rows,dict) and set(rows)==set(SHARES),'Exactly three share receipts required')
    for row in rows.values():
        require(isinstance(row,dict) and set(row)=={'sha256','manifest_sha256'} and all(isinstance(s,str) and HEX.fullmatch(s) for s in row.values()),'Invalid snapshot receipt')
    require(len({r['sha256'] for r in rows.values()})==len(SHARES),'Duplicate snapshot identity')
    doc={'schema':SCHEMA,'shares':rows};raw=canonical(doc)
    return {'set':json.loads(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def validate(doc,pin):
    if isinstance(doc,dict) and set(doc)=={'set','sha256'}:
        require(doc['sha256']==pin,'Recovery receipt pin mismatch');doc=doc['set']
    require(isinstance(doc,dict) and set(doc)=={'schema','shares'} and doc['schema']==SCHEMA,'Invalid recovery set')
    expected=recovery_set(doc['shares'],quiesced=True)
    require(isinstance(pin,str) and HEX.fullmatch(pin) and expected['sha256']==pin,'Recovery set pin mismatch')
    return expected['set']['shares']


def restore_set(doc,pin,dest,*,retrieve,inspect,restore):
    rows=validate(doc,pin);dest=Path(dest);private(dest.parent)
    if dest.exists() or dest.is_symlink():raise FileExistsError(str(dest))
    # Never fall back to another generation when a replica is incomplete.
    for name in SHARES:
        row=rows[name];retrieve(row['sha256'],row['manifest_sha256'])
        require(inspect(row['sha256'])['share']==name,'Snapshot share identity mismatch')
    with tempfile.TemporaryDirectory(prefix='.smb-recovery-',dir=dest.parent) as tmp:
        stage=Path(tmp)/'shares';stage.mkdir(mode=0o700)
        for name in SHARES:
            sha=rows[name]['sha256'];result=restore(sha,stage/name)
            require(result['status']=='RESTORED' and result['sha256']==sha,'Snapshot restore receipt mismatch');private(stage/name)
        sync_dir(stage);publish(stage,dest)
    return {'status':'RECOVERED_OFFLINE','set_sha256':pin,'shares':list(SHARES)}


def main(argv=None):
    from .artifacts import ArtifactStore
    from .storage_snapshot import create,load_index,manifest_pin,replicate,retrieve,restore,encrypted_replicas,VPS,SHARES as PATHS
    from tools.capctl import read_json
    import subprocess
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',type=Path,required=True);sub=p.add_subparsers(dest='cmd',required=True)
    c=sub.add_parser('capture');c.add_argument('--confirm-quiesced',action='store_true',required=True)
    for name in ('push','restore'):
        a=sub.add_parser(name);a.add_argument('--set',type=Path,required=True);a.add_argument('--sha256',required=True);a.add_argument('--remote',action='append',required=True)
        if name=='push':a.add_argument('--allow-export',action='store_true',required=True)
        else:a.add_argument('--dest',type=Path,required=True)
    a=p.parse_args(argv)
    try:
        cas=ArtifactStore(a.vault)
        if a.cmd=='capture':
            rows={}
            for name in SHARES:
                source=VPS/PATHS[name];require(not any(x.is_symlink() for x in (source,*[x for x in source.parents if VPS in x.parents])),'Share path symlink refused')
                r=create(cas,source,name);rows[name]={k:r[k] for k in ('sha256','manifest_sha256')}
            result=recovery_set(rows,quiesced=a.confirm_quiesced)
        else:
            doc=read_json(a.set);rows=validate(doc,a.sha256);replicas=encrypted_replicas(a.remote)
            if a.cmd=='push':
                for name,row in rows.items():
                    require(load_index(cas,row['sha256'])['share']==name and manifest_pin(cas,row['sha256'])==row['manifest_sha256'],'Snapshot receipt mismatch')
                for replica in replicas:
                    for row in rows.values():replicate(cas,row['sha256'],[replica])
                result={'status':'VERIFIED_READBACK','set_sha256':a.sha256,'replicas':[r.root for r in replicas]}
            else:
                require(not a.dest.resolve().is_relative_to(cas.root.resolve()),'Destination must be outside snapshot CAS')
                result=restore_set(doc,a.sha256,a.dest,retrieve=lambda sha,pin:retrieve(cas,sha,pin,replicas),inspect=lambda sha:load_index(cas,sha),restore=lambda sha,dest:restore(cas,sha,dest))
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError,RecursionError) as exc:print('STORAGE RECOVERY ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
