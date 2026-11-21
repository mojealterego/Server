"""E19a offline compute/data locality advisor; never activates a schedule.

All performance numbers are operator-supplied measurements, bound to an
independent digest. They are not remote attestation or a plan certificate.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class LocalityError(ValueError):
    pass


def require(ok,reason):
    if not ok:raise LocalityError(reason)


def integer(x,lo=0,hi=2**63-1):
    return type(x) is int and lo<=x<=hi


def digest(doc):
    try:
        raw=json.dumps(doc,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
    except (TypeError,ValueError,OverflowError) as exc:
        raise LocalityError('Invalid observations') from exc
    return hashlib.sha256(raw).hexdigest()


def _id(s):
    return type(s) is str and 1<=len(s)<=128 and s.isascii() and all(
        c.isalnum() or c in '-_.' for c in s)


def _fresh(at,now,max_age):
    return 0<=now-at<=max_age


def _node_eligible(t,n):
    privacy=t.get('privacy','trusted_only')
    if privacy=='local_only' and n.get('trust')!='local':return False
    if privacy=='trusted_only' and n.get('trust')=='untrusted':return False
    if t['engine'] not in n['capabilities'] or any(m not in n['models'] for m in t['models']):return False
    if n['ram_available_mb']-n['ram_headroom_mb']<t['ram_mb']:return False
    if not 0<=n['thermal_c']<43:return False
    return True


def advise(tasks:list[dict],nodes:list[dict],profile:dict,pin:str,now:int,*,max_age:int=3600)->dict:
    require(integer(now,1) and integer(max_age,1,86400),'Invalid time bounds')
    require(isinstance(tasks,list) and 1<=len(tasks)<=256 and
            isinstance(nodes,list) and 1<=len(nodes)<=128,'Invalid task or node count')
    tids=set();nids=set()
    for t in tasks:
        require(type(t) is dict and _id(t.get('id')) and t['id'] not in tids and
                _id(t.get('engine')) and isinstance(t.get('models'),list) and
                all(_id(m) for m in t['models']) and
                integer(t.get('ram_mb'),1) and
                t.get('privacy','trusted_only') in ('any','trusted_only','local_only'),
                'Invalid task policy')
        tids.add(t['id'])
    for n in nodes:
        require(type(n) is dict and _id(n.get('id')) and n['id'] not in nids and
                n.get('trust') in ('local','trusted','untrusted') and
                isinstance(n.get('capabilities'),list) and isinstance(n.get('models'),list) and
                all(_id(x) for x in n['capabilities']+n['models']) and
                all(integer(n.get(x)) for x in ('ram_available_mb','ram_headroom_mb','disk_free_bytes')) and
                type(n.get('thermal_c')) in (int,float) and
                math.isfinite(n['thermal_c']), 'Invalid node policy')
        nids.add(n['id'])
    require(type(profile) is dict and set(profile)=={'schema','task_inputs','replicas','links','runtime'}
            and profile['schema']=='omega.locality.v1' and type(pin) is str and
            len(pin)==64 and digest(profile)==pin, 'Locality profile pin mismatch')
    demands={};replicas={};links={};runtime={}
    inputs=profile['task_inputs']
    require(isinstance(inputs,list) and len(inputs)<=len(tids),'Invalid input inventory')
    for row in inputs:
        require(type(row) is dict and set(row)=={'task','sha256','bytes'} and
                row['task'] in tids and row['task'] not in demands and
                type(row['sha256']) is str and len(row['sha256'])==64 and
                all(c in '0123456789abcdef' for c in row['sha256']) and
                integer(row['bytes'],1), 'Invalid task input')
        demands[row['task']]=(row['sha256'],row['bytes'])
    rows=profile['replicas']
    require(isinstance(rows,list) and len(rows)<=len(nids)*max(1,len(demands)),
            'Invalid replica inventory')
    for row in rows:
        require(type(row) is dict and set(row)=={'node','sha256','observed_at'} and
                row['node'] in nids and type(row['sha256']) is str and
                len(row['sha256'])==64 and all(c in '0123456789abcdef' for c in row['sha256'])
                and integer(row['observed_at']) and (row['node'],row['sha256']) not in replicas,
                'Invalid replica observation')
        replicas[(row['node'],row['sha256'])]=_fresh(row['observed_at'],now,max_age)
    rows=profile['links']
    require(isinstance(rows,list) and len(rows)<=len(nids)*(len(nids)-1),
            'Invalid link inventory')
    for row in rows:
        require(type(row) is dict and set(row)=={'source','target','bytes_per_second','rtt_ms','observed_at'} and
                row['source'] in nids and row['target'] in nids and row['source']!=row['target'] and
                integer(row['bytes_per_second'],1,10**13) and integer(row['rtt_ms'],0,60000) and
                integer(row['observed_at']) and (row['source'],row['target']) not in links,
                'Invalid link measurement')
        links[(row['source'],row['target'])]=(row['bytes_per_second'],row['rtt_ms']) if _fresh(row['observed_at'],now,max_age) else None
    rows=profile['runtime']
    require(isinstance(rows,list) and len(rows)<=len(tids)*len(nids),
            'Invalid runtime inventory')
    for row in rows:
        require(type(row) is dict and set(row)=={'task','node','samples_ms','observed_at'} and
                row['task'] in tids and row['node'] in nids and integer(row['observed_at']) and
                (row['task'],row['node']) not in runtime and
                isinstance(row['samples_ms'],list) and 10<=len(row['samples_ms'])<=100 and
                all(integer(x,1,86400000) for x in row['samples_ms']),
                'Invalid latency samples')
        if _fresh(row['observed_at'],now,max_age):
            sorted_samples=sorted(row['samples_ms']);index=(95*len(sorted_samples)+99)//100-1
            runtime[(row['task'],row['node'])]=sorted_samples[index]
    result=[]
    for task in sorted(tasks,key=lambda x:x['id']):
        ranked=[]
        for n in nodes:
            nid=n['id'];latency=runtime.get((task['id'],nid))
            if latency is None or not _node_eligible(task,n):continue
            transfer=0
            demand=demands.get(task['id'])
            if demand:
                sha,amount=demand
                if not replicas.get((nid,sha),False):
                    times=[]
                    for (source,stored_sha),valid in replicas.items():
                        if stored_sha!=sha or not valid:continue
                        link=links.get((source,nid))
                        if link is None:continue
                        bps,rtt=link
                        times.append((amount*1000+bps-1)//bps+rtt)
                    if not times:continue
                    transfer=min(times)
            ranked.append({'node':nid,'runtime_p95_ms':latency,'transfer_ms':transfer,
                           'estimated_sum_ms':latency+transfer,
                           'basis':'OBSERVATION_NOT_ATTESTATION'})
        ranked.sort(key=lambda row:(row['estimated_sum_ms'],row['node']))
        result.append({'task':task['id'],'ranked':ranked})
    return {'status':'ADVISORY_ONLY','profile_sha256':pin,'tasks':result,
            'note':'Independent task-level estimated sums, not concurrent execution, a certified plan, measured end-to-end p95 or deployment.'}


def main(argv=None):
    import argparse
    from pathlib import Path
    import sys
    import time
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('tasks','nodes','profile'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile-sha256',required=True)
    p.add_argument('--now',type=int,default=None)
    p.add_argument('--max-age',type=int,default=3600)
    a=p.parse_args(argv)
    def read(path):
        require(path.is_file() and not path.is_symlink(),'Unsafe profile input')
        with path.open('rb') as f:raw=f.read(8*1024**2+1)
        require(len(raw)<=8*1024**2,'Input JSON too large')
        def unique(pairs):
            result={}
            for k,v in pairs:
                require(k not in result,'Duplicate input JSON key')
                result[k]=v
            return result
        return json.loads(raw,object_pairs_hook=unique,
                          parse_constant=lambda _:(_ for _ in ()).throw(LocalityError('Nonfinite input')))
    try:
        result=advise(read(a.tasks),read(a.nodes),read(a.profile),a.profile_sha256,
                      int(time.time()) if a.now is None else a.now,max_age=a.max_age)
        print(json.dumps(result,sort_keys=True));return 0
    except (LocalityError,ValueError,OSError,TypeError,KeyError) as exc:
        print('LOCALITY ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
