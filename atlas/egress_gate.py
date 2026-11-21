"""E19b: zero-billable-egress filter for E19a offline locality recommendations.

This module neither reads remote bytes nor performs reservations. 'free_bytes'
are operator-declared allowances, NOT direct evidence of provider billing state.
The result is per-task advice only and MUST NOT auto-activate a schedule.
"""
from __future__ import annotations
import hashlib
import json

MAX=2**63-1

class EgressError(ValueError):
    pass

def require(ok,why):
    if not ok:raise EgressError(why)

def integer(n,lo=0):
    return type(n) is int and lo<=n<=MAX

def digest(doc):
    try:raw=json.dumps(doc,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (ValueError,TypeError,OverflowError) as exc:raise EgressError('Cannot encode policy') from exc
    require(len(raw)<=2**21,'Profile/policy too large')
    return hashlib.sha256(raw).hexdigest()

def filter_advice(advice,profile,profile_pin,policy,policy_pin,now):
    """Filter unsupported or billable transfers without changing E19 runtime privileges."""
    require(integer(now,1) and type(profile) is dict and type(advice) is dict and
            isinstance(profile_pin,str) and digest(profile)==profile_pin and
            advice.get('status')=='ADVISORY_ONLY' and advice.get('profile_sha256')==profile_pin,
            'Untrusted or unpinned locality advice')
    require(type(policy) is dict and set(policy)=={'schema','profile_sha256','max_age_seconds','links'}
            and policy['schema']=='omega.egress.guard.v1' and policy['profile_sha256']==profile_pin and
            isinstance(policy_pin,str) and digest(policy)==policy_pin and
            integer(policy['max_age_seconds'],1) and policy['max_age_seconds']<=86400 and
            type(policy['links']) is list and len(policy['links'])<=2048,
            'Unpinned or invalid egress policy')
    age=policy['max_age_seconds']
    budgets={}
    for row in policy['links']:
        require(type(row) is dict and set(row)=={'source','target','free_bytes','billable','observed_at'}
                and type(row['source']) is str and type(row['target']) is str and
                row['source']!=row['target'] and integer(row['free_bytes']) and
                type(row['billable']) is bool and integer(row['observed_at']) and
                (row['source'],row['target']) not in budgets,
                'Invalid or duplicated operator egress budget')
        budgets[(row['source'],row['target'])]=row
    require(profile.get('schema')=='omega.locality.v1' and
            isinstance(profile.get('task_inputs'),list) and
            isinstance(profile.get('replicas'),list) and
            isinstance(profile.get('links'),list) and
            type(profile.get('runtime')) is list and
            type(advice.get('tasks')) is list and len(advice['tasks'])<=256,
            'Wrong E19 locality profile schema')
    demands={}
    for row in profile['task_inputs']:
        require(type(row) is dict and set(row)=={'task','sha256','bytes'} and
                type(row['task']) is str and row['task'] not in demands and
                type(row['sha256']) is str and len(row['sha256'])==64 and
                all(ch in '0123456789abcdef' for ch in row['sha256']) and
                integer(row['bytes'],1), 'Invalid task input evidence')
        demands[row['task']]=(row['sha256'],row['bytes'])
    replicas={}
    for row in profile['replicas']:
        require(type(row) is dict and set(row)=={'node','sha256','observed_at'} and
                type(row['node']) is str and type(row['sha256']) is str and
                integer(row['observed_at']) and (row['node'],row['sha256']) not in replicas,
                'Duplicate/invalid replica declaration')
        replicas[(row['node'],row['sha256'])]=0<=now-row['observed_at']<=age
    links={}
    for row in profile['links']:
        require(type(row) is dict and set(row)=={
                    'source','target','bytes_per_second','rtt_ms','observed_at'} and
                type(row['source']) is str and type(row['target']) is str and
                row['source']!=row['target'] and integer(row['bytes_per_second'],1)
                and integer(row['rtt_ms']) and integer(row['observed_at']) and
                (row['source'],row['target']) not in links,
                'Duplicate/invalid link telemetry')
        links[(row['source'],row['target'])]=row
    runtime={}
    for row in profile['runtime']:
        require(type(row) is dict and set(row)=={'task','node','samples_ms','observed_at'} and
                type(row['task']) is str and type(row['node']) is str and
                (row['task'],row['node']) not in runtime and integer(row['observed_at']) and
                type(row['samples_ms']) is list and 10<=len(row['samples_ms'])<=100 and
                all(integer(v,1) and v<=86400000 for v in row['samples_ms']),
                'Invalid or duplicate runtime observations')
        if 0<=now-row['observed_at']<=age:
            samples=sorted(row['samples_ms'])
            runtime[(row['task'],row['node'])]=samples[(95*len(samples)+99)//100-1]
    output=[];seen_tasks=set()
    for task in advice['tasks']:
        require(type(task) is dict and set(task)=={'task','ranked'} and
                type(task['task']) is str and task['task'] not in seen_tasks and
                type(task['ranked']) is list,
                'Invalid E19 task recommendation')
        seen_tasks.add(task['task']);selected=[];seen_nodes=set()
        for candidate in task['ranked']:
            require(type(candidate) is dict and set(candidate)=={
                        'node','runtime_p95_ms','transfer_ms','estimated_sum_ms','basis'} or
                    type(candidate) is dict and set(candidate)=={
                        'node','runtime_p95_ms','transfer_ms','estimated_sum_ms'},
                    'Malformed locality candidate')
            node=candidate['node']
            require(type(node) is str and node not in seen_nodes and
                    integer(candidate['runtime_p95_ms'],1),'Invalid candidate identity/runtime')
            require((task['task'],node) in runtime and
                    runtime[(task['task'],node)]==candidate['runtime_p95_ms'],
                    'Advisory runtime is unmeasured, expired or mismatched')
            seen_nodes.add(node)
            demand=demands.get(task['task'])
            if demand is None:
                source=None;bytes_used=0;duration=0
            else:
                sha,nbytes=demand
                if replicas.get((node,sha),False):
                    source=node;bytes_used=0;duration=0
                else:
                    options=[]
                    for (origin,sha2),present in replicas.items():
                        if not present or sha2!=sha or origin==node:continue
                        policy_link=budgets.get((origin,node));link=links.get((origin,node))
                        if not policy_link or not link or policy_link['billable'] is True:
                            continue
                        if (not 0<=now-policy_link['observed_at']<=age or
                            not 0<=now-link['observed_at']<=age or
                            policy_link['free_bytes']<nbytes):
                            continue
                        bps=link['bytes_per_second'];rtt=link['rtt_ms']
                        options.append(((nbytes*1000+bps-1)//bps+rtt,origin))
                    if not options:continue
                    duration,source=min(options);bytes_used=nbytes
            # Cross-check original E19 score against the pinned observations,
            # before applying the more restrictive free-egress filter.
            if demand is None or replicas.get((node,demand[0]),False):
                original_transfer=0
            else:
                original=[]
                for (origin,sha2),present in replicas.items():
                    if not present or sha2!=demand[0] or origin==node:continue
                    link=links.get((origin,node))
                    if not link or not 0<=now-link['observed_at']<=age:continue
                    original.append((demand[1]*1000+link['bytes_per_second']-1)//link['bytes_per_second'] + link['rtt_ms'])
                require(original,'Original locality advice has no measured transfer route')
                original_transfer=min(original)
            require(candidate['transfer_ms']==original_transfer and
                    candidate['estimated_sum_ms']==candidate['runtime_p95_ms']+original_transfer and
                    candidate.get('basis','OBSERVATION_NOT_ATTESTATION')=='OBSERVATION_NOT_ATTESTATION',
                    'Advisory score contradicts pinned E19 measurements')
            selected.append({'node':node,'source_node':source,'egress_bytes':bytes_used,
                             'transfer_estimate_ms':duration,
                             'runtime_p95_ms':candidate['runtime_p95_ms'],
                             'estimated_zero_cost_ms':candidate['runtime_p95_ms']+duration,
                             'basis':'OPERATOR_ATTESTED_FREE_BUDGET_NOT_BILLING_PROOF'})
        selected.sort(key=lambda r:(r['estimated_zero_cost_ms'],r['node']))
        output.append({'task':task['task'],'ranked':selected})
    return {'status':'ADVISORY_ONLY','profile_sha256':profile_pin,'policy_sha256':policy_pin,
            'scope':'ADVISORY_PER_TASK_NO_GLOBAL_RESERVATION','tasks':output}


def _private_json(path):
    """Read an operator-pinned local JSON artifact without following symlinks."""
    import os
    import stat
    from pathlib import Path
    target=Path(path)
    require(target.is_absolute() and not target.is_symlink(), 'Unsafe JSON input path')
    fd=os.open(target, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and
                info.st_mode & 0o077==0 and 0<info.st_size<=2**21,
                'JSON artifact must be a private regular file <=2MiB')
        with os.fdopen(os.dup(fd),'rb') as stream: raw=stream.read(2**21+1)
        require(0<len(raw)<=2**21,'JSON input exceeds limit')
    finally:
        os.close(fd)
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'Duplicate JSON key')
            result[key]=value
        return result
    try:
        return json.loads(raw,object_pairs_hook=unique,
                          parse_constant=lambda _:(_ for _ in ()).throw(EgressError('Nonfinite JSON constant')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:
        raise EgressError('Malformed JSON document') from exc


def main(argv=None):
    import argparse
    import sys
    import time
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('advice','profile','policy'):
        parser.add_argument('--'+name,required=True)
    for name in ('profile-sha256','policy-sha256'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--now',type=int,default=None)
    args=parser.parse_args(argv)
    try:
        result=filter_advice(_private_json(args.advice),_private_json(args.profile),
                             args.profile_sha256,_private_json(args.policy),
                             args.policy_sha256,int(time.time()) if args.now is None else args.now)
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0
    except (EgressError,ValueError,TypeError,KeyError,OSError) as exc:
        print('EGRESS GUARD ERROR: '+str(exc),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
