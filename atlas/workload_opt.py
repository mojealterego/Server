"""Bounded offline workload placement proposals using pinned profiling evidence."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import json
import time

from .capacity_fabric import integer, read_json
from .phaseshift import compile_workflow, digest
from .phaseverify import verify_workflow


class OptimizationError(ValueError):
    pass


def require(ok,message):
    if not ok: raise OptimizationError(message)


def measurements(profile,pin,baseline,tasks,nodes,now,max_age):
    require(isinstance(profile,dict) and set(profile)=={'schema','input_sha256','records'} and
            profile['schema']=='omega.workload.profile.v1' and profile['input_sha256']==baseline['input_sha256'] and
            digest(profile)==pin,'Profile version/input pin mismatch')
    records=profile['records']; limits={(t['id'],n['id']) for t in tasks for n in nodes}
    require(isinstance(records,list) and 1<=len(records)<=len(limits),'Invalid profiling records')
    results={};seen=set()
    for rec in records:
        require(isinstance(rec,dict) and set(rec)=={'task','node','observed_at','samples_ms'},'Invalid measurement schema')
        key=rec['task'],rec['node'];samples=rec['samples_ms']
        require(all(isinstance(k,str) for k in key) and key in limits and key not in seen and
                integer(rec['observed_at']) and isinstance(samples,list) and 10<=len(samples)<=100 and
                all(integer(x,1,86400000) for x in samples),'Invalid or duplicate measurement')
        seen.add(key)
        if 0<=now-rec['observed_at']<=max_age:
            # Nearest-rank per-stage p95; not an end-to-end latency estimate.
            results[key]=sorted(samples)[(95*len(samples)+99)//100-1]
    return results


def score(plan,observations):
    keys=[(a['id'],a['node']) for a in plan['primary']['assignments']]
    if any(k not in observations for k in keys): return None
    return sum(observations[k] for k in keys)


def optimize(baseline,tasks,nodes,catalog,profile,profile_pin,now,*,max_age=3600,
             min_improvement_bps=500,candidate_limit=8):
    require(integer(now) and integer(max_age,1,86400) and integer(min_improvement_bps,0,10000)
            and integer(candidate_limit,1,8),'Invalid optimization policy')
    check=verify_workflow(baseline,tasks,nodes,catalog)
    require(check['primary_feasible'] and baseline['admitted'] is True,'Baseline is not admitted')
    settings=baseline['settings']
    require(settings['max_states']<=20000,'Optimization search budget exceeds 20000 states per scenario')
    observations=measurements(profile,profile_pin,baseline,tasks,nodes,now,max_age)
    initial=score(baseline,observations)
    require(initial is not None,'Incomplete or stale baseline profiling evidence')
    best=baseline;best_score=initial;attempted=0;eligible=0
    old_coverage=set(check['verified_failure_scenarios'])
    # Generate alternative deterministic search priorities; no capacity, trust or recipe edits.
    order=sorted(nodes,key=lambda n:(n.get('priority',100),n['id']))
    for promoted in sorted(nodes,key=lambda n:n['id'])[:candidate_limit]:
        ids=[promoted['id']]+[n['id'] for n in order if n['id']!=promoted['id']]
        ranks={nid:i for i,nid in enumerate(ids)}
        alternate=[{**n,'priority':ranks[n['id']]} for n in nodes]
        proposal=compile_workflow(tasks,alternate,catalog,**settings);attempted+=1
        # Verify the alternate search output first, then bind to original operator inputs.
        verify_workflow(proposal,tasks,alternate,catalog)
        if proposal['admitted'] is not True: continue
        candidate={**proposal,'input_sha256':baseline['input_sha256']}
        candidate['certificate_sha256']=digest({k:v for k,v in candidate.items() if k!='certificate_sha256'})
        verified=verify_workflow(candidate,tasks,nodes,catalog)
        if not verified['primary_feasible'] or not old_coverage<=set(verified['verified_failure_scenarios']): continue
        if candidate['primary']['makespan_slots']>baseline['primary']['makespan_slots']: continue
        if any(candidate['failures'][n]['makespan_slots']>baseline['failures'][n]['makespan_slots'] for n in old_coverage): continue
        proposed=score(candidate,observations)
        if proposed is None: continue
        eligible+=1
        if proposed<best_score and proposed*10000<=initial*(10000-min_improvement_bps):
            best,best_score=candidate,proposed
    return {'status':'PROPOSED' if best is not baseline else 'UNCHANGED','objective':'SUM_OF_PROFILED_STAGE_P95_MS',
            'baseline_score_ms':initial,'candidate_score_ms':best_score,'attempted':attempted,
            'eligible':eligible,'profile_sha256':profile_pin,'plan':best,
            'scope':'OFFLINE_PROPOSAL_ONLY_NO_RUNTIME_ACTIVATION'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','tasks','nodes','catalog','profile'):p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--profile-sha256',required=True);p.add_argument('--max-age',type=int,default=3600)
    p.add_argument('--min-improvement-bps',type=int,default=500);p.add_argument('--candidate-limit',type=int,default=8)
    a=p.parse_args(argv)
    try:
        result=optimize(*(read_json(getattr(a,k)) for k in ('baseline','tasks','nodes','catalog','profile')),
                        a.profile_sha256,int(time.time()),max_age=a.max_age,
                        min_improvement_bps=a.min_improvement_bps,candidate_limit=a.candidate_limit)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,TypeError,KeyError,RecursionError) as exc:
        print('OPTIMIZATION ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
