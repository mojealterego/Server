#!/usr/bin/env python3
"""Deterministic *synthetic* admission safety comparison, not hardware benchmark."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import random
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlas.phaseshift import compile_workflow
from atlas.phaseverify import verify_workflow


def benchmark(cases: int=200, seed: int=20261115) -> dict:
    if type(cases) is not int or not 1 <= cases <= 10000:
        raise ValueError('cases must be 1..10000')
    rng=random.Random(seed)
    catalog={'synthetic-model':{'bytes':1,'format':'gguf','role':'llm','lineage_verified':False}}
    counts={'naive_overcommit_cases':0,'primary_feasible':0,'resilient':0,
            'admitted':0,'blocked':0,'indeterminate':0,'verified_certificates':0}
    for _ in range(cases):
        n=rng.randint(1,3)
        nodes=[{'id':f'n{i}','trust':'trusted','capabilities':['llama'],
                'models':['synthetic-model'],'ram_available_mb':rng.choice([512,1024,2048]),
                'ram_headroom_mb':128,'disk_free_bytes':1000000,'thermal_c':35,
                'priority':i} for i in range(n)]
        tasks=[{'id':f't{j}','engine':'llama','models':['synthetic-model'],
                'ram_mb':rng.choice([256,512,768]),'duration_slots':rng.choice([1,2]),
                'privacy':'trusted_only'} for j in range(rng.randint(2,6))]
        # Explicitly naive comparator: send all independent tasks to priority-0
        # node at slot zero; this is NOT the v3 planner's runtime behavior.
        if sum(t['ram_mb'] for t in tasks) > nodes[0]['ram_available_mb']-nodes[0]['ram_headroom_mb']:
            counts['naive_overcommit_cases']+=1
        doc=compile_workflow(tasks,nodes,catalog,horizon=8,max_states=3000)
        proof=verify_workflow(doc,tasks,nodes,catalog)
        counts['verified_certificates']+=int(proof['valid'])
        counts['primary_feasible']+=int(proof['primary_feasible'])
        counts['resilient']+=int(doc['status']=='RESILIENT')
        counts['admitted']+=int(doc['admitted'])
        counts['blocked']+=int(doc['status']=='BLOCKED')
        counts['indeterminate']+=int(doc['status']=='INDETERMINATE')
    return {'schema':'omega.phaseshift.synthetic.v1','seed':seed,'cases':cases,
            'comparator':'naive immediate concurrent placement on first node (not ATLAS v3 scheduler)',
            'measurement':'in-memory simulated declarations; no real throughput, energy or transfer',
            **counts}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--cases',type=int,default=200)
    p.add_argument('--seed',type=int,default=20261115)
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    result=benchmark(args.cases,args.seed)
    if args.output:
        if args.output.is_symlink() or args.output.exists():
            raise ValueError('Output exists or is symlink')
        args.output.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))

if __name__=='__main__':main()
