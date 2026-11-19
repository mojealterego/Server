#!/usr/bin/env python3
"""Execute typed PHASESHIFT recipes for one local node, with durable CAS handoffs."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.capctl import read_json
from atlas.artifacts import ArtifactStore
from atlas.execution import SupervisedExecutor, ExecutionError
from atlas.phaselease import LeaseStore
from atlas.runtime_gate import gate_from_args, GateError
from atlas.multimodal import run_node, PipelineError, validate_recipes


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('tasks','nodes','catalog','plan','db','cas','work','deployment'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--node',required=True)
    p.add_argument('--timeout',type=float,default=600)
    p.add_argument('--retry-failed',action='store_true')
    for name in ('runtime-envelope-dir','runtime-policy','runtime-db','thermal-file','runtime-cgroup'):
        p.add_argument('--'+name,type=Path)
    p.add_argument('--runtime-ttl',type=int,default=120)
    a=p.parse_args(argv)
    try:
        runtime=[a.runtime_envelope_dir,a.runtime_policy,a.runtime_db,a.thermal_file]
        enabled=any(runtime) or a.runtime_cgroup is not None
        if enabled and not all(runtime):raise PipelineError('Incomplete runtime gate configuration')
        if enabled and (not a.runtime_envelope_dir.is_dir() or a.runtime_envelope_dir.is_symlink()):raise PipelineError('Unsafe runtime envelope directory')
        # Preserve leaf symlinks for the downstream validators; do not resolve them away.
        a.cas=a.cas.absolute();a.work=a.work.absolute();a.db=a.db.absolute()
        tasks,nodes,catalog,plan,deploy=(read_json(getattr(a,x)) for x in ('tasks','nodes','catalog','plan','deployment'))
        cas=ArtifactStore(a.cas)
        with LeaseStore(a.db,plan,tasks,nodes,catalog,artifacts=cas) as lease:
            validate_recipes(lease.task_list,lease.catalog,lease.assignments)
            executor=SupervisedExecutor(lease,cas,a.work)
            def gate(task):
                x=argparse.Namespace(**vars(a));x.task=task['id'];x.runtime_envelope=a.runtime_envelope_dir/(task['id']+'.json')
                return gate_from_args(x,tasks,nodes)
            result=run_node(lease,cas,executor,a.node,deploy,retry_failed=a.retry_failed,timeout=a.timeout,gate_factory=gate if enabled else None)
        print(json.dumps(result,sort_keys=True,ensure_ascii=False));return 0 if result['status']=='COMPLETED' else 2
    except (OSError,ValueError,TypeError,KeyError,GateError,ExecutionError,RecursionError) as exc:
        print('OMEGA-MULTI ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
