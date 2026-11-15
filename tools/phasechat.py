#!/usr/bin/env python3
"""End-to-end local llama-server -> PHASESHIFT lease -> CAS execution command.

The model stays on the phone/VPS hosting a trusted loopback llama-server.
No arbitrary remote endpoint or executable command is accepted.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlas.cli import _read_json
from atlas.artifacts import ArtifactStore, ArtifactError
from atlas.execution import SupervisedExecutor, ExecutionError
from atlas.llama_job import validate_chat, LlamaJobError
from atlas.phaselease import LeaseStore, LeaseError

def main(argv=None):
    p=argparse.ArgumentParser(description='Run vetted localhost llama-server inference under PHASESHIFT')
    for name in ('tasks','nodes','catalog','plan','db','cas','work'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--task',required=True)
    p.add_argument('--node',required=True)
    p.add_argument('--endpoint',required=True)
    p.add_argument('--model',required=True,help='Exact id from llama-server /v1/models (not a filename guess)')
    p.add_argument('--prompt-file',required=True,type=Path)
    p.add_argument('--max-tokens',type=int,default=256)
    p.add_argument('--ready-timeout',type=int,default=15)
    p.add_argument('--request-timeout',type=int,default=90)
    p.add_argument('--timeout',type=float,default=600)
    p.add_argument('--ttl',type=int,default=30)
    args=p.parse_args(argv)
    try:
        # Validate local network boundary and input *before* creating a lease.
        validate_chat(args.endpoint,args.model,args.prompt_file,max_tokens=args.max_tokens,
                      ready_timeout=args.ready_timeout,request_timeout=args.request_timeout)
        tasks=_read_json(args.tasks);nodes=_read_json(args.nodes)
        catalog=_read_json(args.catalog);plan=_read_json(args.plan)
        # Require the matching scheduled model family and text-generation engine.
        task=next((t for t in tasks if isinstance(t,dict) and t.get('id')==args.task),None)
        if task is None or task.get('engine')!='llama':
            raise LlamaJobError('Only scheduled llama engine tasks can use phasechat')
        # The model_id is a llama-server runtime ID, while the workflow model is
        # a catalog identifier; require an explicit deployment binding.
        bindings=task.get('runtime_model_ids')
        if not isinstance(bindings,dict) or bindings.get(args.model) not in task.get('models',[]):
            raise LlamaJobError('Missing trusted runtime-model binding in workflow')
        exe=[sys.executable,'-I',str(Path(__file__).resolve().parent/'llama_job.py'),
             '--endpoint',args.endpoint,'--model',args.model,
             '--prompt-file',str(args.prompt_file.resolve(strict=True)),
             '--output','{output}','--max-tokens',str(args.max_tokens),
             '--ready-timeout',str(args.ready_timeout),
             '--request-timeout',str(args.request_timeout)]
        cas=ArtifactStore(args.cas)
        with LeaseStore(args.db,plan,tasks,nodes,catalog,artifacts=cas) as lease:
            result=SupervisedExecutor(lease,cas,args.work).run(
                args.task,args.node,exe,ttl=args.ttl,timeout_seconds=args.timeout,
                suffix='.txt',max_log_bytes=32768)
        print(json.dumps(result,ensure_ascii=False,sort_keys=True))
        return 0
    except (LlamaJobError,ExecutionError,LeaseError,ArtifactError,OSError,ValueError,TypeError,KeyError) as exc:
        print('OMEGA-PHASECHAT ERROR: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
