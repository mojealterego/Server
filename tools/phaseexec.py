#!/usr/bin/env python3
"""Execute an explicitly supplied, trusted command under PHASESHIFT fencing.

Usage: phaseexec.py --tasks T --nodes N --catalog C --plan P --db D
    --cas CAS --work WORK --task ID --node NODE [options] -- EXEC ... {output}
The command is a *local operator command*, not executable model-generated code.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlas.cli import _read_json
from atlas.artifacts import ArtifactStore
from atlas.execution import SupervisedExecutor, ExecutionError
from atlas.phaselease import LeaseStore, LeaseError


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='Fenced local subprocess execution with a durable CAS receipt')
    for name in ('tasks','nodes','catalog','plan','db','cas','work'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--task',required=True)
    parser.add_argument('--node',required=True)
    parser.add_argument('--ttl',type=int,default=30)
    parser.add_argument('--timeout',type=float,default=600)
    parser.add_argument('--suffix',default='.bin')
    parser.add_argument('--max-log-bytes',type=int,default=262144)
    parser.add_argument('command',nargs=argparse.REMAINDER)
    args=parser.parse_args(argv)
    command=args.command[1:] if args.command and args.command[0]=='--' else args.command
    try:
        tasks=_read_json(args.tasks)
        nodes=_read_json(args.nodes)
        catalog=_read_json(args.catalog)
        plan=_read_json(args.plan)
        cas=ArtifactStore(args.cas)
        with LeaseStore(args.db,plan,tasks,nodes,catalog,artifacts=cas) as store:
            result=SupervisedExecutor(store,cas,args.work).run(
                args.task,args.node,command,ttl=args.ttl,timeout_seconds=args.timeout,
                suffix=args.suffix,max_log_bytes=args.max_log_bytes)
        print(json.dumps(result,sort_keys=True,ensure_ascii=False))
        return 0
    except (ExecutionError,LeaseError,OSError,ValueError,TypeError,KeyError) as exc:
        print(f'OMEGA-EXEC ERROR: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
