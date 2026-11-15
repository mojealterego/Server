#!/usr/bin/env python3
"""PHASESHIFT CLI; offline Python stdlib, no implicit network or model execution."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from atlas.cli import _read_json, _write_json
from atlas.phaseshift import compile_workflow
from atlas.phaseverify import verify_workflow
from atlas.phaselease import LeaseStore, LeaseError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='PHASESHIFT proof-carrying fault-counterfactual scheduler')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('compile','verify','claim','renew','complete','status'):
        p = sub.add_parser(name)
        p.add_argument('--tasks', type=Path, required=True)
        p.add_argument('--nodes', type=Path, required=True)
        p.add_argument('--catalog', type=Path, required=True)
        if name == 'compile':
            p.add_argument('--out', type=Path, required=True)
            p.add_argument('--horizon', type=int, default=8)
            p.add_argument('--max-states', type=int, default=20000)
            p.add_argument('--require-n-minus-one', action='store_true')
        else:
            p.add_argument('--plan', type=Path, required=True)
        if name in ('claim','renew','complete','status'):
            p.add_argument('--db', type=Path, required=True)
            p.add_argument('--task', required=True)
        if name in ('claim','renew','complete'):
            p.add_argument('--node', required=True)
            p.add_argument('--token-file', type=Path, required=True)
        if name in ('claim','renew'):
            p.add_argument('--ttl', type=int, default=60)
        if name == 'complete':
            p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        tasks = _read_json(args.tasks)
        nodes = _read_json(args.nodes)
        catalog = _read_json(args.catalog)
        if args.command == 'compile':
            result = compile_workflow(tasks,nodes,catalog,horizon=args.horizon,
                     max_states=args.max_states,require_n_minus_one=args.require_n_minus_one)
            _write_json(args.out,result)
            display = {'status':result['status'],'admitted':result['admitted'],
                       'certificate_sha256':result['certificate_sha256'], 'plan':str(args.out)}
        else:
            doc = _read_json(args.plan)
            if args.command == 'verify':
                display = verify_workflow(doc,tasks,nodes,catalog)
            else:
                with LeaseStore(args.db,doc,tasks,nodes,catalog) as store:
                    if args.command == 'claim':
                        if args.token_file.exists() or args.token_file.is_symlink():
                            raise LeaseError('Token file exists; refusing to overwrite')
                        result = store.claim(args.task,args.node,ttl=args.ttl)
                        _write_json(args.token_file, result)
                        display = {k:v for k,v in result.items() if k!='token'}
                        display['token_file'] = str(args.token_file)
                    elif args.command == 'status':
                        display = store.status(args.task)
                    else:
                        if args.token_file.is_symlink() or not args.token_file.is_file() or args.token_file.stat().st_mode & 0o077:
                            raise LeaseError('Token file must be private (0600)')
                        cred = _read_json(args.token_file,max_bytes=4096)
                        if (cred.get('task') != args.task or cred.get('node') != args.node or
                            cred.get('plan_sha256') != store.plan_hash):
                            raise LeaseError('Token file not bound to this task, node and plan')
                        if args.command == 'renew':
                            display = store.renew(args.task,args.node,cred['token'],cred['epoch'],ttl=args.ttl)
                        else:
                            display = store.complete(args.task,args.node,cred['token'],cred['epoch'],args.output)
        print(json.dumps(display,sort_keys=True,ensure_ascii=False,indent=2))
        return 0
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f'PHASESHIFT ERROR: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__':
    sys.exit(main())
