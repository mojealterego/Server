#!/usr/bin/env python3
"""Explicit CAS export and verified restore over operator-configured Rclone."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlas.artifacts import ArtifactStore
from atlas.replication import Replica, push, pull


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vault',type=Path,required=True)
    p.add_argument('--remote',action='append',required=True,help='Configured Rclone remote:relative-vault; repeat for replicas')
    p.add_argument('--timeout',type=int,default=120)
    sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('push');a.add_argument('sha256');a.add_argument('--allow-export',action='store_true',required=True)
    a=sub.add_parser('pull');a.add_argument('sha256');a.add_argument('--manifest-sha256',required=True)
    args=p.parse_args(argv)
    try:
        replicas=[Replica(r,timeout=args.timeout) for r in args.remote]
        store=ArtifactStore(args.vault)
        result=push(store,args.sha256,replicas) if args.action=='push' else pull(store,args.sha256,args.manifest_sha256,replicas)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError) as exc:
        print('REPLICATION ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
