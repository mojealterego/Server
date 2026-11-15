#!/usr/bin/env python3
"""Local artifact vault CLI. No network access and no implicit overwrite."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from atlas.artifacts import ArtifactStore, ArtifactError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='OMEGA-X local SHA256 artifact vault')
    parser.add_argument('--vault', type=Path, required=True,
                        help='Private (0700) CAS directory, created on first use')
    commands=parser.add_subparsers(dest='action',required=True)
    put=commands.add_parser('put',help='Stage a verified artifact durably')
    put.add_argument('source',type=Path)
    put.add_argument('--max-bytes',type=int,default=16*1024**3)
    verify=commands.add_parser('verify',help='Rehash an existing CAS object')
    verify.add_argument('sha256')
    restore=commands.add_parser('restore',help='Restore to a NEW path, never overwrite')
    restore.add_argument('sha256')
    restore.add_argument('destination',type=Path)
    args=parser.parse_args(argv)
    try:
        store=ArtifactStore(args.vault)
        if args.action=='put':
            result=store.put(args.source,max_bytes=args.max_bytes)
        elif args.action=='verify':
            store.verify(args.sha256)
            result={'sha256':args.sha256,'valid':True}
        elif args.action=='restore':
            result=store.restore(args.sha256,args.destination)
        else:
            raise AssertionError('Unknown action')
    except (ArtifactError,OSError) as exc:
        print(f'CAS_ERROR: {exc}',file=sys.stderr)
        return 2
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
