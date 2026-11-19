#!/usr/bin/env python3
"""Private per-stage subprocess; existing guardian owns its deadline."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlas.multimodal import media_job, text_job
from tools.capctl import read_json


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--spec',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        spec=read_json(args.spec)
        if spec['kind']=='qwen_text':text_job(spec,args.output)
        else:media_job(spec,args.output)
        return 0
    except (ValueError,OSError,TypeError,KeyError,RuntimeError,RecursionError) as exc:
        # Do not echo prompt/model-generated data into persistent logs.
        print('MULTIMODAL_JOB_FAILED: '+type(exc).__name__,file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
