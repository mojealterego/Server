#!/usr/bin/env python3
"""Internal, single-shot loopback llama-server inference adapter for PHASESHIFT."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from atlas.llama_job import perform_chat, write_response_new, LlamaJobError
from atlas.runner import RunnerError

def main(argv=None):
    p=argparse.ArgumentParser(description='Run one local inference and create output without overwrite')
    p.add_argument('--endpoint',required=True)
    p.add_argument('--model',required=True)
    p.add_argument('--prompt-file',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--max-tokens',type=int,default=256)
    p.add_argument('--ready-timeout',type=int,default=15)
    p.add_argument('--request-timeout',type=int,default=90)
    x=p.parse_args(argv)
    try:
        answer=perform_chat(x.endpoint,x.model,x.prompt_file,max_tokens=x.max_tokens,
                            ready_timeout=x.ready_timeout,request_timeout=x.request_timeout)
        write_response_new(x.output,answer)
        return 0
    except (LlamaJobError,RunnerError,OSError,ValueError) as exc:
        print('OMEGA-LLAMA-JOB ERROR: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
