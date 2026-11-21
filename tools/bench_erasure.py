#!/usr/bin/env python3
"""Measured offline E15 Reed-Solomon encode/decode on this host only.

No S24 Ultra, provider, disk throughput or cluster metric can be inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import statistics
import sys
import time

from atlas import reed_solomon as rs


def run(*, size: int = 1024 * 1024, repeats: int = 3, seed: int = 20261121) -> dict:
    if (type(size) is not int or not 65536 <= size <= 4 * 1024 * 1024 or
        type(repeats) is not int or not 1 <= repeats <= 5 or
        type(seed) is not int or not 0 <= seed < 2**32):
        raise ValueError('Invalid offline benchmark limits')
    rng=random.Random(seed)
    payload=rng.randbytes(size)
    expected=hashlib.sha256(payload).hexdigest()
    rows=[]
    for k,parity in ((4,2),(8,3)):
        enc_times=[];dec_times=[];got_shards=[]
        # Erase the maximum permitted number of original data shards, which
        # forces reconstruction via parity rather than simple direct copy.
        erased=set(range(parity))
        for _ in range(repeats):
            start=time.perf_counter_ns()
            shards=rs.encode(payload,k=k,parity=parity)
            enc_times.append((time.perf_counter_ns()-start)/1_000_000)
            survivors={i:data for i,data in enumerate(shards) if i not in erased}
            start=time.perf_counter_ns()
            decoded=rs.recover(survivors,length=size,k=k,parity=parity)
            dec_times.append((time.perf_counter_ns()-start)/1_000_000)
            if decoded!=shards or hashlib.sha256(b''.join(decoded[:k])[:size]).hexdigest()!=expected:
                raise RuntimeError('Benchmark integrity verification failed')
            got_shards=shards
        encoded_bytes=sum(map(len,got_shards))
        rows.append({'profile':f'{k}+{parity}',
                     'data_shards':k,'parity_shards':parity,
                     'encoded_bytes':encoded_bytes,'two_copy_bytes':2*size,
                     'savings_relative_to_two_copies_fraction':round(1-encoded_bytes/(2*size),6),
                     'encode_ms_median':round(statistics.median(enc_times),4),
                     'recover_ms_median':round(statistics.median(dec_times),4),
                     'encode_ms_runs':[round(x,4) for x in enc_times],
                     'recover_ms_runs':[round(x,4) for x in dec_times],
                     'sha256_verified':True})
    return {'schema':'omega.rs-bench.v1','case_bytes':size,'repeat_count':repeats,'seed':seed,
            'platform':platform.platform(),'python':platform.python_version(),
            'note':'Offline synthetic CPU codec only; not network, disk, Android or cloud.',
            'profiles':rows}


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bytes',type=int,default=1024*1024)
    p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--seed',type=int,default=20261121)
    args=p.parse_args(argv)
    try:
        print(json.dumps(run(size=args.bytes,repeats=args.repeats,seed=args.seed),
                         sort_keys=True,indent=2));return 0
    except (ValueError,RuntimeError,rs.ErasureError) as exc:
        print('BENCH ERROR: '+type(exc).__name__,file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
