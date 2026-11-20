"""Quota-aware zero-cost placement proposals; no remote writes or billing guarantees."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

MAX = 2**63 - 1
MIB = 1024**2
MAX_BLOCKS = 65536
MAX_JSON = 40*MIB
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
FIELDS = {'id', 'pool', 'domain', 'kind', 'limit_bytes', 'used_bytes',
          'reserve_bytes', 'write_budget_bytes', 'read_budget_bytes',
          'block_budget', 'observed_at', 'authorized', 'zero_cost'}


class PolicyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def integer(x, lo=0, hi=MAX):
    return type(x) is int and lo <= x <= hi


def identifier(x):
    return isinstance(x, str) and ID.fullmatch(x) is not None


def digest(doc):
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def normalize(doc):
    require(isinstance(doc, dict) and set(doc) == {'schema', 'copies', 'chunk_bytes',
            'max_age_seconds', 'pools'} and doc['schema'] == 'omega.capacity.v1', 'Invalid policy')
    require(integer(doc['copies'], 1, 3) and integer(doc['chunk_bytes'], MIB, 64*MIB)
            and integer(doc['max_age_seconds'], 1, 86400), 'Invalid policy limits')
    rows = doc['pools']
    require(isinstance(rows, list) and 1 <= len(rows) <= 128, 'Expected 1..128 pools')
    ids, pools = set(), set()
    for r in rows:
        require(isinstance(r, dict) and set(r) == FIELDS, 'Invalid pool fields')
        require(all(identifier(r[k]) for k in ('id', 'pool', 'domain')) and
                r['kind'] in ('local', 'smb', 'crypt', 'object'), 'Invalid pool identity/type')
        require(r['id'] not in ids and r['pool'] not in pools, 'Duplicate ID or underlying quota pool')
        ids.add(r['id']); pools.add(r['pool'])
        require(all(integer(r[k]) for k in ('limit_bytes', 'used_bytes', 'reserve_bytes',
                'write_budget_bytes', 'read_budget_bytes', 'block_budget', 'observed_at')),
                'Invalid quota or observation')
        require(type(r['authorized']) is bool and type(r['zero_cost']) is bool, 'Explicit policy flags required')
    return {**doc, 'pools': sorted((dict(r) for r in rows), key=lambda r: r['id'])}


def available(doc, now):
    require(integer(now), 'Invalid current time')
    rows, budgets, excluded = {}, {}, {}
    for r in doc['pools']:
        name = r['id']
        if not r['authorized']: excluded[name] = 'authorization'
        elif not r['zero_cost']: excluded[name] = 'cost'
        elif not 0 <= now-r['observed_at'] <= doc['max_age_seconds']: excluded[name] = 'stale'
        else:
            usable = min(max(0,r['limit_bytes']-r['used_bytes']-r['reserve_bytes']),
                         r['write_budget_bytes'], r['read_budget_bytes'], r['block_budget']*doc['chunk_bytes'])
            rows[name] = r
            budgets[name] = [usable, r['block_budget']]
    return rows, budgets, excluded


def capacity(doc, now):
    doc = normalize(doc)
    rows, budgets, excluded = available(doc, now)
    domains = {}
    for name, (size, _) in budgets.items():
        domain = rows[name]['domain']
        domains[domain] = domains.get(domain, 0)+size
    # Relaxation: each payload byte consumes one byte in each of k distinct domains.
    # This upper bound ignores indivisible chunks and per-pool fragmentation.
    total = sum(domains.values()); copies = doc['copies']
    lo, hi = 0, total//copies
    while lo < hi:
        mid = (lo+hi+1)//2
        if sum(min(size, mid) for size in domains.values()) >= copies*mid: lo = mid
        else: hi = mid-1
    return {'eligible_bytes': total, 'payload_upper_bound_bytes': lo,
            'domains': domains, 'excluded': excluded, 'policy_sha256': digest(doc)}


def geometry(doc, size):
    require(integer(size, 1) and (size+doc['chunk_bytes']-1)//doc['chunk_bytes'] <= MAX_BLOCKS,
            'Payload outside supported block geometry')
    for offset in range(0, size, doc['chunk_bytes']):
        yield offset, min(doc['chunk_bytes'], size-offset)


def plan(doc, size, now):
    doc = normalize(doc)
    rows, budgets, _ = available(doc, now)
    blocks = []
    for offset, length in geometry(doc, size):
        chosen, domains = [], set()
        # Prefer the pool with most remaining capacity; ties resolve by ID.
        for name in sorted(budgets, key=lambda n: (-budgets[n][0], n)):
            domain = rows[name]['domain']; remaining, count = budgets[name]
            if domain in domains or remaining < length or count < 1: continue
            chosen.append(name); domains.add(domain)
            if len(chosen) == doc['copies']: break
        require(len(chosen) == doc['copies'], 'No feasible greedy placement within current quota; no writes performed')
        for name in chosen:
            budgets[name][0] -= length; budgets[name][1] -= 1
        blocks.append({'offset': offset, 'length': length, 'pools': chosen})
    result = {'schema':'omega.capacity.plan.v1', 'policy_sha256':digest(doc),
              'size_bytes':size, 'blocks':blocks}
    verify(doc, result, now)
    return result


def verify(doc, proposal, now):
    doc=normalize(doc); rows, budgets, _=available(doc,now)
    require(isinstance(proposal,dict) and set(proposal)=={'schema','policy_sha256','size_bytes','blocks'}
            and proposal['schema']=='omega.capacity.plan.v1' and proposal['policy_sha256']==digest(doc), 'Policy pin mismatch')
    expected=list(geometry(doc,proposal['size_bytes'])); blocks=proposal['blocks']
    require(isinstance(blocks,list) and len(blocks)==len(expected), 'Invalid block count')
    for block,(offset,length) in zip(blocks,expected):
        require(isinstance(block,dict) and set(block)=={'offset','length','pools'} and
                integer(block['offset']) and integer(block['length'],1) and
                (block['offset'],block['length'])==(offset,length), 'Invalid block geometry')
        chosen=block['pools']
        require(isinstance(chosen,list) and len(chosen)==doc['copies'] and
                all(identifier(n) and n in rows for n in chosen), 'Invalid pool selection')
        require(len({rows[n]['domain'] for n in chosen})==doc['copies'], 'Copies share failure domain')
        for name in chosen:
            remaining,count=budgets[name]
            require(remaining>=length and count>=1, 'Quota or operation budget exceeded')
            budgets[name]=[remaining-length,count-1]
    return True


def probe_local(path, host, now):
    require(identifier(host) and integer(now), 'Invalid host/time')
    path=Path(path).resolve(strict=True)
    require(path.is_dir(), 'Local probe needs a directory')
    with_fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(with_fd); info=os.fstatvfs(with_fd)
        total=info.f_blocks*info.f_frsize; free=info.f_bavail*info.f_frsize
        require(integer(total) and integer(free,0,total), 'Invalid filesystem capacity')
        pool=f'{host}:{st.st_dev}'
        require(identifier(pool),'Host identifier too long for volume identity')
        return {'pool':pool, 'total_bytes':total, 'free_bytes':free, 'observed_at':now}
    finally: os.close(with_fd)


def probe_remote(alias, pool, now, *, rclone='rclone', timeout=15):
    """Read quota only. Missing or unlimited quota is deliberately not accepted."""
    require(isinstance(alias,str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',alias)
            and identifier(pool) and integer(now) and integer(timeout,1,60), 'Invalid remote probe')
    try:
        with subprocess.Popen([rclone,'about',alias+':','--json'],stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as proc:
            data=bytearray(); deadline=time.monotonic()+timeout
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout,selectors.EVENT_READ)
                    while True:
                        remaining=deadline-time.monotonic()
                        require(remaining>0 and selector.select(remaining),'Quota probe timeout')
                        part=os.read(proc.stdout.fileno(),min(8192,65537-len(data)))
                        if not part: break
                        data.extend(part); require(len(data)<=65536,'Quota output too large')
                require(proc.wait(timeout=max(.001,deadline-time.monotonic()))==0,'Quota probe failed')
            finally:
                if proc.poll() is None: proc.kill();proc.wait()
        obj=json.loads(data,object_pairs_hook=unique_json)
        require(isinstance(obj,dict) and integer(obj.get('total')) and
                integer(obj.get('free'),0,obj['total']),'Unknown or invalid remote quota')
        total,free=obj['total'],obj['free']
        # free already includes shared services/trash where the provider supports them.
        if 'used' in obj:
            require(integer(obj['used']),'Invalid used quota')
            free=min(free,max(0,total-obj['used']))
        return {'pool':pool,'total_bytes':total,'free_bytes':free,'observed_at':now}
    except (OSError,subprocess.SubprocessError,UnicodeError,ValueError,RecursionError) as exc:
        raise PolicyError('Remote quota unavailable or invalid') from None


def unique_json(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'Duplicate JSON field');result[k]=v
    return result


def read_json(path):
    with Path(path).open('rb') as f: data=f.read(MAX_JSON+1)
    require(len(data)<=MAX_JSON,'JSON input too large')
    return json.loads(data,object_pairs_hook=unique_json)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__); subs=parser.add_subparsers(dest='cmd',required=True)
    for cmd in ('capacity','plan','verify'):
        p=subs.add_parser(cmd); p.add_argument('--policy',required=True,type=Path)
        if cmd=='plan': p.add_argument('--bytes',required=True,type=int)
        if cmd=='verify': p.add_argument('--proposal',required=True,type=Path)
    p=subs.add_parser('probe-local');p.add_argument('--path',required=True,type=Path);p.add_argument('--host',required=True)
    p=subs.add_parser('probe-remote');p.add_argument('--alias',required=True);p.add_argument('--pool',required=True)
    a=parser.parse_args(argv);now=int(time.time())
    try:
        if a.cmd=='probe-local': result=probe_local(a.path,a.host,now)
        elif a.cmd=='probe-remote': result=probe_remote(a.alias,a.pool,now)
        else:
            doc=read_json(a.policy)
            if a.cmd=='capacity': result=capacity(doc,now)
            elif a.cmd=='plan': result=plan(doc,a.bytes,now)
            else: result={'valid':verify(doc,read_json(a.proposal),now)}
        print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0
    except (ValueError,OSError,TypeError,KeyError,RecursionError) as exc:
        print('CAPACITY ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__': sys.exit(main())
