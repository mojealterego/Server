#!/usr/bin/env python3
"""Fail-closed capacity admission for preprovisioned dedicated SMB filesystems."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import sys

class LimitError(ValueError):pass


def parse_limits(value):
    if not isinstance(value,str) or not re.fullmatch(r'[1-9][0-9]{0,7}(,[1-9][0-9]{0,7}){2}',value):
        raise LimitError('Expected three positive MiB limits (compat,secure,models)')
    caps=tuple(int(x)*1024**2 for x in value.split(','))
    if any(x>64*1024**4 for x in caps):raise LimitError('Volume limit exceeds 64 TiB')
    return caps


def mount_layout(path):
    """Check mountinfo for a local filesystem root and no nested mounts."""
    def unescape(value):
        return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)
    path=path.absolute();matched=[]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,right=line.split(' - ',1);fields=left.split();target=Path(unescape(fields[4]))
        if target==path:matched.append((unescape(fields[3]),right.split()[0]))
        elif path in target.parents:raise LimitError('Nested mount not allowed: '+str(path))
    if len(matched)!=1 or matched[0][0]!='/' or matched[0][1] not in ('ext4','xfs'):
        raise LimitError('Expected dedicated ext4/XFS filesystem root: '+str(path))


def check_volumes(paths,caps,*,mount=os.path.ismount,device=lambda p:p.stat().st_dev,usage=os.statvfs,layout=mount_layout):
    if len(paths)!=3 or len(caps)!=3 or any(type(x) is not int or x<=0 for x in caps):raise LimitError('Three volumes and positive caps required')
    rows=[];devices=set()
    for path,cap in zip(paths,caps):
        p=Path(path)
        if p.is_symlink() or not p.is_dir() or not mount(p):raise LimitError('Dedicated volume mount required: '+str(p))
        layout(p)
        dev=device(p)
        if dev==device(p.parent) or dev in devices:raise LimitError('Volumes must have distinct filesystem devices')
        devices.add(dev);s=usage(p);total=s.f_blocks*s.f_frsize
        if total<=0 or total>cap:raise LimitError('Filesystem capacity exceeds configured limit: '+str(p))
        rows.append({'path':str(p),'capacity_bytes':total,'available_bytes':s.f_bavail*s.f_frsize,'limit_bytes':cap})
    return rows


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--limits',required=True);p.add_argument('--paths',nargs=3,type=Path,required=True);a=p.parse_args(argv)
    try:print(json.dumps(check_volumes(a.paths,parse_limits(a.limits)),sort_keys=True));return 0
    except (ValueError,OSError) as exc:print('SMB LIMIT ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
