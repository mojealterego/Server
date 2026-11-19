"""Optional fail-closed local execution gate for signed capabilities and live resource telemetry."""
from __future__ import annotations
import argparse
import json
import sqlite3
import sys
from pathlib import Path
import shutil
import time
from tools.capctl import admit, read_json, sign, CapabilityError

MIB=1024**2

class GateError(RuntimeError):
    pass

class Telemetry:
    def __init__(self, thermal_file: Path, disk: Path, *, meminfo=Path('/proc/meminfo'), cgroup: Path|None=None):
        self.thermal_file=Path(thermal_file);self.disk=Path(disk)
        self.meminfo=Path(meminfo);self.cgroup=cgroup

    def sample(self):
        try:
            rows=[line.split() for line in self.meminfo.read_text().splitlines() if line.startswith('MemAvailable:')]
            if len(rows)!=1 or len(rows[0])!=3 or rows[0][2]!='kB':raise ValueError('Missing MemAvailable kB')
            available=int(rows[0][1])*1024
            if available<0:raise ValueError('Negative MemAvailable')
            if self.cgroup is not None:
                limit=(self.cgroup/'memory.max').read_text().strip()
                current=int((self.cgroup/'memory.current').read_text())
                if current<0:raise ValueError('Negative memory.current')
                if limit!='max':
                    ceiling=int(limit)
                    if ceiling<0:raise ValueError('Negative memory.max')
                    available=min(available,max(0,ceiling-current))
            thermal=int(self.thermal_file.read_text().strip())/1000
            if not -40<=thermal<=150:raise ValueError('Invalid millidegree reading')
            return {'ram_available_mb':available//MIB,'thermal_c':thermal,'disk_free_bytes':shutil.disk_usage(self.disk).free}
        except (OSError,ValueError,OverflowError) as exc:
            raise GateError('TELEMETRY_UNAVAILABLE: '+str(exc)) from exc

class RuntimeGate:
    def __init__(self,probe,node,task,*,deadline,clock=time.monotonic):
        self.probe=probe;self.node=node;self.task=task;self.deadline=deadline;self.clock=clock
        if (node['thermal_c']>=43 or task['engine'] not in node['capabilities'] or not set(task['models'])<=set(node['models'])
                or task['ram_mb']+node['ram_headroom_mb']>node['ram_available_mb']
                or task.get('output_bytes',0)>node['disk_free_bytes']):
            raise GateError('TASK_OUTSIDE_SIGNED_CAPACITY')

    def check(self,*,starting=False):
        if self.clock()>=self.deadline:raise GateError('ATTESTATION_EXPIRED')
        s=self.probe.sample()
        if s['thermal_c']>=43:raise GateError('THERMAL_LIMIT')
        reserve=self.node['ram_headroom_mb']+(self.task['ram_mb'] if starting else 0)
        if s['ram_available_mb']<reserve:raise GateError('RAM_LIMIT')
        if starting and s['disk_free_bytes']<self.task.get('output_bytes',0):raise GateError('DISK_LIMIT')
        if self.clock()>=self.deadline:raise GateError('ATTESTATION_EXPIRED')
        return s

def admitted_gate(probe,envelope,policy,db,task,planned_node,*,ttl=120):
    # Read the signed identity before consuming replay state; verify cryptographically in admit.
    if envelope.get('node',{}).get('id')!=planned_node['id']:raise GateError('NODE_MISMATCH')
    wall=time.time_ns();mono=time.monotonic()
    try:
        node,=admit([envelope],policy,db,now_ns=wall,ttl=ttl)
    except (CapabilityError,OSError,ValueError,KeyError,TypeError,sqlite3.Error) as exc:
        raise GateError('CAPABILITY_REJECTED: '+str(exc)) from exc
    if node['trust']!=planned_node['trust'] or node['priority']!=planned_node.get('priority',100):
        raise GateError('PLAN_POLICY_MISMATCH')
    # Never downgrade the plan's free-memory buffer.
    node={**node,'ram_headroom_mb':max(node['ram_headroom_mb'],planned_node['ram_headroom_mb'])}
    remaining=min(ttl,(envelope['issued_ns']+ttl*10**9-wall)/10**9)
    return RuntimeGate(probe,node,task,deadline=mono+remaining)

def add_runtime_args(parser):
    for name in ('runtime-envelope','runtime-policy','runtime-db','thermal-file','runtime-cgroup'):
        parser.add_argument('--'+name,type=Path)
    parser.add_argument('--runtime-ttl',type=int,default=120)

def gate_from_args(args,tasks,nodes):
    mandatory=[args.runtime_envelope,args.runtime_policy,args.runtime_db,args.thermal_file]
    if not any(mandatory) and args.runtime_cgroup is None:return None
    if not all(mandatory):raise GateError('All runtime envelope/policy/db/thermal flags are required')
    task=next((t for t in tasks if t['id']==args.task),None)
    node=next((n for n in nodes if n['id']==args.node),None)
    if task is None or node is None:raise GateError('Unknown task or node')
    # work root might not exist yet; its parent is the filesystem used by executor.
    probe=Telemetry(args.thermal_file,args.work if args.work.exists() else args.work.parent,cgroup=args.runtime_cgroup)
    return admitted_gate(probe,read_json(args.runtime_envelope),read_json(args.runtime_policy),args.runtime_db,task,node,ttl=args.runtime_ttl)

def collect_signed(probe,template,key):
    if not isinstance(template,dict) or set(template)!={'id','capabilities','models','ram_headroom_mb'}:
        raise GateError('Invalid node template; measurements are collected, not supplied')
    return sign({**template,**probe.sample()},key)

def main(argv=None):
    p=argparse.ArgumentParser(description='Collect and sign live local telemetry')
    for name in ('template','key','thermal-file','disk'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--cgroup',type=Path)
    a=p.parse_args(argv)
    try:
        result=collect_signed(Telemetry(a.thermal_file,a.disk,cgroup=a.cgroup),read_json(a.template),a.key)
        print(json.dumps(result,sort_keys=True,allow_nan=False));return 0
    except (GateError,ValueError,OSError,TypeError,KeyError) as exc:
        print('RUNTIME GATE: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
