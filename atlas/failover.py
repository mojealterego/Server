"""Operator-confirmed, fenced full restart of a failed network workflow."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import time
from .phaselease import LeaseStore
from .phaseshift import compile_workflow,digest
from .phaseverify import verify_workflow
from .multimodal import validate_recipes
from .artifacts import _private_dir
from tools.capctl import admit,read_json,validate_node,FIELDS

class FailoverError(ValueError):pass


def require(ok,msg):
    if not ok:raise FailoverError(msg)


def recover_restart(lease):
    row=lease.conn.execute('SELECT payload FROM retired_plans WHERE plan_hash=?',(lease.plan_hash,)).fetchone()
    require(row is not None,'No committed successor for this plan')
    return json.loads(row[0])


def watch_restart(lease,failed,*,timeout=60,poll=1,clock=time.monotonic,sleep=time.sleep):
    """Bounded wait for an expired-lease candidate; never perform a cutover."""
    require(failed in lease.nodes,'Unknown failed node')
    require(type(timeout) is int and 1<=timeout<=3600 and type(poll) in (int,float) and .1<=poll<=30,'Invalid watch limits')
    require(all(a['effective_privacy']!='local_only' for a in lease.assignments.values()),'Local-only workflows require separate local recovery')
    deadline=clock()+timeout
    while True:
        def inspect():
            rows=lease.conn.execute('SELECT state,expires_at,node_id FROM leases WHERE plan_hash=?',(lease.plan_hash,)).fetchall()
            now=time.time()
            return {'expired_on_failed':sum(state=='LEASED' and expiry<=now and nid==failed for state,expiry,nid in rows),
                    'active':sum(state=='LEASED' and expiry>now for state,expiry,_ in rows),
                    'completed':sum(state=='COMPLETED' for state,_,_ in rows),
                    'exhausted_tasks':sorted(tid for tid in lease.tasks if lease._attempt_budget(tid)==0)}
        info=lease._transaction(inspect)
        if info['active']==0 and info['expired_on_failed']>0 and info['completed']==0 and not info['exhausted_tasks']:
            return {'status':'CANDIDATE','failed_node':failed,'plan':lease.plan_hash,**info}
        if clock()>=deadline:return {'status':'TIMEOUT','failed_node':failed,'plan':lease.plan_hash,**info}
        sleep(min(poll,max(0,deadline-clock())))


def prepare_restart(lease,failed,live_nodes,*,restart_completed=False,allow_degraded=False,require_expired=False):
    """One authority/DB. Caller verifies live declarations and quiesces workers."""
    require(type(restart_completed) is bool and type(allow_degraded) is bool and type(require_expired) is bool,'Invalid restart authorization')
    _private_dir(lease.path.parent)
    require(failed in lease.nodes,'Unknown failed node')
    require(all(a['effective_privacy']!='local_only' for a in lease.assignments.values()),'Local-only workflows require separate local recovery')
    require(isinstance(live_nodes,list) and 1<=len(live_nodes)<=8,'No live replacement nodes')
    static=[];conservative=[];seen=set()
    for live in live_nodes:
        require(isinstance(live,dict) and set(live)==FIELDS|{'trust','priority'},'Invalid live node fields')
        validate_node({k:live[k] for k in FIELDS});nid=live['id']
        require(nid!=failed and nid in lease.nodes and nid not in seen,'Invalid replacement identity');seen.add(nid)
        n=copy.deepcopy(lease.nodes[nid]);require(live['trust']==n['trust'] and live['priority']==n.get('priority',100),'Trust or priority changed')
        static.append(n);conservative.append({**n,'ram_available_mb':min(n['ram_available_mb'],live['ram_available_mb']),
            'ram_headroom_mb':max(n['ram_headroom_mb'],live['ram_headroom_mb']),
            'disk_free_bytes':min(n['disk_free_bytes'],live['disk_free_bytes']),
            'thermal_c':max(n['thermal_c'],live['thermal_c']),
            'models':sorted(set(n['models'])&set(live['models'])),'capabilities':sorted(set(n['capabilities'])&set(live['capabilities']))})
    settings=copy.deepcopy(lease.document['settings'])
    if allow_degraded:settings['require_n_minus_one']=False
    plan=compile_workflow(lease.task_list,conservative,lease.catalog,**settings)
    require(plan['admitted'],'No admitted restart under live resource limits')
    # Rebase the conservatively computed feasible scenarios onto immutable enrolled
    # capacities, preserving the existing SQLite node-registry contract.
    plan['input_sha256']=digest({'tasks':lease.task_list,'nodes':static,'catalog':lease.catalog,**settings})
    plan['evidence_scope']='Conservative live-snapshot restart; predecessor '+lease.plan_hash+'; generation '+secrets.token_hex(16)
    plan['certificate_sha256']=digest({k:v for k,v in plan.items() if k!='certificate_sha256'})
    require(verify_workflow(plan,lease.task_list,static,lease.catalog)['primary_feasible'],'Invalid successor plan')
    validate_recipes(lease.task_list,lease.catalog,{a['id']:a for a in plan['primary']['assignments']},allow_cross_node=True)
    result={'schema':'omega.restart.v1','predecessor':lease.plan_hash,'failed_node':failed,'nodes':static,'plan':plan}
    def cutover():
        rows=lease.conn.execute('SELECT state,expires_at,node_id FROM leases WHERE plan_hash=?',(lease.plan_hash,)).fetchall()
        now=time.time()
        require(not any(state=='LEASED' and expiry>now for state,expiry,_ in rows),'Active predecessor leases; cutover denied')
        require(restart_completed or not any(state=='COMPLETED' for state,_,_ in rows),'Completed tasks require explicit full-restart authorization')
        if require_expired:
            require(any(state=='LEASED' and expiry<=now and nid==failed for state,expiry,nid in rows),'No expired lease on failed node')
        policy=lease.conn.execute('SELECT root_hash,max_attempts FROM attempt_limits WHERE plan_hash=?',(lease.plan_hash,)).fetchone()
        if policy is not None:
            require(all(lease._attempt_budget(tid)>0 for tid in lease.tasks),'Administrator attempt budget exhausted; failover refused')
            lease.conn.execute('INSERT INTO attempt_limits VALUES(?,?,?)',(plan['certificate_sha256'],*policy))
        lease.conn.execute('INSERT INTO retired_plans VALUES(?,?,?)',(lease.plan_hash,plan['certificate_sha256'],json.dumps(result,sort_keys=True,allow_nan=False)))
        return result
    return lease._transaction(cutover)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prepare','recover','watch'))
    for name in ('db','plan','tasks','nodes','catalog'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--failed-node');p.add_argument('--envelope',type=Path,action='append');p.add_argument('--policy',type=Path);p.add_argument('--replay',type=Path)
    p.add_argument('--confirm-quiesced',action='store_true');p.add_argument('--restart-completed',action='store_true');p.add_argument('--allow-degraded',action='store_true');p.add_argument('--require-expired',action='store_true')
    p.add_argument('--watch-timeout',type=int,default=60);p.add_argument('--poll',type=float,default=1)
    a=p.parse_args(argv)
    try:
        with LeaseStore(a.db,read_json(a.plan),read_json(a.tasks),read_json(a.nodes),read_json(a.catalog)) as lease:
            if a.action=='recover':result=recover_restart(lease)
            elif a.action=='watch':result=watch_restart(lease,a.failed_node,timeout=a.watch_timeout,poll=a.poll)
            else:
                require(a.confirm_quiesced and a.failed_node and a.envelope and a.policy and a.replay,'Explicit quiescence confirmation and fresh signed declarations required')
                require(a.db.resolve()!=a.replay.resolve(),'Separate admission database required')
                live=admit([read_json(x) for x in a.envelope],read_json(a.policy),a.replay,ttl=120)
                result=prepare_restart(lease,a.failed_node,live,restart_completed=a.restart_completed,allow_degraded=a.allow_degraded,require_expired=a.require_expired)
        print(json.dumps(result,sort_keys=True));return 2 if result.get('status')=='TIMEOUT' else 0
    except (ValueError,OSError,TypeError,KeyError,sqlite3.Error,RecursionError) as exc:
        print('FAILOVER ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
