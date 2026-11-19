"""Bounded, serial polling of certified network assignments on one node."""
from __future__ import annotations
import time
from .dispatch import DispatchError, require
from tools.capctl import integer


def schedule_node(node,assignments,status,execute,*,retry_failed=False,max_attempts=1,
                  poll_interval=1,idle_timeout=300,max_rpc_errors=5,
                  clock=time.monotonic,sleep=time.sleep):
    require(type(retry_failed) is bool and integer(max_attempts,1,10) and
            (retry_failed or max_attempts==1),'Retry budget requires explicit opt-in')
    require(type(poll_interval) in (int,float) and .1<=poll_interval<=30 and
            type(idle_timeout) in (int,float) and 1<=idle_timeout<=86400 and
            integer(max_rpc_errors,1,10),'Invalid scheduler limits')
    selected=sorted((a for a in assignments if a['node']==node and a['effective_privacy']!='local_only'),
                    key=lambda a:(a['start_slot'],a['end_slot'],a['id']))
    ids=[a['id'] for a in selected];require(ids and len(ids)==len(set(ids)),'No unique dispatch tasks for node')
    deadline=clock()+idle_timeout;last=None;errors=0;due={};failures={};rows={}
    def pause(delay):
        remaining=min(delay,max(0,deadline-clock()))
        if remaining:sleep(remaining)
    def report(reason,status='BLOCKED'):
        return {'status':status,'scope':'NODE_NETWORK_ASSIGNMENTS','node':node,'reason':reason,
                'tasks':{tid:{'state':rows[tid][0],'epoch':rows[tid][1]} for tid in ids if tid in rows}}
    while True:
        try:
            snapshot={}
            for tid in ids:
                reply=status(tid);r=reply['lease'];q=reply['readiness'];state=r['state'];epoch=r['epoch']
                require(r['task']==tid and state in ('PENDING','LEASED','FAILED','COMPLETED') and
                        integer(epoch,0,2**63-1) and (state=='PENDING')==(epoch==0) and
                        (epoch==0 or r['node']==node) and type(q['dependencies_complete']) is bool and
                        type(q['retryable']) is bool and (not q['retryable'] or state in ('FAILED','LEASED')),
                        'Invalid scheduler status')
                remaining=q.get('remaining_attempts')
                require(remaining is None or integer(remaining,0,10),'Invalid administrator attempt budget')
                snapshot[tid]=(state,epoch,q['dependencies_complete'],q['retryable'],remaining)
            rows=snapshot;errors=0
        except (ValueError,OSError,RuntimeError,TypeError,KeyError,AttributeError) as exc:
            errors+=1
            if errors>=max_rpc_errors:return report('RPC_UNAVAILABLE')
            if clock()>=deadline:return report('IDLE_TIMEOUT')
            pause(min(30,poll_interval*(2**(errors-1))));continue
        if rows!=last:
            deadline=clock()+idle_timeout;last=rows.copy()
        if all(r[0]=='COMPLETED' for r in rows.values()):return report('ALL_COMPLETED','COMPLETED')
        terminal=set();runnable=[]
        for tid in ids:
            state,epoch,ready,retryable,remaining=rows[tid];count=failures.get((tid,epoch),0)
            if state=='COMPLETED':terminal.add(tid);continue
            if (remaining==0 and (state=='PENDING' or retryable)) or count>=3 or state in ('FAILED','LEASED') and retryable and (not retry_failed or epoch>=max_attempts):
                terminal.add(tid);continue
            if ready and (state=='PENDING' or retryable and retry_failed) and clock()>=due.get(tid,0):runnable.append(tid)
        if len(terminal)==len(ids):return report('RETRY_BUDGET_OR_POLICY')
        if clock()>=deadline:return report('IDLE_TIMEOUT')
        if runnable:
            tid=runnable[0];state,epoch,_,_,_=rows[tid]
            try:execute(tid,retry=state!='PENDING',max_epoch=max_attempts)
            except (ValueError,OSError,RuntimeError,TypeError,KeyError):
                key=(tid,epoch);count=failures.get(key,0)+1;failures[key]=count
                due[tid]=clock()+min(30,poll_interval*(2**min(count-1,5)))
            else:
                # Never busy-spin if a completion response races visibility.
                due[tid]=clock()+poll_interval
            continue
        pause(poll_interval)
