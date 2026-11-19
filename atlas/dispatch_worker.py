"""Operator-provisioned worker for one typed stage on a remote coordinator.

Reuses local multimodal jobs and crash guardian. No remote command strings.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from .artifacts import _private_dir
from .dispatch import DispatchClient, DispatchError, require
from .execution import _terminate_group
from .mesh import client_context
from .multimodal import ROOT,KINDS,validate_recipes,absolute_file,prompt_text,read_text,probe_output
from .phaseverify import verify_workflow
from .recovery import NodeLock,spawn_guarded,RecoveryBusy
from .runtime_gate import Telemetry,collect_signed,GateError
from tools.capctl import read_json,integer


def run_task(client,plan,tasks,nodes,catalog,node,tid,deployment,work,probe,template,key,*,timeout=600,retry=False):
    require(type(timeout) in (int,float) and .1<=timeout<=86400,'Invalid worker timeout')
    require(verify_workflow(plan,tasks,nodes,catalog)['primary_feasible'] and plan['admitted'],'Plan not admitted')
    require(client.plan==plan['certificate_sha256'],'Plan pin mismatch')
    assignments={a['id']:a for a in plan['primary']['assignments']}
    ordered=validate_recipes(tasks,catalog,assignments,allow_cross_node=True)
    byid={t['id']:t for t in ordered};task=byid.get(tid)
    require(task is not None and assignments[tid]['node']==node and assignments[tid]['effective_privacy']!='local_only','Task not allowed over dispatch')
    planned=next(n for n in nodes if n['id']==node)
    require(template.get('id')==node and deployment.get('node')==node,'Local deployment identity mismatch')
    work=Path(work).absolute();_private_dir(work)
    anchor=work/'worker.lock-anchor';fd=os.open(anchor,os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_RDWR,0o600);os.close(fd)
    r=task['recipe'];kind=r['kind'];budget=task['output_bytes']
    if kind=='qwen_text':
        from .runner import _base
        _base(deployment['llama_endpoint'])
    else:
        for k in ('sd_cli','ffprobe','ffmpeg'):absolute_file(deployment[k],executable=True)
        require(deployment.get('backend') in ('cpu','cuda0','vulkan0','hip0'),'Invalid backend')
        paths=[absolute_file(deployment['model_paths'][m]) for m in task['models']];require(len(set(paths))==len(paths),'Duplicate weight paths')
    with NodeLock(anchor,node) as lock:
        stop=threading.Event();lost=threading.Event();thread=None;proc=None;control=None;reader=None;cred=None;temporary=None
        start=time.monotonic();end=start+timeout;reason='PROCESS_FAILED';deadline=[start]
        def check(starting=False):
            if lost.is_set() or time.monotonic()>=deadline[0]:raise GateError('Remote lease lost')
            if time.monotonic()>=end:raise TimeoutError('Worker deadline exceeded')
            snap=probe.sample();reserve=max(template['ram_headroom_mb'],planned['ram_headroom_mb'])
            if not 0<=snap['thermal_c']<43 or snap['ram_available_mb']<reserve+(task['ram_mb'] if starting else 0):raise GateError('Local resource policy denied')
            if starting and snap['disk_free_bytes']<budget:raise GateError('Local disk policy denied')
        try:
            a=client.call('claim',tid,envelope=collect_signed(probe,template,key),retry=retry)
            owner=a['lease'];ttl=a['lease_ttl'];require(integer(ttl,1,120) and owner['node']==node and owner['task']==tid and owner['plan_sha256']==client.plan and owner['state']=='LEASED','Lease binding mismatch')
            cred={k:owner[k] for k in ('token','epoch')};deadline[0]=start+ttl
            require(a['recipe']==r and a['models']=={m:catalog[m] for m in task['models']} and a['output_bytes']==budget and set(a['inputs'])==set(task.get('depends_on',[])),'Remote recipe differs from local admitted plan')
            def heartbeat():
                while not stop.wait(max(.15,min(ttl/3,2))):
                    try:
                        check();sent=time.monotonic();reply=client.call('renew',tid,**cred,envelope=collect_signed(probe,template,key))
                        require(reply['lease_ttl']==ttl and reply['lease']['epoch']==cred['epoch'] and reply['lease']['task']==tid,'Renewal binding mismatch')
                        deadline[0]=sent+ttl
                    except Exception:lost.set();return
            thread=threading.Thread(target=heartbeat,daemon=True);thread.start();check(starting=True)
            # A private directory persists only within this attempt; central uploads resume
            # through the same lease via the file client, not via automatic model re-execution.
            temporary=tempfile.TemporaryDirectory(prefix='remote-stage-',dir=work)
            private=Path(temporary.name);inputs={}
            for dep,receipt in a['inputs'].items():
                require(receipt['kind']==byid[dep]['recipe']['kind'] and integer(receipt['size_bytes'],1,byid[dep]['output_bytes']),'Invalid input receipt')
                inputs[dep]=client.fetch_input(tid,cred,dep,receipt,private,check=check)
                probe_output(inputs[dep],receipt['kind'],byid[dep]['recipe'],deployment)
            prompt=private/'prompt.txt'
            text=read_text(inputs[r['prompt_from']]) if 'prompt_from' in r else r['prompt']
            prompt.write_text(prompt_text(text,kind!='qwen_text'),encoding='utf-8')
            spec={**r,'prompt':str(prompt),'output_bytes':budget}
            if kind=='qwen_text':spec['endpoint']=deployment['llama_endpoint']
            else:
                spec.update({k:deployment[k] for k in ('sd_cli','ffprobe','ffmpeg','backend')})
                spec['slots']={slot:{'path':deployment['model_paths'][mid],'sha256':catalog[mid]['sha256'],'bytes':catalog[mid]['bytes']} for slot,mid in r['slots'].items()}
                if kind=='wan_i2v':
                    image=private/'input.png';os.link(inputs[r['image_from']],image);spec['image']=str(image)
            specfile=private/'spec.json';specfile.write_text(json.dumps(spec,ensure_ascii=False,allow_nan=False));specfile.chmod(0o600)
            output=private/('result'+KINDS[kind]);check(starting=True)
            proc,control=spawn_guarded(lock,[sys.executable,'-I',str(ROOT/'tools'/'multimodal_job.py'),'--spec',str(specfile),'--output',str(output)],private,os.environ.copy())
            def drain():
                try:
                    while proc.stdout.read(65536):pass
                except (ValueError,OSError):pass
            reader=threading.Thread(target=drain,daemon=True);reader.start()
            while proc.poll() is None:check();time.sleep(.1)
            reader.join(2);require(proc.returncode==0 and not reader.is_alive(),'Engine process failed or did not drain')
            check();result=client.publish_file(tid,cred,output,check=check)
            return result['lease']
        except BaseException as exc:
            reason='RUNTIME_GUARD' if isinstance(exc,GateError) else 'PROCESS_TIMEOUT' if isinstance(exc,TimeoutError) else 'PROCESS_INTERRUPTED' if isinstance(exc,KeyboardInterrupt) else 'PROCESS_FAILED'
            # Terminate before releasing remote reservation. No second claim is automatic.
            stop.set()
            if proc is not None:_terminate_group(proc)
            if thread is not None:thread.join(client.timeout+11)
            if cred is not None:
                try:client.call('fail',tid,**cred,reason=reason)
                except (ValueError,OSError):pass
            raise
        finally:
            stop.set()
            if control is not None:os.close(control)
            if proc is not None:
                _terminate_group(proc)
                if reader is not None:reader.join(2)
                proc.stdout.close()
            if thread is not None:thread.join(client.timeout+11)
            if temporary is not None:temporary.cleanup()


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('plan','tasks','nodes','catalog','deployment','work','template','sign-key','thermal-file','ca','cert','key'):
        p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--cgroup',type=Path);p.add_argument('--host',required=True);p.add_argument('--server-pin',required=True)
    p.add_argument('--node',required=True);p.add_argument('--task',required=True);p.add_argument('--port',type=int,default=8444)
    p.add_argument('--timeout',type=float,default=600);p.add_argument('--rpc-timeout',type=int,default=10);p.add_argument('--retry-failed',action='store_true')
    a=p.parse_args(argv)
    try:
        plan,tasks,nodes,catalog,deployment,template=(read_json(getattr(a,k)) for k in ('plan','tasks','nodes','catalog','deployment','template'))
        ctx=client_context(a.ca,a.cert,a.key);client=DispatchClient(a.host,a.port,ctx,a.server_pin,plan['certificate_sha256'],timeout=a.rpc_timeout)
        result=run_task(client,plan,tasks,nodes,catalog,a.node,a.task,deployment,a.work,Telemetry(a.thermal_file,a.work,cgroup=a.cgroup),template,a.sign_key,timeout=a.timeout,retry=a.retry_failed)
        print(json.dumps(result,sort_keys=True));return 0
    except KeyboardInterrupt:return 130
    except (ValueError,OSError,RuntimeError,TypeError,KeyError,RecursionError) as exc:
        print('DISPATCH WORKER ERROR: '+type(exc).__name__,file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
