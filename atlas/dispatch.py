"""Central fenced task dispatch and bounded artifact transport over pinned mTLS.

Single trusted coordinator, one durable SQLite lease authority. No arbitrary
command execution, arbitrary CAS reads or automatic export of local_only data.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import sys
import time
from .artifacts import ArtifactStore, _open_regular, _private_dir, _check_digest, _sync_directory, _check_unchanged
from .mesh import MeshServer, _peer_pin, _remaining, recv_frame, send_frame, server_context, client_context, HEX
from .multimodal import validate_recipes, probe_output, ID, MAX_OUTPUT
from .phaselease import LeaseStore
from .ha_authority import authority
from .distributed_authority import AuthorityGuard, GuardedCoordinator
from tools.capctl import admit, canonical, read_json, integer

CHUNK = 64 * 1024
OPERATIONS = {'status':set(), 'claim':{'envelope'}, 'renew':{'epoch','token','envelope'},
              'fail':{'epoch','token','reason'}, 'upload':{'epoch','token','offset','data'},
              'offset':{'epoch','token'}, 'download':{'epoch','token','dependency','offset'},
              'complete':{'epoch','token','sha256'}}

class DispatchError(ValueError):
    pass


def require(ok, message):
    if not ok:raise DispatchError(message)


def request(host,port,ctx,server_pin,body,*,timeout=30):
    require(isinstance(server_pin,str) and HEX.fullmatch(server_pin),'Invalid server pin')
    require(integer(port,1,65535) and integer(timeout,1,60),'Invalid connection limits')
    require(ctx.verify_mode==ssl.CERT_REQUIRED and ctx.check_hostname and ctx.minimum_version==ssl.TLSVersion.TLSv1_3,'Unsafe client TLS context')
    deadline=time.monotonic()+timeout
    try:
        with socket.create_connection((host,port),timeout=timeout) as raw:
            _remaining(raw,deadline)
            with ctx.wrap_socket(raw,server_hostname=host) as peer:
                require(peer.version()=='TLSv1.3' and _peer_pin(peer)==server_pin,'Server pin mismatch')
                send_frame(peer,body,deadline);reply=recv_frame(peer,deadline)
                require(isinstance(reply,dict) and reply.get('status')=='OK','Dispatch rejected')
                require(reply.get('plan')==body['plan'] and reply.get('task')==body['task'] and reply.get('op')==body['op'],'Response binding mismatch')
                return reply
    except (OSError,ValueError,KeyError,TypeError,RecursionError) as exc:
        raise DispatchError('Dispatch request failed: '+str(exc)) from exc


class DispatchClient:
    """Resumable file transport; caller owns lease renewal and retry decisions."""
    def __init__(self,host,port,ctx,server_pin,plan,*,timeout=30):
        _check_digest(plan)
        self.host=host;self.port=port;self.ctx=ctx;self.pin=server_pin;self.plan=plan;self.timeout=timeout

    def call(self,op,task,**fields):
        return request(self.host,self.port,self.ctx,self.pin,{'op':op,'task':task,'plan':self.plan,**fields},timeout=self.timeout)

    def publish_file(self,task,credentials,source,*,check=lambda:None):
        fd,before=_open_regular(Path(source))
        try:
            require(0<before.st_size<=MAX_OUTPUT,'Invalid output file size')
            h=hashlib.sha256();size=0
            while data:=os.read(fd,CHUNK):
                size+=len(data);require(size<=before.st_size,'Output grew');h.update(data)
            _check_unchanged(fd,before,size);sha=h.hexdigest()
            state=self.call('status',task)['lease']['state']
            if state!='COMPLETED':
                offset=self.call('offset',task,**credentials)['offset']
                require(integer(offset,0,size),'Remote offset exceeds file size')
                while offset<size:
                    check()
                    data=os.pread(fd,min(CHUNK,size-offset),offset)
                    require(len(data)==min(CHUNK,size-offset),'Output changed during upload')
                    nxt=self.call('upload',task,**credentials,offset=offset,data=base64.b64encode(data).decode())['offset']
                    require(nxt==offset+len(data),'Upload acknowledgement mismatch');offset=nxt
            _check_unchanged(fd,before,size)
            check();result=self.call('complete',task,**credentials,sha256=sha)
            require(result['lease']['state']=='COMPLETED' and result['lease']['output_sha256']==sha,'Completion receipt mismatch')
            return result
        finally:os.close(fd)

    def fetch_input(self,task,credentials,dependency,expected,directory,*,check=lambda:None):
        require(isinstance(dependency,str) and ID.fullmatch(dependency),'Invalid dependency ID')
        sha=expected['sha256'];_check_digest(sha);size=expected['size_bytes']
        require(integer(size,1,MAX_OUTPUT),'Invalid dependency size')
        directory=Path(directory);_private_dir(directory)
        final=directory/(dependency+'.'+sha);part=directory/(final.name+'.part')
        if final.exists() or final.is_symlink():
            fd,st=_open_regular(final)
            try:
                require(st.st_size==size,'Existing dependency size mismatch');h=hashlib.sha256();n=0
                while data:=os.read(fd,CHUNK):n+=len(data);require(n<=size,'Dependency grew');h.update(data)
                _check_unchanged(fd,st,n);require(h.hexdigest()==sha,'Existing dependency hash mismatch')
            finally:os.close(fd)
            return final
        fd=os.open(part,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o077,'Unsafe partial dependency')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:raise DispatchError('Dependency download busy') from exc
            st=os.fstat(fd);offset=st.st_size;require(offset<=size,'Partial dependency too large')
            while offset<size:
                check();r=self.call('download',task,**credentials,dependency=dependency,offset=offset)
                require(r['sha256']==sha and r['size_bytes']==size and r['offset']==offset,'Dependency receipt mismatch')
                data=base64.b64decode(r['data'],validate=True)
                require(len(data)==min(CHUNK,size-offset),'Invalid dependency chunk length')
                written=0
                while written<len(data):
                    n=os.pwrite(fd,data[written:],offset+written);require(n>0,'Short write');written+=n
                offset+=len(data);os.fsync(fd)
            os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();n=0;before=os.fstat(fd)
            while data:=os.read(fd,CHUNK):n+=len(data);require(n<=size,'Dependency grew');h.update(data)
            _check_unchanged(fd,before,n)
            if n!=size or h.hexdigest()!=sha:
                part.unlink();_sync_directory(directory);raise DispatchError('Dependency SHA-256 mismatch; discarded partial')
            os.fsync(fd);os.link(part,final,follow_symlinks=False);_sync_directory(directory)
            part.unlink();_sync_directory(directory);return final
        finally:os.close(fd)


class Coordinator:
    def __init__(self,db,plan,tasks,nodes,catalog,cas,staging,policy,replay,media_tools,*,ttl=60,max_attempts=3):
        require(integer(ttl,1,120),'Dispatch TTL must be 1..120 seconds')
        self.db=Path(db);self.replay=Path(replay);self.cas=cas;self.ttl=ttl
        _private_dir(self.db.parent);_private_dir(self.replay.parent)
        require(self.db.resolve()!=self.replay.resolve(),'Separate lease and replay databases required')
        with LeaseStore(self.db,plan,tasks,nodes,catalog,artifacts=cas) as lease:
            validate_recipes(lease.task_list,lease.catalog,lease.assignments,allow_cross_node=True)
            self.plan=lease.document;self.tasks=lease.task_list;self.nodes=lease.node_list;self.catalog=lease.catalog
            self.hash=lease.plan_hash;self.node_map=lease.nodes
            for task in self.tasks:
                require(len(canonical({'task':task,'models':{m:catalog[m] for m in task['models']}}))<=65536,'Task recipe exceeds transport budget')
        self.policy=copy.deepcopy(policy);self.media_tools=copy.deepcopy(media_tools)
        require(isinstance(policy,dict) and all(n['id'] in policy and policy[n['id']]['trust']==n['trust'] and policy[n['id']]['priority']==n.get('priority',100) for n in self.nodes),'Plan/policy node mismatch')
        staging=Path(staging);staging.mkdir(mode=0o700,exist_ok=True);_private_dir(staging)
        self.staging=staging/self.hash;self.staging.mkdir(mode=0o700,exist_ok=True);_private_dir(self.staging)
        with self._open() as lease:lease.configure_attempt_limit(max_attempts)

    def _open(self):return LeaseStore(self.db,self.plan,self.tasks,self.nodes,self.catalog,artifacts=self.cas)

    def _attest(self,ident,envelope,task,*,starting):
        require(isinstance(envelope,dict) and envelope.get('node',{}).get('id')==ident,'Certificate/attestation mismatch')
        node,=admit([envelope],self.policy,self.replay,ttl=120)
        planned=self.node_map[ident]
        reserve=max(node['ram_headroom_mb'],planned['ram_headroom_mb'])
        require(0<=node['thermal_c']<43 and task['engine'] in node['capabilities'] and set(task['models'])<=set(node['models']),'Live capability rejected')
        require(node['ram_available_mb']>=reserve+(task['ram_mb'] if starting else 0),'Live RAM rejected')
        if starting:require(node['disk_free_bytes']>=task['output_bytes'],'Live disk rejected')

    @contextmanager
    def _lock(self,task):
        fd=os.open(self.staging/(task+'.lock'),os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_RDWR,0o600)
        try:
            st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o077,'Unsafe staging lock')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:raise DispatchError('Task transfer busy') from exc
            yield
        finally:os.close(fd)

    def _part(self,task,epoch):return self.staging/f'{task}.{epoch}.part'

    @staticmethod
    def _owner(lease,tid,ident,req,*,completed=False):
        return lease._transaction(lambda:lease._check_owner(tid,ident,req['token'],req['epoch'],time.time(),completed=completed))

    def _upload(self,path,offset,data,budget):
        require(integer(offset,0,budget) and isinstance(data,str) and len(data)<=4*((CHUNK+2)//3),'Invalid upload chunk')
        raw=base64.b64decode(data,validate=True)
        require(0<len(raw)<=CHUNK and base64.b64encode(raw).decode()==data and offset+len(raw)<=budget,'Chunk exceeds output budget')
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o077,'Unsafe staged data')
            size=st.st_size;require(size<=budget,'Staging exceeds budget')
            if offset<size:
                require(offset+len(raw)<=size and os.pread(fd,len(raw),offset)==raw,'Conflicting repeated chunk')
                # An earlier acknowledgement may have been lost; repeat is safe.
                os.fsync(fd);_sync_directory(path.parent);return size
            require(offset==size,'Noncontiguous upload')
            written=0
            while written<len(raw):
                n=os.pwrite(fd,raw[written:],offset+written);require(n>0,'Short write');written+=n
            os.fsync(fd);_sync_directory(path.parent);return size+len(raw)
        finally:os.close(fd)

    def _input(self,lease,task,dep):
        require(dep in task.get('depends_on',[]),'Not an authorized dependency')
        row=lease.status(dep);require(row['state']=='COMPLETED','Dependency incomplete')
        sha=row['output_sha256'];self.cas.verify(sha);path=self.cas._path(sha)
        return {'sha256':sha,'size_bytes':path.stat().st_size,'kind':lease.tasks[dep]['recipe']['kind']}

    def handle(self,ident,req):
        require(isinstance(req,dict) and isinstance(req.get('op'),str) and req['op'] in OPERATIONS,'Unknown dispatch operation')
        op=req['op'];expected={'op','task','plan'}|OPERATIONS[op]
        require(set(req)==expected or op=='claim' and expected<=set(req)<=expected|{'retry','max_epoch'},'Unexpected request fields')
        require(req['plan']==self.hash and isinstance(req['task'],str),'Plan mismatch')
        tid=req['task']
        with self._open() as lease:
            assignment=lease.assignments.get(tid);require(assignment is not None and assignment['node']==ident,'Task/node mismatch')
            # The verified plan already propagates the strictest upstream privacy.
            require(assignment['effective_privacy']!='local_only','Local-only data cannot cross transport')
            task=lease.tasks[tid];budget=assignment['disk_bytes']
            def reply(**data):return {'status':'OK','plan':self.hash,'task':tid,'op':op,**data}
            if op=='status':
                def status_snapshot():
                    row=lease.status(tid)
                    ready=all(lease.status(dep)['state']=='COMPLETED' for dep in task.get('depends_on',[]))
                    remaining=lease._attempt_budget(tid)
                    retryable=row['state']=='FAILED' or row['state']=='LEASED' and row['expires_at']<=time.time()
                    return reply(lease=row,readiness={'dependencies_complete':ready,'retryable':retryable,'remaining_attempts':remaining})
                return lease._transaction(status_snapshot)
            if op=='claim':
                require(type(req.get('retry',False)) is bool,'Invalid retry flag')
                require('max_epoch' not in req or integer(req['max_epoch'],1,10),'Invalid epoch budget')
                with self._lock(tid):
                    previous=lease.status(tid)
                    require(lease._attempt_budget(tid)!=0,'Administrator attempt budget exhausted')
                    require('max_epoch' not in req or previous['epoch']<req['max_epoch'],'Epoch budget exhausted')
                    require(previous['state']=='PENDING' or req.get('retry',False) and (previous['state']=='FAILED' or previous['state']=='LEASED' and previous['expires_at']<=time.time()),'Task not eligible for claim')
                    inputs={dep:self._input(lease,task,dep) for dep in task.get('depends_on',[])}
                    self._attest(ident,req['envelope'],task,starting=True)
                    owner=lease.claim(tid,ident,ttl=self.ttl)
                    # Stable lock serializes old upload requests and new claims.
                    # Remove only prior epochs belonging to this exact task.
                    for epoch in (previous['epoch'],):
                        if epoch:self._part(tid,epoch).unlink(missing_ok=True)
                    _sync_directory(self.staging)
                    return reply(lease=owner,lease_ttl=self.ttl,recipe=task['recipe'],models={m:lease.catalog[m] for m in task['models']},inputs=inputs,output_bytes=budget)
            require(integer(req.get('epoch'),1,2**63-1) and isinstance(req.get('token'),str) and len(req['token'])==43,'Invalid lease credential')
            if op=='renew':
                self._owner(lease,tid,ident,req);self._attest(ident,req['envelope'],task,starting=False)
                return reply(lease=lease.renew(tid,ident,req['token'],req['epoch'],ttl=self.ttl),lease_ttl=self.ttl)
            if op=='download':
                self._owner(lease,tid,ident,req)
                dep=req['dependency'];require(isinstance(dep,str),'Invalid dependency')
                # Complete objects are immutable within the trusted CAS boundary;
                # rehash at claim, and clients must check full SHA on receipt.
                require(dep in task.get('depends_on',[]),'Not an authorized dependency')
                row=lease.status(dep);require(row['state']=='COMPLETED','Dependency incomplete')
                sha=row['output_sha256'];fd,st=_open_regular(self.cas._path(sha))
                try:
                    offset=req['offset'];require(integer(offset,0,st.st_size),'Invalid download offset')
                    content=os.pread(fd,min(CHUNK,st.st_size-offset),offset)
                    require(len(content)==min(CHUNK,st.st_size-offset),'Incomplete dependency read')
                finally:os.close(fd)
                self._owner(lease,tid,ident,req)
                return reply(sha256=sha,size_bytes=st.st_size,offset=offset,data=base64.b64encode(content).decode())
            with self._lock(tid):
                row=self._owner(lease,tid,ident,req,completed=op=='complete')
                path=self._part(tid,req['epoch'])
                if op=='fail':
                    result=lease.fail(tid,ident,req['token'],req['epoch'],req['reason']);path.unlink(missing_ok=True);_sync_directory(self.staging);return reply(lease=result)
                if op=='offset':
                    if not path.exists():return reply(offset=0)
                    fd,st=_open_regular(path);os.close(fd);return reply(offset=st.st_size)
                if op=='upload':return reply(offset=self._upload(path,req['offset'],req['data'],budget))
                if op=='complete':
                    sha=req['sha256'];_check_digest(sha)
                    if row[4]=='COMPLETED':
                        require(row[5]==sha,'Completion digest differs');self.cas.verify(sha)
                        path.unlink(missing_ok=True);_sync_directory(self.staging)
                        return reply(lease=lease.status(tid))
                    actual,size=self.cas._scan(path,max_bytes=budget);require(actual==sha and size>0,'Output SHA-256 mismatch')
                    probe_output(path,task['recipe']['kind'],task['recipe'],self.media_tools)
                    # The existing LeaseStore rehashes and fences again before commit.
                    result=lease.complete(tid,ident,req['token'],req['epoch'],path)
                    require(result['output_sha256']==sha,'Completion digest changed')
                    path.unlink(missing_ok=True);_sync_directory(self.staging);return reply(lease=result)
            raise DispatchError('Unsupported operation')


class DispatchHandler:
    def __init__(self,request,address,server):
        deadline=time.monotonic()+server.timeout
        try:
            _remaining(request,deadline)
            with server.ctx.wrap_socket(request,server_side=True) as peer:
                if peer.version()!='TLSv1.3':return
                ident=server.pins.get(_peer_pin(peer))
                if ident is None:return
                try:out=server.coordinator.handle(ident,recv_frame(peer,deadline))
                except (ValueError,OSError,KeyError,TypeError,AttributeError,sqlite3.Error,RecursionError):out={'status':'REJECTED'}
                send_frame(peer,out,deadline)
        except (ValueError,OSError,RecursionError):return


class DispatchServer(MeshServer):
    def __init__(self,address,ctx,coordinator,pins,**kwargs):
        super().__init__(address,ctx,coordinator.policy,pins,coordinator.replay,**kwargs)
        self.coordinator=coordinator;self.RequestHandlerClass=DispatchHandler


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('serve');c=sub.add_parser('request')
    for q in (s,c):
        for name in ('ca','cert','key'):q.add_argument('--'+name,type=Path,required=True)
        q.add_argument('--port',type=int,default=8444);q.add_argument('--timeout',type=int,default=30)
    for name in ('db','plan','tasks','nodes','catalog','cas','staging','policy','replay','pins','media-tools'):s.add_argument('--'+name,type=Path,required=True)
    s.add_argument('--bind',default='127.0.0.1');s.add_argument('--allow-network',action='store_true');s.add_argument('--lease-ttl',type=int,default=60);s.add_argument('--max-attempts',type=int,default=3)
    s.add_argument('--standby-wait',type=int,default=0,help='Wait for same-host authority lock, up to 3600 seconds')
    s.add_argument('--distributed-authority-config',type=Path,help='Optional operator-fenced etcd authority grant')
    c.add_argument('--host',required=True);c.add_argument('--server-pin',required=True);c.add_argument('--body',type=Path,required=True);c.add_argument('--upload-file',type=Path);c.add_argument('--download-dir',type=Path)
    a=p.parse_args(argv)
    try:
        if a.cmd=='serve':
            with authority(a.db,wait=a.standby_wait):
                guard=AuthorityGuard.from_config(read_json(a.distributed_authority_config)) if a.distributed_authority_config else None
                if guard is not None:guard.check()
                q=Coordinator(a.db,read_json(a.plan),read_json(a.tasks),read_json(a.nodes),read_json(a.catalog),ArtifactStore(a.cas),a.staging,read_json(a.policy),a.replay,read_json(a.media_tools),ttl=a.lease_ttl,max_attempts=a.max_attempts)
                if guard is not None:q=GuardedCoordinator(q,guard)
                with DispatchServer((a.bind,a.port),server_context(a.ca,a.cert,a.key),q,read_json(a.pins),timeout=a.timeout,allow_network=a.allow_network) as srv:
                    # Keep authority until all in-flight handlers have drained.
                    srv.daemon_threads=False;srv.block_on_close=True
                    print('Dispatch listening on '+str(srv.server_address),file=sys.stderr,flush=True);srv.serve_forever()
        else:
            body=read_json(a.body);ctx=client_context(a.ca,a.cert,a.key)
            require(not (a.upload_file and a.download_dir),'Choose one transfer operation')
            if a.upload_file or a.download_dir:
                client=DispatchClient(a.host,a.port,ctx,a.server_pin,body['plan'],timeout=a.timeout)
                cred={k:body[k] for k in ('token','epoch')}
                if a.upload_file:result=client.publish_file(body['task'],cred,a.upload_file)
                else:result={'path':str(client.fetch_input(body['task'],cred,body['dependency'],body['expected'],a.download_dir))}
            else:result=request(a.host,a.port,ctx,a.server_pin,body,timeout=a.timeout)
            print(json.dumps(result,sort_keys=True))
        return 0
    except KeyboardInterrupt:return 130
    except (ValueError,OSError,TypeError,KeyError,sqlite3.Error,RecursionError) as exc:
        print('DISPATCH ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
