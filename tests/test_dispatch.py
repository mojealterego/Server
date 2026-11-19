import hashlib,base64,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from atlas.artifacts import ArtifactStore
from atlas.phaseshift import compile_workflow
from atlas.mesh import client_context,server_context,fingerprint
from atlas.dispatch import Coordinator,DispatchServer,request,DispatchError,CHUNK
from tools.capctl import sign

class DispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t=tempfile.TemporaryDirectory();cls.addClassCleanup(t.cleanup);cls.keys=Path(t.name)
        def oss(*args):subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        r=cls.keys
        oss('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=ca','-keyout',r/'ca.key','-out',r/'ca.pem')
        for name in ('server','phone','gpu','unknown'):
            oss('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+name,'-keyout',r/(name+'.key'),'-out',r/(name+'.csr'))
            (r/(name+'.key')).chmod(0o600)
            ext=r/(name+'.ext');ext.write_text('basicConstraints=CA:FALSE\nextendedKeyUsage='+('serverAuth' if name=='server' else 'clientAuth')+'\nsubjectAltName=IP:127.0.0.1\n')
            oss('x509','-req','-in',r/(name+'.csr'),'-CA',r/'ca.pem','-CAkey',r/'ca.key','-CAcreateserial','-days','1','-extfile',ext,'-out',r/(name+'.pem'))
        for name in ('phone','gpu'):
            oss('genpkey','-algorithm','ED25519','-out',r/(name+'.sign'));(r/(name+'.sign')).chmod(0o600)
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.cas=ArtifactStore(self.root/'cas')
        self.catalog={i:{'family':'qwen','role':'llm','format':'gguf','bytes':1} for i in ('q1','q2')}
        def task(i,m,recipe,deps=(),privacy='trusted_only'):
            return {'id':i,'engine':'llama','models':[m],'ram_mb':10,'output_bytes':200000,'privacy':privacy,'depends_on':list(deps),'runtime_model_ids':{m:m},'recipe':{'kind':'qwen_text','runtime_model':m,**recipe}}
        self.tasks=[task('first','q1',{'prompt':'hello'}),task('second','q2',{'prompt_from':'first'},['first']),task('private','q1',{'prompt':'secret'},privacy='local_only')]
        self.nodes=[{'id':i,'trust':trust,'priority':1,'ram_available_mb':1000,'ram_headroom_mb':100,'disk_free_bytes':1000000,'thermal_c':31,'capabilities':['llama'],'models':[m]} for i,trust,m in [('phone','local','q1'),('gpu','trusted','q2')]]
        self.plan=compile_workflow(self.tasks,self.nodes,self.catalog);assert self.plan['admitted']
        self.policy={};self.pins={}
        for n in self.nodes:
            name=n['id'];env=self.envelope(name)
            self.policy[name]={'public_key':env['public_key'],'trust':n['trust'],'priority':1,'max_ram_mb':2000,'min_headroom_mb':100,'max_disk_bytes':2000000,'capabilities':n['capabilities'],'models':n['models']}
            self.pins[fingerprint(self.keys/(name+'.pem'))]=name
        self.coord=Coordinator(self.root/'leases.db',self.plan,self.tasks,self.nodes,self.catalog,self.cas,self.root/'staging',self.policy,self.root/'replay.db',{},ttl=30)
        self.start()
    def start(self):
        k=self.keys
        self.server=DispatchServer(('127.0.0.1',0),server_context(k/'ca.pem',k/'server.pem',k/'server.key'),self.coord,self.pins,timeout=5)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.02});self.thread.start();self.addCleanup(self.stop)
    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)
    def envelope(self,name,**updates):
        n=next(x for x in self.nodes if x['id']==name)
        return sign({**{k:v for k,v in n.items() if k not in ('trust','priority')},**updates},self.keys/(name+'.sign'))
    def call(self,name,op,task,**kw):
        k=self.keys;ctx=client_context(k/'ca.pem',k/(name+'.pem'),k/(name+'.key'))
        return request('127.0.0.1',self.server.server_address[1],ctx,fingerprint(k/'server.pem'),{'op':op,'task':task,'plan':self.plan['certificate_sha256'],**kw})
    def claim(self,name='phone',task='first'):
        return self.call(name,'claim',task,envelope=self.envelope(name))
    def cred(self,x):return {'token':x['lease']['token'],'epoch':x['lease']['epoch']}
    def put(self,c,data,offset=0,name='phone',task='first'):
        return self.call(name,'upload',task,**c,offset=offset,data=base64.b64encode(data).decode())
    def finish(self,c,data,name='phone',task='first'):
        return self.call(name,'complete',task,**c,sha256=hashlib.sha256(data).hexdigest())
    def test_cross_node_flow(self):
        a=self.claim();c=self.cred(a);data=b'hello gpu';self.put(c,data);self.finish(c,data)
        b=self.claim('gpu','second');self.assertEqual(b['inputs']['first']['sha256'],hashlib.sha256(data).hexdigest())
        d=self.call('gpu','download','second',**self.cred(b),dependency='first',offset=0)
        self.assertEqual(base64.b64decode(d['data']),data)
        self.put(self.cred(b),b'done',name='gpu',task='second');self.finish(self.cred(b),b'done',name='gpu',task='second')
        self.assertEqual(self.call('gpu','status','second')['lease']['state'],'COMPLETED')
    def test_private_and_wrong_node(self):
        for name,task in [('phone','private'),('gpu','first'),('unknown','first')]:
            with self.assertRaises(DispatchError):self.call(name,'status',task)
    def test_dependency_and_replay(self):
        with self.assertRaises(DispatchError):self.claim('gpu','second')
        env=self.envelope('phone');self.call('phone','claim','first',envelope=env)
        with self.assertRaises(DispatchError):self.call('phone','claim','first',envelope=env)
    def test_upload_idempotency_gap_and_pin(self):
        c=self.cred(self.claim());a=b'a'*CHUNK;b=b'b';self.put(c,a)
        self.assertEqual(self.put(c,a)['offset'],len(a))
        for data,offset in [(b'x',0),(b,CHUNK+1)]:
            with self.assertRaises(DispatchError):self.put(c,data,offset)
        self.put(c,b,CHUNK)
        with self.assertRaises(DispatchError):self.finish(c,b'wrong')
        self.finish(c,a+b);self.finish(c,a+b)
        self.assertTrue(self.cas.verify(hashlib.sha256(a+b).hexdigest()))
    def test_failure_retry_fences_old_epoch(self):
        c=self.cred(self.claim());self.put(c,b'old')
        self.call('phone','fail','first',**c,reason='PROCESS_FAILED')
        with self.assertRaises(DispatchError):self.claim()
        n=self.cred(self.call('phone','claim','first',envelope=self.envelope('phone'),retry=True));self.assertEqual(n['epoch'],2)
        with self.assertRaises(DispatchError):self.put(c,b'stale')
        self.put(n,b'new');self.finish(n,b'new')
    def test_renew_fresh_telemetry(self):
        c=self.cred(self.claim());r=self.call('phone','renew','first',**c,envelope=self.envelope('phone'));self.assertEqual(r['lease']['epoch'],1)
        with self.assertRaises(DispatchError):self.call('phone','renew','first',**c,envelope=self.envelope('phone',thermal_c=44))
    def test_invalid_output_and_unrelated_read(self):
        c=self.cred(self.claim());self.put(c,b'\x00x')
        with self.assertRaises(DispatchError):self.finish(c,b'\x00x')
        self.assertEqual(self.call('phone','status','first')['lease']['state'],'LEASED')
        with self.assertRaises(DispatchError):self.call('phone','download','first',**c,dependency='private',offset=0)
    def test_plan_and_budget(self):
        c=self.cred(self.claim());
        with self.assertRaises(DispatchError):self.call('phone','upload','first',**c,offset=0,data=base64.b64encode(b'a'*(CHUNK+1)).decode())
        with self.assertRaises(DispatchError):self.call('phone','status','first',plan='bad')
    def test_file_client_resume_and_digest(self):
        from atlas.dispatch import DispatchClient
        def client(name):
            k=self.keys;return DispatchClient('127.0.0.1',self.server.server_address[1],client_context(k/'ca.pem',k/(name+'.pem'),k/(name+'.key')),fingerprint(k/'server.pem'),self.plan['certificate_sha256'])
        # Exercise multiple chunks with a larger budget, using a typed text limit.
        # A text artifact is valid up to 2 MiB; actual bytes remain below planned 200000.
        source=self.root/'source';data=b'a'*(CHUNK+11);source.write_bytes(data)
        a=self.claim();c=self.cred(a);self.put(c,data[:CHUNK]);r=client('phone').publish_file('first',c,source)
        self.assertEqual(r['lease']['output_sha256'],hashlib.sha256(data).hexdigest())
        b=self.claim('gpu','second');dest=self.root/'incoming';dest.mkdir(mode=0o700)
        part=dest/('first.'+b['inputs']['first']['sha256']+'.part');part.write_bytes(data[:333]);part.chmod(0o600)
        saved=client('gpu').fetch_input('second',self.cred(b),'first',b['inputs']['first'],dest)
        self.assertEqual(saved.read_bytes(),data);self.assertFalse(list(dest.glob('*.part')))
    def test_expiry_restart_and_concurrency(self):
        from concurrent.futures import ThreadPoolExecutor
        from unittest.mock import patch
        c=self.cred(self.claim());self.put(c,b'data')
        with patch('atlas.dispatch.time.time',return_value=time.time()+60):
            with self.assertRaises(DispatchError):self.put(c,b'invalid',4)
            new=self.cred(self.call('phone','claim','first',envelope=self.envelope('phone'),retry=True));self.assertEqual(new['epoch'],2)
            def attempt(_):
                try:return self.put(new,b'same')['offset']
                except DispatchError:return None
            with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,range(2)))
            self.assertIn(4,results);self.assertTrue(all(x in (None,4) for x in results));self.assertEqual(self.put(new,b'same')['offset'],4)
        # Restart the coordinator on the same DB/staging, preserving retry state.
        q=Coordinator(self.root/'leases.db',self.plan,self.tasks,self.nodes,self.catalog,self.cas,self.root/'staging',self.policy,self.root/'replay.db',{},ttl=30)
        self.server.coordinator=q
        self.assertEqual(self.call('phone','offset','first',**new)['offset'],4)
        self.finish(new,b'same')
    def test_two_automatic_workers(self):
        from atlas.dispatch_worker import run_task
        from atlas.dispatch import DispatchClient
        from atlas.runtime_gate import Telemetry
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        import json
        class Handler(BaseHTTPRequestHandler):
            def response(self,x):
                b=json.dumps(x).encode();self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
            def do_GET(self):self.response({'status':'ok'} if self.path=='/health' else {'data':[{'id':x} for x in ('q1','q2')]})
            def do_POST(self):
                x=json.loads(self.rfile.read(int(self.headers['Content-Length'])));self.server.prompts.append(x['messages'][0]['content']);self.server.on_prompt();time.sleep(2.3);
                try:self.response({'choices':[{'message':{'content':'answer '+x['model']}}]})
                except OSError:pass
            def log_message(self,*_):pass
        http=ThreadingHTTPServer(('127.0.0.1',0),Handler);http.prompts=[];http.on_prompt=lambda:None;t=threading.Thread(target=http.serve_forever,kwargs={'poll_interval':.02});t.start()
        def stop():http.shutdown();http.server_close();t.join(3)
        self.addCleanup(stop)
        renewals=[];original=self.coord.handle
        def traced(ident,req):
            if req['op']=='renew':renewals.append(ident)
            return original(ident,req)
        self.coord.handle=traced
        for task,node in [('first','phone'),('second','gpu')]:
            k=self.keys;client=DispatchClient('127.0.0.1',self.server.server_address[1],client_context(k/'ca.pem',k/(node+'.pem'),k/(node+'.key')),fingerprint(k/'server.pem'),self.plan['certificate_sha256'],timeout=5)
            work=self.root/node;work.mkdir(mode=0o700);sensor=work/'thermal';sensor.write_text('31000');mem=work/'meminfo';mem.write_text('MemAvailable: 1024000 kB\n')
            class Probe(Telemetry):
                def sample(self):return {**super().sample(),'disk_free_bytes':1000000}
            probe=Probe(sensor,work,meminfo=mem);n=next(x for x in self.nodes if x['id']==node);template={k:n[k] for k in ('id','capabilities','models','ram_headroom_mb')}
            args=(client,self.plan,self.tasks,self.nodes,self.catalog,node,task,{'node':node,'llama_endpoint':f'http://127.0.0.1:{http.server_port}'},work,probe,template,k/(node+'.sign'))
            if task=='first':
                from atlas.runtime_gate import GateError
                http.on_prompt=lambda:sensor.write_text('44000')
                with self.assertRaises(GateError):run_task(*args,timeout=10)
                status=self.call(node,'status',task)['lease'];self.assertEqual(status['state'],'FAILED');self.assertEqual(status['last_error'],'RUNTIME_GUARD')
                self.assertFalse(list(self.cas.objects.iterdir()));self.assertFalse(list(work.glob('remote-stage-*')))
                sensor.write_text('31000');http.on_prompt=lambda:None
            result=run_task(*args,timeout=15,retry=task=='first')
            self.assertEqual(result['state'],'COMPLETED')
        self.assertEqual(http.prompts,['hello','hello','answer q1']);self.assertIn('phone',renewals);self.assertIn('gpu',renewals)
