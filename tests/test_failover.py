import tempfile,time,unittest
from pathlib import Path
from atlas.phaselease import LeaseStore,LeaseError
from atlas.phaseshift import compile_workflow
from atlas.phaseverify import verify_workflow
from atlas.failover import prepare_restart, recover_restart, FailoverError

class FailoverTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.db=self.root/'leases'
        self.catalog={'q':{'format':'gguf','bytes':1,'family':'qwen','role':'llm'}}
        self.tasks=[{'id':'a','engine':'llama','models':['q'],'ram_mb':10,'output_bytes':20,'privacy':'trusted_only','recipe':{'kind':'qwen_text','prompt':'hi','runtime_model':'q'},'runtime_model_ids':{'q':'q'}}]
        self.nodes=[{'id':n,'trust':'trusted','priority':i,'ram_available_mb':100,'ram_headroom_mb':10,'disk_free_bytes':1000,'thermal_c':30,'capabilities':['llama'],'models':['q']} for i,n in enumerate(('phone','gpu'))]
        self.plan=compile_workflow(self.tasks,self.nodes,self.catalog)
    def lease(self):return LeaseStore(self.db,self.plan,self.tasks,self.nodes,self.catalog)
    def cut(self,lease,**kw):return prepare_restart(lease,'phone',[self.nodes[1]],**kw)
    def test_restart_and_old_plan_fenced(self):
        with self.lease() as old:
            result=self.cut(old);self.assertEqual(result['plan']['primary']['assignments'][0]['node'],'gpu');self.assertTrue(verify_workflow(result['plan'],self.tasks,result['nodes'],self.catalog)['valid'])
            with self.assertRaises(LeaseError):old.claim('a','phone')
            self.assertEqual(recover_restart(old),result)
        with LeaseStore(self.db,result['plan'],self.tasks,result['nodes'],self.catalog) as new:
            self.assertEqual(new.claim('a','gpu')['epoch'],1)
        with self.lease() as old:
            with self.assertRaises(LeaseError):old.claim('a','phone')
    def test_live_lease_blocks_cutover(self):
        with self.lease() as old:
            c=old.claim('a','phone')
            with self.assertRaises(FailoverError):self.cut(old)
            old.fail('a','phone',c['token'],c['epoch'],'PROCESS_FAILED');self.cut(old)
            with self.assertRaises(LeaseError):old.renew('a','phone',c['token'],c['epoch'])
    def test_completed_requires_explicit_authorization(self):
        p=self.root/'out';p.write_bytes(b'ok')
        with self.lease() as old:
            c=old.claim('a','phone');old.complete('a','phone',c['token'],c['epoch'],p)
            with self.assertRaises(FailoverError):self.cut(old)
            self.cut(old,restart_completed=True)
    def test_insufficient_live_resources_no_retirement(self):
        with self.lease() as old:
            with self.assertRaises(FailoverError):prepare_restart(old,'phone',[{**self.nodes[1],'ram_available_mb':11}])
            self.assertEqual(old.claim('a','phone')['node'],'phone')
    def test_reject_private_workflow(self):
        self.tasks[0]['privacy']='local_only'
        self.nodes[0]['trust']='local';self.nodes[1]['trust']='local';self.plan=compile_workflow(self.tasks,self.nodes,self.catalog)
        with self.lease() as old:
            with self.assertRaises(FailoverError):self.cut(old)
    def test_expired_owner_fenced(self):
        with self.lease() as old:
            c=old.claim('a','phone',now=time.time()-10,ttl=1);self.cut(old)
            p=self.root/'out';p.write_bytes(b'ok')
            with self.assertRaises(LeaseError):old.complete('a','phone',c['token'],c['epoch'],p)
    def test_reject_unknown_or_changed_trust(self):
        with self.lease() as old:
            for live in ([{**self.nodes[1],'id':'rogue'}],[{**self.nodes[1],'trust':'local'}],[self.nodes[0]]):
                with self.assertRaises(FailoverError):prepare_restart(old,'phone',live)
    def test_concurrent_cutover_has_one_successor(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        barrier=Barrier(2)
        def attempt(_):
            with self.lease() as lease:
                barrier.wait(timeout=5)
                try:return self.cut(lease)['plan']['certificate_sha256']
                except LeaseError:return None
        with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(attempt,range(2)))
        self.assertEqual(sum(x is not None for x in results),1)
        with self.lease() as old:self.assertIn(recover_restart(old)['plan']['certificate_sha256'],results)
    def test_cli_signed_declaration_and_recovery(self):
        import json,subprocess,sys
        from tools.capctl import sign
        key=self.root/'key';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        node=self.nodes[1];env=sign({k:v for k,v in node.items() if k not in ('trust','priority')},key)
        policy={'gpu':{'public_key':env['public_key'],'trust':'trusted','priority':1,'max_ram_mb':100,'min_headroom_mb':10,'max_disk_bytes':1000,'capabilities':['llama'],'models':['q']}}
        args=[]
        for name,value in [('plan',self.plan),('tasks',self.tasks),('nodes',self.nodes),('catalog',self.catalog),('envelope',env),('policy',policy)]:
            p=self.root/(name+'.json');p.write_text(json.dumps(value));args.extend(['--'+name,str(p)])
        cmd=[sys.executable,'-m','atlas.failover'];common=['--db',str(self.db),*args[:8]]
        r=subprocess.run(cmd+['prepare',*common,*args[8:],'--replay',str(self.root/'replay'),'--failed-node','phone','--confirm-quiesced'],capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr);result=json.loads(r.stdout)
        r=subprocess.run(cmd+['recover',*common],capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout),result)
