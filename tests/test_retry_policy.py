import tempfile,unittest,time
from pathlib import Path
from atlas.phaselease import LeaseStore,LeaseError
from atlas.phaseshift import compile_workflow
from atlas.failover import prepare_restart

class RetryPolicyTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.db=Path(t.name)/'db'
        self.catalog={'q':{'format':'gguf','bytes':1,'family':'qwen','role':'llm'}}
        self.tasks=[{'id':'a','engine':'llama','models':['q'],'ram_mb':10,'output_bytes':20,'privacy':'trusted_only','recipe':{'kind':'qwen_text','prompt':'hi','runtime_model':'q'},'runtime_model_ids':{'q':'q'}}]
        self.nodes=[{'id':n,'trust':'trusted','priority':i,'ram_available_mb':100,'ram_headroom_mb':10,'disk_free_bytes':1000,'thermal_c':30,'capabilities':['llama'],'models':['q']} for i,n in enumerate(('phone','gpu'))]
        self.plan=compile_workflow(self.tasks,self.nodes,self.catalog)
    def lease(self):return LeaseStore(self.db,self.plan,self.tasks,self.nodes,self.catalog)
    def test_no_bypass_and_persistent_policy(self):
        with self.lease() as l:
            l.configure_attempt_limit(1);c=l.claim('a','phone');l.fail('a','phone',c['token'],c['epoch'],'PROCESS_FAILED')
        with self.lease() as l:
            l.configure_attempt_limit(1)
            with self.assertRaises(LeaseError):l.configure_attempt_limit(2)
            with self.assertRaises(LeaseError):l.claim('a','phone')
    def test_inherit_budget_across_failover(self):
        with self.lease() as l:
            l.configure_attempt_limit(2);c=l.claim('a','phone',now=time.time()-10,ttl=1)
            result=prepare_restart(l,'phone',[self.nodes[1]],require_expired=True)
        with LeaseStore(self.db,result['plan'],self.tasks,result['nodes'],self.catalog) as l:
            l.configure_attempt_limit(2);c=l.claim('a','gpu');l.fail('a','gpu',c['token'],c['epoch'],'PROCESS_FAILED')
            with self.assertRaises(LeaseError):l.claim('a','gpu')
    def test_expired_trigger_requires_evidence(self):
        with self.lease() as l:
            with self.assertRaises(ValueError):prepare_restart(l,'phone',[self.nodes[1]],require_expired=True)
            c=l.claim('a','phone',now=time.time()-10,ttl=1)
            self.assertEqual(prepare_restart(l,'phone',[self.nodes[1]],require_expired=True)['failed_node'],'phone')
    def test_illegal_limit(self):
        with self.lease() as l:
            for x in (0,True,11,None):
                with self.assertRaises(LeaseError):l.configure_attempt_limit(x)
    def test_policy_cannot_ignore_prior_attempts(self):
        with self.lease() as l:
            c=l.claim('a','phone');l.fail('a','phone',c['token'],c['epoch'],'PROCESS_FAILED');l.configure_attempt_limit(1)
            with self.assertRaises(LeaseError):l.claim('a','phone')
    def test_exhausted_budget_blocks_cutover(self):
        with self.lease() as l:
            l.configure_attempt_limit(1);l.claim('a','phone',now=time.time()-10,ttl=1)
            with self.assertRaisesRegex(ValueError,'budget exhausted'):prepare_restart(l,'phone',[self.nodes[1]],require_expired=True)
    def test_watch_candidate_and_timeout_without_cutover(self):
        from atlas.failover import watch_restart
        with self.lease() as l:
            now=[0]
            def sleep(n):now[0]+=n
            r=watch_restart(l,'phone',timeout=1,clock=lambda:now[0],sleep=sleep)
            self.assertEqual(r['status'],'TIMEOUT');self.assertEqual(now[0],1)
            l.claim('a','phone',now=time.time()-10,ttl=1)
            r=watch_restart(l,'phone');self.assertEqual(r['status'],'CANDIDATE');self.assertEqual(r['expired_on_failed'],1)
            self.assertIsNone(l.conn.execute('SELECT 1 FROM retired_plans').fetchone())
