import unittest
from atlas.scheduler import schedule_node
from atlas.dispatch import DispatchError

class FakeClock:
    def __init__(self):self.now=0;self.sleeps=[]
    def clock(self):return self.now
    def sleep(self,n):self.sleeps.append(n);self.now+=n

class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.time=FakeClock();self.calls=[];self.assignments=[{'id':'b','node':'phone','effective_privacy':'trusted_only','start_slot':2,'end_slot':3},{'id':'a','node':'phone','effective_privacy':'trusted_only','start_slot':0,'end_slot':2},{'id':'private','node':'phone','effective_privacy':'local_only','start_slot':0,'end_slot':1},{'id':'remote','node':'gpu','effective_privacy':'trusted_only','start_slot':0,'end_slot':1}]
        self.states={key:self.row(key) for key in ('a','b')}
    @staticmethod
    def row(tid,state='PENDING',epoch=0,ready=True,retryable=False):
        return {'lease':{'task':tid,'state':state,'epoch':epoch,**({'node':'phone'} if epoch else {})},'readiness':{'dependencies_complete':ready,'retryable':retryable}}
    def status(self,tid):return self.states[tid]
    def execute(self,tid,*,retry,max_epoch):
        self.calls.append((tid,retry,max_epoch));self.states[tid]=self.row(tid,'COMPLETED',self.states[tid]['lease']['epoch']+1)
    def run_scheduler(self,**kw):
        args=dict(poll_interval=1,idle_timeout=10,clock=self.time.clock,sleep=self.time.sleep);args.update(kw)
        return schedule_node('phone',self.assignments,self.status,self.execute,**args)
    def test_priority_and_privacy(self):
        r=self.run_scheduler();self.assertEqual(r['status'],'COMPLETED');self.assertEqual(self.calls,[('a',False,1),('b',False,1)])
    def test_wait_for_remote_dependency(self):
        self.states['a']=self.row('a',ready=False);self.states['b']=self.row('b','COMPLETED',1)
        def wait(n):self.time.sleep(n);self.states['a']=self.row('a',ready=True)
        self.assertEqual(self.run_scheduler(sleep=wait)['status'],'COMPLETED');self.assertEqual(self.calls,[('a',False,1)]);self.assertTrue(self.time.sleeps)
    def test_no_implicit_retry(self):
        self.states['a']=self.row('a','FAILED',1,retryable=True);self.states['b']=self.row('b','COMPLETED',1)
        r=self.run_scheduler();self.assertEqual(r['status'],'BLOCKED');self.assertFalse(self.calls)
    def test_explicit_retry_and_epoch_cap(self):
        self.states['a']=self.row('a','LEASED',1,retryable=True);self.states['b']=self.row('b','FAILED',3,retryable=True)
        r=self.run_scheduler(retry_failed=True,max_attempts=3);self.assertEqual(r['status'],'BLOCKED');self.assertEqual(self.calls,[('a',True,3)])
    def test_preclaim_error_backpressure(self):
        self.states['b']=self.row('b','COMPLETED',1)
        def fail(tid,**kw):self.calls.append(tid);raise DispatchError('no claim')
        self.execute=fail;r=self.run_scheduler();self.assertEqual(r['status'],'BLOCKED');self.assertEqual(len(self.calls),3);self.assertGreaterEqual(sum(self.time.sleeps),3)
    def test_rpc_backoff(self):
        def unavailable(tid):raise DispatchError('unavailable')
        self.status=unavailable;r=self.run_scheduler(max_rpc_errors=3);self.assertEqual(r['reason'],'RPC_UNAVAILABLE');self.assertEqual(self.time.sleeps,[1,2])
    def test_pending_dependency_has_idle_limit(self):
        self.states={key:self.row(key,ready=False) for key in ('a','b')}
        r=self.run_scheduler(idle_timeout=3);self.assertEqual(r['reason'],'IDLE_TIMEOUT');self.assertEqual(self.time.now,3);self.assertFalse(self.calls)
    def test_live_lease_never_retried(self):
        self.states['a']=self.row('a','LEASED',1,retryable=False);self.states['b']=self.row('b','COMPLETED',1)
        r=self.run_scheduler(retry_failed=True,max_attempts=3,idle_timeout=2);self.assertEqual(r['reason'],'IDLE_TIMEOUT');self.assertFalse(self.calls)
    def test_malformed_readiness_fail_closed(self):
        self.states['a']['readiness']['dependencies_complete']='true'
        r=self.run_scheduler(max_rpc_errors=1);self.assertEqual(r['reason'],'RPC_UNAVAILABLE');self.assertFalse(self.calls)
    def test_lost_completion_response_reconciles(self):
        orig=self.execute
        def lost(tid,**kw):orig(tid,**kw);raise DispatchError('reply lost')
        self.execute=lost;self.assertEqual(self.run_scheduler()['status'],'COMPLETED');self.assertEqual(len(self.calls),2)
    def test_retry_requires_opt_in(self):
        with self.assertRaises(ValueError):self.run_scheduler(max_attempts=3)

    def test_administrator_budget_blocks_without_polling(self):
        self.states['a']=self.row('a','FAILED',1,retryable=True)
        self.states['a']['readiness']['remaining_attempts']=0
        self.states['b']=self.row('b','COMPLETED',1)
        self.assertEqual(self.run_scheduler(retry_failed=True,max_attempts=3)['reason'],'RETRY_BUDGET_OR_POLICY')
        self.assertFalse(self.calls);self.assertFalse(self.time.sleeps)

if __name__=='__main__':unittest.main()
