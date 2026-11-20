import unittest
from atlas.scheduler import schedule_node
from atlas.dispatch import DispatchError

class AdaptiveSchedulerTests(unittest.TestCase):
    def run_poll(self, *, maximum=None, ready_at=None, idle=20, error=False):
        now=0; sleeps=[]; calls=[]; executions=[]; complete=False
        assignments=[{'id':'a','node':'phone','effective_privacy':'trusted_only','start_slot':0,'end_slot':1}]
        def status(tid):
            calls.append(now)
            if error:raise DispatchError('unavailable')
            return {'lease':{'task':tid,'state':'COMPLETED' if complete else 'PENDING','epoch':int(complete), 'node':'phone'},'readiness':{'dependencies_complete':ready_at is not None and now>=ready_at,'retryable':False}}
        def sleep(n):
            nonlocal now
            sleeps.append(n);now+=n
        def execute(tid,**kwargs):
            nonlocal complete
            executions.append((tid,now,kwargs));complete=True
        options={} if maximum is None else {'max_poll_interval':maximum}
        report=schedule_node('phone',assignments,status,execute,poll_interval=1,idle_timeout=idle,clock=lambda:now,sleep=sleep,**options)
        return report,sleeps,calls,executions
    def test_fixed_default_unchanged(self):
        r,s,c,e=self.run_poll(idle=5)
        self.assertEqual(s,[1]*5);self.assertEqual(r['reason'],'IDLE_TIMEOUT')
    def test_adaptive_idle_backoff_is_bounded(self):
        r,s,c,e=self.run_poll(maximum=8,idle=20)
        self.assertEqual(s,[1,2,4,8,5]);self.assertEqual(r['reason'],'IDLE_TIMEOUT');self.assertEqual(c[-1],20)
    def test_readiness_triggers_immediate_execution(self):
        r,s,c,e=self.run_poll(maximum=8,ready_at=6)
        self.assertEqual(r['status'],'COMPLETED');self.assertEqual(e,[('a',7,{'retry':False,'max_epoch':1})])
    def test_invalid_caps_rejected(self):
        for value in (.5,31,True,float('nan'),float('inf'),'4'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.run_poll(maximum=value)
    def test_rpc_failure_budget_does_not_change(self):
        r,s,c,e=self.run_poll(maximum=8,error=True,idle=60)
        self.assertEqual(r['reason'],'RPC_UNAVAILABLE');self.assertEqual(s,[1,2,4,8]);self.assertFalse(e)
