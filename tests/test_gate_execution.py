"""Real subprocess guard integration; lease/CAS boundaries use controlled doubles."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from atlas.execution import SupervisedExecutor, ExecutionError
from atlas.runtime_gate import RuntimeGate, Telemetry

class GuardedExecutionTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.cas=Mock();self.cas.root=self.root/'cas'
        self.lease=Mock();self.lease.artifacts=self.cas
        self.lease.path=self.root/'jobs.sqlite';self.lease.path.touch(mode=0o600)
        self.lease.claim.return_value={'epoch':1,'token':'token'}
        self.lease.complete.return_value={'output_sha256':'digest'}
        self.work=self.root/'work';self.executor=SupervisedExecutor(self.lease,self.cas,self.work)
        self.executor._heartbeat=lambda *args:None
        self.temp=self.root/'temp';self.temp.write_text('38000')
        self.mem=self.root/'mem';self.mem.write_text('MemAvailable: 4194304 kB')
        node={'id':'phone','ram_headroom_mb':128,'ram_available_mb':3000,'thermal_c':38,'disk_free_bytes':10000,'capabilities':['llama'],'models':['m']}
        task={'id':'job','engine':'llama','models':['m'],'ram_mb':64,'output_bytes':1}
        import time
        self.gate=RuntimeGate(Telemetry(self.temp,self.root,meminfo=self.mem),node,task,deadline=time.monotonic()+20)
    def run_job(self,code):
        return self.executor.run('job','phone',[sys.executable,'-c',code,'{output}'],runtime_gate=self.gate,ttl=10,timeout_seconds=8)
    def test_denied_before_claim(self):
        self.temp.write_text('43000')
        with self.assertRaisesRegex(ExecutionError,'RUNTIME_GUARD'): self.run_job('raise AssertionError()')
        self.lease.claim.assert_not_called();self.lease.complete.assert_not_called()
    def test_guard_stops_running_child(self):
        code=f'from pathlib import Path;import time;Path({str(self.temp)!r}).write_text("44000");time.sleep(20)'
        with self.assertRaisesRegex(ExecutionError,'RUNTIME_GUARD'): self.run_job(code)
        self.lease.fail.assert_called_once_with('job','phone','token',1,'RUNTIME_GUARD')
        self.lease.complete.assert_not_called()
    def test_guard_rechecks_before_publish(self):
        code=f'from pathlib import Path;import sys;Path(sys.argv[1]).write_bytes(b"ok");Path({str(self.temp)!r}).write_text("44000")'
        with self.assertRaisesRegex(ExecutionError,'RUNTIME_GUARD'):self.run_job(code)
        self.lease.complete.assert_not_called()
    def test_healthy_process_publishes(self):
        result=self.run_job('from pathlib import Path;import sys;Path(sys.argv[1]).write_bytes(b"ok")')
        self.assertEqual(result['status'],'COMPLETED');self.lease.complete.assert_called_once()
