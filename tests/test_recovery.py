import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from atlas.recovery import NodeLock, RecoveryBusy, spawn_guarded, node_status

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.db=self.root/'jobs.sqlite';self.db.touch(mode=0o600)
    def wait_for(self, predicate):
        end=time.monotonic()+5
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.04)
        self.fail('deadline exceeded')
    def test_exclusive_and_distinct_nodes(self):
        with NodeLock(self.db,'phone'):
            self.assertEqual(node_status(self.db,'phone'),'BUSY')
            with self.assertRaises(RecoveryBusy):
                with NodeLock(self.db,'phone'):pass
            with NodeLock(self.db,'gpu'):pass
        self.assertEqual(node_status(self.db,'phone'),'IDLE')
    def test_lock_released_on_exception(self):
        with self.assertRaises(RuntimeError):
            with NodeLock(self.db,'phone'):raise RuntimeError('oops')
        self.assertEqual(node_status(self.db,'phone'),'IDLE')
    def test_guard_maintains_lock_until_child_exits(self):
        with NodeLock(self.db,'phone') as lock:
            proc,control=spawn_guarded(lock,[sys.executable,'-c','import time;time.sleep(.4)'],self.root,os.environ.copy())
        try:
            self.assertEqual(node_status(self.db,'phone'),'BUSY')
            self.assertEqual(proc.wait(timeout=5),0)
        finally:
            os.close(control);proc.stdout.close()
        self.assertEqual(node_status(self.db,'phone'),'IDLE')
    def test_supervisor_sigkill_stops_child_and_allows_retry(self):
        marker=self.root/'pid';done=self.root/'late'
        code=("import os,time;from pathlib import Path;"
              f"Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(2);Path({str(done)!r}).touch()")
        supervisor= subprocess.Popen([sys.executable,'-c',
            'import os,sys,time;from pathlib import Path;from atlas.recovery import NodeLock,spawn_guarded;'
            'lock=NodeLock(Path(sys.argv[1]),"phone");lock.__enter__();'
            'p,fd=spawn_guarded(lock,[sys.executable,"-c",sys.argv[2]],Path(sys.argv[1]).parent,os.environ.copy());time.sleep(60)',
            str(self.db),code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.wait_for(marker.exists)
            self.assertEqual(node_status(self.db,'phone'),'BUSY')
            supervisor.kill();supervisor.wait(timeout=5)
            self.wait_for(lambda:node_status(self.db,'phone')=='IDLE')
            time.sleep(2.1)
            self.assertFalse(done.exists())
        finally:
            if supervisor.poll() is None:supervisor.kill();supervisor.wait(timeout=5)
    def test_guardian_death_retains_lock_in_foreground_child(self):
        marker=self.root/'running'; release=self.root/'release'
        code=("import time;from pathlib import Path;"
              f"Path({str(marker)!r}).touch();"
              f"exec({('while not Path('+repr(str(release))+').exists(): time.sleep(.04)')!r})")
        with NodeLock(self.db,'phone') as lock:
            proc,fd=spawn_guarded(lock,[sys.executable,'-c',code],self.root,os.environ.copy())
        try:
            self.wait_for(marker.exists)
            proc.kill();proc.wait(timeout=5)
            self.assertEqual(node_status(self.db,'phone'),'BUSY')
        finally:
            release.touch();os.close(fd);proc.stdout.close()
            if proc.poll() is None:proc.kill();proc.wait(timeout=5)
        self.wait_for(lambda:node_status(self.db,'phone')=='IDLE')

    def test_guard_preserves_exit_code(self):
        with NodeLock(self.db,'phone') as lock:
            proc,fd=spawn_guarded(lock,[sys.executable,'-c','raise SystemExit(17)'],self.root,os.environ.copy())
            try:self.assertEqual(proc.wait(timeout=5),17)
            finally:os.close(fd);proc.stdout.close()
    def test_symlink_lock_rejected(self):
        with NodeLock(self.db,'phone') as lock:path=lock.path
        path.unlink();path.symlink_to(self.db)
        with self.assertRaises(OSError):
            with NodeLock(self.db,'phone'):pass


class ExecutorRecoveryTests(unittest.TestCase):
    def test_busy_node_blocks_before_claim(self):
        from unittest.mock import Mock
        from atlas.execution import SupervisedExecutor, ExecutionError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); db=root/'leases.db'; db.touch(mode=0o600)
            cas=Mock(); cas.root=root/'cas'
            lease=Mock(); lease.path=db; lease.artifacts=cas
            executor=SupervisedExecutor(lease,cas,root/'work')
            with NodeLock(db,'phone'):
                with self.assertRaisesRegex(ExecutionError,'RECOVERY_BUSY'):
                    executor.run('job','phone',[sys.executable,'-c','{output}'])
            lease.claim.assert_not_called()
