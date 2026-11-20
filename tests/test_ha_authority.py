import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from atlas.ha_authority import authority, AuthorityBusy

class AuthorityTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.db=self.root/'leases.db'
    def test_exclusive_and_release(self):
        with authority(self.db):
            with self.assertRaises(AuthorityBusy):
                with authority(self.db):pass
        with authority(self.db):pass
    def test_symlink_and_hardlink_rejected(self):
        p=self.root/'target';p.touch(mode=0o600);self.db.symlink_to(p)
        with self.assertRaises(ValueError):
            with authority(self.db):pass
        self.db.unlink();os.link(p,self.db)
        with self.assertRaises(ValueError):
            with authority(self.db):pass
    def test_process_death_allows_standby(self):
        program='import sys,time;from pathlib import Path;from atlas.ha_authority import authority\nwith authority(Path(sys.argv[1]),wait=float(sys.argv[2])):\n print("READY",flush=True);time.sleep(60)'
        def start(wait):return subprocess.Popen([sys.executable,'-c',program,str(self.db),str(wait)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def stop(p):
            if p.poll() is None:p.kill()
            p.wait(timeout=5);p.stdout.close();p.stderr.close()
        import select
        leader=start(0);self.addCleanup(stop,leader);self.assertTrue(select.select([leader.stdout],[],[],5)[0]);self.assertEqual(leader.stdout.readline().strip(),'READY')
        standby=start(5);self.addCleanup(stop,standby);self.assertFalse(select.select([standby.stdout],[],[],.2)[0]);leader.kill();leader.wait(timeout=5)
        self.assertTrue(select.select([standby.stdout],[],[],5)[0]);self.assertEqual(standby.stdout.readline().strip(),'READY')
