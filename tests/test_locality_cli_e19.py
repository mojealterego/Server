import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from atlas.locality_advisor import digest
from tests.test_locality_e19 import PROFILE, TASKS, NODES, NOW

class LocalityCliTests(unittest.TestCase):
    def test_cli_readonly_and_bad_pin(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700)
            for name,doc in [('tasks',TASKS),('nodes',NODES),('profile',PROFILE)]:
                (root/(name+'.json')).write_text(json.dumps(doc))
            args=[sys.executable,'-m','atlas.locality_advisor','--tasks',str(root/'tasks.json'),
                  '--nodes',str(root/'nodes.json'),'--profile',str(root/'profile.json'),
                  '--now',str(NOW),'--profile-sha256',digest(PROFILE)]
            cwd=Path(__file__).resolve().parents[1]
            r=subprocess.run(args,cwd=cwd,text=True,capture_output=True,timeout=10)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(json.loads(r.stdout)['status'],'ADVISORY_ONLY')
            args[-1]='f'*64
            r=subprocess.run(args,cwd=cwd,text=True,capture_output=True,timeout=10)
            self.assertNotEqual(r.returncode,0)

if __name__=='__main__':unittest.main()
