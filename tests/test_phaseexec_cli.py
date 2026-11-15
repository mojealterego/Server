"""CLI proof: a real subprocess writes output, CAS stores content, SQLite records success."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CMD=[sys.executable,str(ROOT/'tools/phaseexec.py')]

class PhaseExecCLITests(unittest.TestCase):
    def test_cli_runs_real_command_and_persists_to_cas(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            tasks=[{'id':'render','engine':'llama','models':['m'],'ram_mb':100,'duration_slots':1,'output_bytes':1024,'privacy':'local_only'}]
            nodes=[{'id':'phone','trust':'local','capabilities':['llama'],'models':['m'],'ram_available_mb':1000,'ram_headroom_mb':100,
                    'disk_free_bytes':10240,'thermal_c':30,'priority':0}]
            catalog={'m':{'bytes':10,'format':'gguf','role':'llm','lineage_verified':True}}
            from atlas.phaseshift import compile_workflow
            for name, data in [('tasks',tasks),('nodes',nodes),('catalog',catalog),('plan',compile_workflow(tasks,nodes,catalog))]:
                (p/f'{name}.json').write_text(json.dumps(data),encoding='utf-8')
            code="import sys;from pathlib import Path;Path(sys.argv[1]).write_bytes(b'real execution')"
            command=[*CMD, '--tasks',str(p/'tasks.json'),'--nodes',str(p/'nodes.json'),
                '--catalog',str(p/'catalog.json'),'--plan',str(p/'plan.json'),
                '--db',str(p/'leases.db'),'--cas',str(p/'cas'),'--work',str(p/'work'),
                '--task','render','--node','phone','--timeout','10','--',
                sys.executable,'-c',code,'{output}']
            cp=subprocess.run(command,capture_output=True,text=True,timeout=15)
            self.assertEqual(cp.returncode,0,cp.stderr)
            outcome=json.loads(cp.stdout)
            self.assertEqual(outcome['status'],'COMPLETED')
            digest=hashlib.sha256(b'real execution').hexdigest()
            self.assertEqual(outcome['sha256'],digest)
            self.assertEqual((p/'cas'/'objects'/digest).read_bytes(),b'real execution')
            cp=subprocess.run(command,capture_output=True,text=True,timeout=15)
            self.assertNotEqual(cp.returncode,0)
            self.assertIn('already completed',cp.stderr)

if __name__=='__main__':unittest.main()
