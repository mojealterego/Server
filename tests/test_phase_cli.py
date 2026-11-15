"""CLI smoke test: compile -> verify -> claim -> complete -> dependent claim."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CMD=[sys.executable,str(ROOT/'tools/phasectl.py')]

class PhaseCLITests(unittest.TestCase):
    def test_end_to_end_local_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            tasks=[{'id':'first','engine':'llama','models':['q'],'ram_mb':100,'duration_slots':1,'privacy':'local_only','output_bytes':100},
                   {'id':'second','engine':'llama','models':['q'],'ram_mb':100,'duration_slots':1,'output_bytes':100,'depends_on':['first']}]
            nodes=[{'id':'phone','trust':'local','capabilities':['llama'],'models':['q'],
                    'ram_available_mb':2000,'ram_headroom_mb':100,'disk_free_bytes':1000,'thermal_c':32}]
            cat={'q':{'bytes':10,'format':'gguf','role':'llm','lineage_verified':True}}
            for name, obj in [('tasks',tasks),('nodes',nodes),('catalog',cat)]:
                (p/(name+'.json')).write_text(json.dumps(obj))
            def call(*args):
                cp=subprocess.run([*CMD,*args,'--tasks',str(p/'tasks.json'),'--nodes',str(p/'nodes.json'),
                                   '--catalog',str(p/'catalog.json')],capture_output=True,text=True,timeout=15)
                self.assertEqual(cp.returncode,0,cp.stderr)
                return json.loads(cp.stdout)
            plan=p/'plan.json';db=p/'lease.db';token=p/'token.json';out=p/'out.bin'
            call('compile','--out',str(plan),'--horizon','4')
            self.assertTrue(call('verify','--plan',str(plan))['valid'])
            claim=call('claim','--plan',str(plan),'--db',str(db),'--task','first',
                       '--node','phone','--token-file',str(token))
            self.assertEqual(claim['state'],'LEASED')
            self.assertNotIn('token',claim)
            self.assertEqual(token.stat().st_mode & 0o077,0)
            out.write_bytes(b'real artifact')
            receipt=call('complete','--plan',str(plan),'--db',str(db),'--task','first',
                         '--node','phone','--token-file',str(token),'--output',str(out))
            self.assertEqual(receipt['state'],'COMPLETED')
            self.assertEqual(call('status','--plan',str(plan),'--db',str(db),'--task','first')['state'],'COMPLETED')
            self.assertEqual(call('claim','--plan',str(plan),'--db',str(db),'--task','second',
                                  '--node','phone','--token-file',str(p/'token2.json'))['state'],'LEASED')

if __name__=='__main__':unittest.main()
