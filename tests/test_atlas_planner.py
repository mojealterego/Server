"""ATLAS fail-closed resource and lineage planner tests."""
import unittest
from atlas.planner import plan, validate_catalog

CATALOG={
 'qwen':{'bytes':100,'format':'gguf','role':'vlm','lineage_verified':True},
 'proj':{'bytes':30,'format':'gguf','role':'projector','lineage_verified':False},
 'ltx':{'bytes':200,'format':'gguf','role':'video_dit','lineage_verified':True},
}
NODES=[
 {'id':'phone','trust':'local','ram_available_mb':5000,'ram_headroom_mb':1024,'disk_free_bytes':2000,'thermal_c':37,'capabilities':['llama'],'models':['qwen','proj'],'priority':0},
 {'id':'gpu','trust':'trusted','ram_available_mb':50000,'ram_headroom_mb':4096,'disk_free_bytes':10000,'thermal_c':30,'capabilities':['sd-cli','llama'],'models':['ltx'],'priority':5},
]

class PlannerTests(unittest.TestCase):
    def test_local_private_llm(self):
        tasks=[{'id':'a','engine':'llama','models':['qwen'],'ram_mb':1024,'privacy':'local_only'}]
        r=plan(tasks,NODES,CATALOG)
        self.assertEqual(r['stages'][0]['node'],'phone')
        self.assertEqual(r['stages'][0]['status'],'READY')
    def test_unknown_model_fails_closed(self):
        r=plan([{'id':'a','engine':'llama','models':['unknown'],'ram_mb':1024}],NODES,CATALOG)
        self.assertEqual(r['stages'][0]['status'],'BLOCKED')
        self.assertIn('UNKNOWN_MODEL',r['stages'][0]['reasons'])
    def test_unverified_projector_blocks_vision(self):
        r=plan([{'id':'a','engine':'llama','models':['qwen','proj'],'ram_mb':1024,'requires_verified_lineage':True}],NODES,CATALOG)
        self.assertEqual(r['stages'][0]['status'],'BLOCKED')
        self.assertIn('UNVERIFIED_LINEAGE:proj',r['stages'][0]['reasons'])
    def test_no_gpu_no_video(self):
        r=plan([{'id':'a','engine':'sd-cli','models':['ltx'],'ram_mb':8000}],NODES[:1],CATALOG)
        self.assertEqual(r['stages'][0]['status'],'BLOCKED')
    def test_private_never_offloaded(self):
        tasks=[{'id':'a','engine':'sd-cli','models':['ltx'],'ram_mb':8000,'privacy':'local_only'}]
        r=plan(tasks,NODES,CATALOG)
        self.assertEqual(r['stages'][0]['status'],'BLOCKED')
    def test_thermal_hard_stop(self):
        nodes=[dict(NODES[0],thermal_c=46)]
        r=plan([{'id':'a','engine':'llama','models':['qwen'],'ram_mb':1024}],nodes,CATALOG)
        self.assertEqual(r['stages'][0]['status'],'BLOCKED')
    def test_dependencies_block_downstream(self):
        tasks=[{'id':'a','engine':'sd-cli','models':['unknown'],'ram_mb':2000},
               {'id':'b','engine':'llama','models':['qwen'],'ram_mb':1024,'depends_on':['a']}]
        r=plan(tasks,NODES,CATALOG)
        self.assertEqual(r['stages'][1]['status'],'BLOCKED_DEPENDENCY')
    def test_dependency_cycle_rejected(self):
        tasks=[{'id':'a','engine':'llama','models':['qwen'],'ram_mb':1024,'depends_on':['b']},
               {'id':'b','engine':'llama','models':['qwen'],'ram_mb':1024,'depends_on':['a']}]
        with self.assertRaisesRegex(ValueError,'cycle'):plan(tasks,NODES,CATALOG)
    def test_unknown_privacy_rejected(self):
        with self.assertRaises(ValueError):plan([{'id':'a','engine':'llama','models':['qwen'],'ram_mb':1024,'privacy':'no_rules'}],NODES,CATALOG)
    def test_no_model_staging_assumptions(self):
        nodes=[dict(NODES[0],models=[])]
        r=plan([{'id':'a','engine':'llama','models':['qwen'],'ram_mb':1024}],nodes,CATALOG)
        self.assertEqual(r['stages'][0]['status'],'BLOCKED')
        self.assertIn('MODEL_NOT_STAGED:qwen',r['stages'][0]['reasons'])
    def test_catalog_rejects_unsafe_name(self):
        with self.assertRaises(ValueError):validate_catalog({'../escape':{'bytes':1,'format':'gguf','role':'vlm'}})

if __name__=='__main__':unittest.main()
