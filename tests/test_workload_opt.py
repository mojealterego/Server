import copy
import unittest
from atlas.phaseshift import compile_workflow, digest
from atlas.phaseverify import verify_workflow
from atlas.workload_opt import optimize, OptimizationError

NOW=1800000000


def node(name,trust='trusted',priority=100):
    return dict(id=name,trust=trust,priority=priority,ram_available_mb=2048,ram_headroom_mb=256,
                disk_free_bytes=10000,thermal_c=30,capabilities=['llama'],models=['m'])


class WorkloadTests(unittest.TestCase):
    def setUp(self):
        self.nodes=[node('slow','local',0),node('fast',priority=100)]
        self.tasks=[dict(id='task',engine='llama',models=['m'],ram_mb=512,privacy='trusted_only',output_bytes=10)]
        self.catalog={'m':{'bytes':10,'format':'gguf','role':'text'}}
        self.baseline=compile_workflow(self.tasks,self.nodes,self.catalog,require_n_minus_one=True)
        self.profile={'schema':'omega.workload.profile.v1','input_sha256':self.baseline['input_sha256'],
                      'records':[dict(task='task',node='slow',observed_at=NOW,samples_ms=[100]*10),
                                 dict(task='task',node='fast',observed_at=NOW,samples_ms=[30]*10)]}

    def run_opt(self, **kw):
        return optimize(self.baseline,self.tasks,self.nodes,self.catalog,self.profile,digest(self.profile),NOW,**kw)

    def test_better_candidate_is_certified_against_original_inputs(self):
        before=copy.deepcopy((self.baseline,self.nodes,self.tasks,self.profile))
        r=self.run_opt();self.assertEqual(r['status'],'PROPOSED');self.assertEqual(r['candidate_score_ms'],30)
        self.assertEqual(r['baseline_score_ms'],100);self.assertEqual(r['plan']['primary']['assignments'][0]['node'],'fast')
        self.assertTrue(verify_workflow(r['plan'],self.tasks,self.nodes,self.catalog)['primary_feasible'])
        self.assertEqual(r['plan']['input_sha256'],self.baseline['input_sha256'])
        self.assertEqual((self.baseline,self.nodes,self.tasks,self.profile),before)

    def test_threshold_and_no_improvement_keep_baseline(self):
        self.assertEqual(self.run_opt(min_improvement_bps=8000)['status'],'UNCHANGED')
        self.profile['records'][1]['samples_ms']=[110]*10
        self.assertEqual(self.run_opt()['plan'],self.baseline)

    def test_incomplete_candidate_profile_does_not_replace_baseline(self):
        self.profile['records'].pop()
        self.assertEqual(self.run_opt()['status'],'UNCHANGED')

    def test_stale_baseline_profile_fails_closed(self):
        self.profile['records'][0]['observed_at']=NOW-3601
        with self.assertRaises(OptimizationError):self.run_opt()

    def test_model_and_input_binding(self):
        self.profile['input_sha256']='0'*64
        with self.assertRaises(OptimizationError):self.run_opt()
        self.profile['input_sha256']=self.baseline['input_sha256']
        with self.assertRaises(OptimizationError):optimize(self.baseline,self.tasks,self.nodes,self.catalog,self.profile,'0'*64,NOW)

    def test_private_task_never_migrates(self):
        self.tasks[0]['privacy']='local_only'
        self.baseline=compile_workflow(self.tasks,self.nodes,self.catalog)
        self.profile['input_sha256']=self.baseline['input_sha256']
        self.assertEqual(self.run_opt()['plan']['primary']['assignments'][0]['node'],'slow')

    def test_duplicate_and_too_few_samples_rejected(self):
        self.profile['records'].append(dict(self.profile['records'][0]))
        with self.assertRaises(OptimizationError):self.run_opt()
        self.profile['records'].pop();self.profile['records'][0]['samples_ms']=[100]
        with self.assertRaises(OptimizationError):self.run_opt()

    def test_determinism_and_budget_and_coverage(self):
        a=self.run_opt();b=self.run_opt();self.assertEqual(a,b)
        self.assertEqual(set(verify_workflow(a['plan'],self.tasks,self.nodes,self.catalog)['verified_failure_scenarios']),{'slow','fast'})
        with self.assertRaises(OptimizationError):self.run_opt(candidate_limit=9)

    def test_nearest_rank_tail_penalty(self):
        self.profile['records'][1]['samples_ms']=[1]*9+[200]
        self.assertEqual(self.run_opt()['status'],'UNCHANGED')
