"""Seeded model-based tests of plans, including infeasible and adversarial inputs."""
import copy
import random
import unittest
from atlas.phaseshift import compile_workflow, digest
from atlas.phaseverify import verify_workflow

CAT={'q':{'bytes':42,'format':'gguf','role':'llm','lineage_verified':True}}

class Properties(unittest.TestCase):
    def test_two_hundred_seeded_schedules_all_certificates_check(self):
        rng=random.Random(20261115)
        statuses={}
        for case in range(200):
            nodes=[]
            for i in range(rng.randint(1,3)):
                nodes.append({'id':f'n{i}', 'trust':rng.choice(['local','trusted','untrusted']),
                              'capabilities':['llama'], 'models':['q'],
                              'ram_available_mb':rng.choice([300,500,800]),'ram_headroom_mb':100,
                              'disk_free_bytes':rng.choice([500,1000]),'thermal_c':rng.choice([30,42,45]),
                              'priority':i})
            jobs=[]
            for i in range(rng.randint(1,5)):
                job={'id':f'j{i}','engine':'llama','models':['q'],
                     'ram_mb':rng.choice([100,250,400]),'duration_slots':rng.choice([1,2]),
                     'output_bytes':rng.choice([0,100,300]),
                     'privacy':rng.choice(['any','trusted_only','local_only'])}
                if i and rng.random() < .35:job['depends_on']=[f'j{i-1}']
                jobs.append(job)
            doc=compile_workflow(jobs,nodes,CAT,horizon=4,max_states=3000,
                                 require_n_minus_one=bool(case%2))
            proof=verify_workflow(doc,jobs,nodes,CAT)
            self.assertTrue(proof['valid'],f'case {case}')
            statuses[doc['status']]=statuses.get(doc['status'],0)+1
            if doc['status']=='RESILIENT':
                self.assertEqual(len(proof['verified_failure_scenarios']),len(nodes))
            if doc['status']=='BLOCKED_RESILIENCE':
                self.assertFalse(doc['admitted'])
        self.assertGreater(len(statuses),2)

    def test_rehashed_wrong_failure_node_rejected(self):
        jobs=[{'id':'a','engine':'llama','models':['q'],'ram_mb':100,'duration_slots':1,'privacy':'any'}]
        nodes=[{'id':n,'trust':'local','capabilities':['llama'],'models':['q'],
                'ram_available_mb':1000,'ram_headroom_mb':0,'disk_free_bytes':1000,'thermal_c':30}
               for n in ('a','b')]
        doc=compile_workflow(jobs,nodes,CAT,horizon=2)
        doc['failures']['a']['assignments'][0]['node']='a'
        doc['certificate_sha256']=digest({k:v for k,v in doc.items() if k!='certificate_sha256'})
        with self.assertRaises(ValueError):verify_workflow(doc,jobs,nodes,CAT)

if __name__=='__main__':unittest.main()
