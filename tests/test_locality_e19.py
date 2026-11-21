"""E19a: bounded, pinned data movement and stage p95 advisor."""
import copy
import unittest
from atlas.locality_advisor import advise, digest, LocalityError

NOW=1800000000
SHA='a'*64
NODES=[
 {'id':'phone','trust':'local','capabilities':['llama'],'models':['q'],
  'ram_available_mb':8000,'ram_headroom_mb':1000,'disk_free_bytes':10**10,'thermal_c':35},
 {'id':'edge','trust':'trusted','capabilities':['llama'],'models':['q'],
  'ram_available_mb':16000,'ram_headroom_mb':1000,'disk_free_bytes':10**10,'thermal_c':30},
 {'id':'public','trust':'untrusted','capabilities':['llama'],'models':['q'],
  'ram_available_mb':16000,'ram_headroom_mb':1000,'disk_free_bytes':10**10,'thermal_c':30},
]
TASKS=[{'id':'t1','engine':'llama','models':['q'],'ram_mb':500,'privacy':'trusted_only'}]
PROFILE={'schema':'omega.locality.v1','task_inputs':[{'task':'t1','sha256':SHA,'bytes':1000000}],
         'replicas':[{'node':'phone','sha256':SHA,'observed_at':NOW}],
         'links':[{'source':'phone','target':'edge','bytes_per_second':1000000,'rtt_ms':20,'observed_at':NOW}],
         'runtime':[{'task':'t1','node':'phone','samples_ms':[200]*20,'observed_at':NOW},
                    {'task':'t1','node':'edge','samples_ms':[100]*20,'observed_at':NOW},
                    {'task':'t1','node':'public','samples_ms':[10]*20,'observed_at':NOW}]}

class LocalityTests(unittest.TestCase):
    def result(self,profile=None,tasks=None,nodes=None,now=NOW):
        profile=PROFILE if profile is None else profile
        return advise(TASKS if tasks is None else tasks,NODES if nodes is None else nodes,
                      profile,digest(profile),now,max_age=300)
    def test_remote_transfer_cost_and_local_recommendation(self):
        r=self.result()
        self.assertEqual(r['status'],'ADVISORY_ONLY')
        self.assertEqual([x['node'] for x in r['tasks'][0]['ranked']][:2],['phone','edge'])
        self.assertEqual(r['tasks'][0]['ranked'][0]['transfer_ms'],0)
        self.assertEqual(r['tasks'][0]['ranked'][1]['transfer_ms'],1020)
    def test_private_task_never_suggested_on_untrusted_node(self):
        r=self.result()
        self.assertNotIn('public',[x['node'] for x in r['tasks'][0]['ranked']])
        t=[dict(TASKS[0],privacy='local_only')]
        r=self.result(tasks=t)
        self.assertEqual([x['node'] for x in r['tasks'][0]['ranked']],['phone'])
    def test_unknown_transfer_route_fails_closed(self):
        p=copy.deepcopy(PROFILE);p['links']=[]
        r=self.result(p)
        self.assertEqual([x['node'] for x in r['tasks'][0]['ranked']],['phone'])
    def test_stale_measurement_excludes_candidate(self):
        p=copy.deepcopy(PROFILE);p['runtime'][0]['observed_at']=NOW-301
        r=self.result(p)
        self.assertEqual([x['node'] for x in r['tasks'][0]['ranked']],['edge'])
    def test_tampered_digest_rejected(self):
        p=copy.deepcopy(PROFILE);p['links'][0]['rtt_ms']=0
        with self.assertRaises(LocalityError):advise(TASKS,NODES,p,digest(PROFILE),NOW)
    def test_invalid_telemetry_and_duplicates(self):
        for key,value in [('bytes_per_second',0),('rtt_ms',True),('bytes_per_second',1e6)]:
            p=copy.deepcopy(PROFILE);p['links'][0][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(LocalityError):self.result(p)
        p=copy.deepcopy(PROFILE);p['links'].append(p['links'][0])
        with self.assertRaises(LocalityError):self.result(p)
    def test_engine_memory_and_model_restrictions(self):
        nodes=copy.deepcopy(NODES)
        nodes[0]['ram_available_mb']=100
        nodes[1]['models']=[]
        r=self.result(nodes=nodes)
        self.assertEqual(r['tasks'][0]['ranked'],[])
    def test_no_data_input_means_no_network_cost(self):
        p=copy.deepcopy(PROFILE);p['task_inputs']=[];p['replicas']=[];p['links']=[]
        r=self.result(p)
        self.assertEqual(r['tasks'][0]['ranked'][0]['node'],'edge')
        self.assertEqual(r['tasks'][0]['ranked'][0]['transfer_ms'],0)
    def test_missing_runtime_blocks_node_even_if_local(self):
        p=copy.deepcopy(PROFILE);p['runtime']=p['runtime'][1:]
        r=self.result(p)
        self.assertEqual([x['node'] for x in r['tasks'][0]['ranked']],['edge'])
    def test_evidence_is_read_only_not_plan(self):
        r=self.result()
        self.assertNotIn('assignments',r)
        self.assertEqual(r['tasks'][0]['ranked'][0]['basis'],'OBSERVATION_NOT_ATTESTATION')

if __name__=='__main__':unittest.main()
