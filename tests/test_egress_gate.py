import copy
import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from atlas.egress_gate import EgressError, digest, filter_advice

NOW=1800000000
SHA='a'*64
PROFILE={'schema':'omega.locality.v1','task_inputs':[{'task':'a','sha256':SHA,'bytes':2097152}],
         'replicas':[{'node':'phone','sha256':SHA,'observed_at':NOW}],
         'links':[{'source':'phone','target':'vps','bytes_per_second':1048576,'rtt_ms':12,'observed_at':NOW},
                  {'source':'phone','target':'edge','bytes_per_second':2097152,'rtt_ms':4,'observed_at':NOW}],
         'runtime':[{'task':'a','node':node,'observed_at':NOW,'samples_ms':[ms]*10}
                    for node,ms in [('vps',70),('edge',100),('phone',300)]]}
PROFILE_PIN=digest(PROFILE)
ADVICE={'status':'ADVISORY_ONLY','profile_sha256':PROFILE_PIN,
        'tasks':[{'task':'a','ranked':[{'node':'vps','runtime_p95_ms':70,'transfer_ms':2012,'estimated_sum_ms':2082},
                                     {'node':'edge','runtime_p95_ms':100,'transfer_ms':1004,'estimated_sum_ms':1104},
                                     {'node':'phone','runtime_p95_ms':300,'transfer_ms':0,'estimated_sum_ms':300}]}]}
POLICY={'schema':'omega.egress.guard.v1','profile_sha256':PROFILE_PIN,'max_age_seconds':300,
        'links':[{'source':'phone','target':'vps','free_bytes':2097152,'billable':True,'observed_at':NOW},
                 {'source':'phone','target':'edge','free_bytes':2097152,'billable':False,'observed_at':NOW}]}

class EgressGateTests(unittest.TestCase):
    def gate(self,policy=None,profile=None,advice=None,pin=None):
        p=copy.deepcopy(POLICY if policy is None else policy)
        x=copy.deepcopy(PROFILE if profile is None else profile)
        a=copy.deepcopy(ADVICE if advice is None else advice)
        return filter_advice(a,x,digest(x),p,digest(p) if pin is None else pin,NOW)

    def test_billable_path_refused_and_free_candidate_kept(self):
        out=self.gate()
        nodes=[x['node'] for x in out['tasks'][0]['ranked']]
        self.assertEqual(nodes,['phone','edge'])
        self.assertEqual(out['tasks'][0]['ranked'][1]['estimated_zero_cost_ms'],1104)
        self.assertEqual(out['tasks'][0]['ranked'][1]['source_node'],'phone')

    def test_local_verified_replica_needs_no_egress(self):
        out=self.gate()
        local=out['tasks'][0]['ranked'][0]
        self.assertEqual(local['egress_bytes'],0)
        self.assertEqual(local['estimated_zero_cost_ms'],300)

    def test_exhausted_free_budget_fails_closed(self):
        p=copy.deepcopy(POLICY);p['links'][1]['free_bytes']=2097151
        out=self.gate(policy=p)
        self.assertEqual([x['node'] for x in out['tasks'][0]['ranked']],['phone'])

    def test_stale_or_future_budget_fails(self):
        for at in [NOW-301,NOW+1]:
            p=copy.deepcopy(POLICY);p['links'][1]['observed_at']=at
            with self.subTest(at=at):
                self.assertEqual([x['node'] for x in self.gate(policy=p)['tasks'][0]['ranked']],['phone'])

    def test_signed_policy_mismatch_fails(self):
        p=copy.deepcopy(POLICY);p['links'][1]['billable']=True
        with self.assertRaises(EgressError):self.gate(policy=p,pin=digest(POLICY))

    def test_forged_profile_or_advice_rejected(self):
        a=copy.deepcopy(ADVICE);a['profile_sha256']='f'*64
        with self.assertRaises(EgressError):self.gate(advice=a)
        p=copy.deepcopy(PROFILE);p['task_inputs'][0]['bytes']=20
        with self.assertRaises(EgressError):filter_advice(copy.deepcopy(ADVICE),p,PROFILE_PIN,POLICY,digest(POLICY),NOW)

    def test_replica_staleness_removes_remote_source(self):
        prof=copy.deepcopy(PROFILE);prof['replicas'][0]['observed_at']=NOW-301
        advice=copy.deepcopy(ADVICE);advice['profile_sha256']=digest(prof)
        policy=copy.deepcopy(POLICY);policy['profile_sha256']=digest(prof)
        out=filter_advice(advice,prof,digest(prof),policy,digest(policy),NOW)
        self.assertEqual(out['tasks'][0]['ranked'],[])

    def test_duplicate_budget_or_non_boolean_billable_rejected(self):
        p=copy.deepcopy(POLICY);p['links'].append(copy.deepcopy(p['links'][0]))
        with self.assertRaises(EgressError):self.gate(policy=p)
        p=copy.deepcopy(POLICY);p['links'][1]['billable']=0
        with self.assertRaises(EgressError):self.gate(policy=p)

    def test_tampered_advice_latency_rejected(self):
        a=copy.deepcopy(ADVICE);a['tasks'][0]['ranked'][1]['runtime_p95_ms']=1
        with self.assertRaises(EgressError):self.gate(advice=a)

    def test_unmeasured_forged_node_rejected(self):
        a=copy.deepcopy(ADVICE);a['tasks'][0]['ranked'].append(
            {'node':'faker','runtime_p95_ms':1,'transfer_ms':0,'estimated_sum_ms':1})
        with self.assertRaises(EgressError):self.gate(advice=a)

    def test_forged_transfer_estimate_rejected(self):
        a=copy.deepcopy(ADVICE);a['tasks'][0]['ranked'][1]['transfer_ms']=0
        with self.assertRaises(EgressError):self.gate(advice=a)

    def test_measurement_expiry_refuses_candidate(self):
        x=copy.deepcopy(PROFILE);x['runtime'][1]['observed_at']=NOW-301
        a=copy.deepcopy(ADVICE);a['profile_sha256']=digest(x)
        p=copy.deepcopy(POLICY);p['profile_sha256']=digest(x)
        with self.assertRaises(EgressError):filter_advice(a,x,digest(x),p,digest(p),NOW)

    def test_real_cli_subprocess_rejects_unsafe_symlink_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            for name,doc in [('profile',PROFILE),('policy',POLICY),('advice',ADVICE)]:
                target=root/(name+'.json')
                target.write_text(json.dumps(doc,sort_keys=True),encoding='utf-8')
                target.chmod(0o600)
            argv=[sys.executable,'-m','atlas.egress_gate',
                  '--profile',str(root/'profile.json'),
                  '--policy',str(root/'policy.json'),
                  '--advice',str(root/'advice.json'),
                  '--profile-sha256',PROFILE_PIN,
                  '--policy-sha256',digest(POLICY),
                  '--now',str(NOW)]
            ok=subprocess.run(argv,capture_output=True,text=True,timeout=15)
            self.assertEqual(ok.returncode,0,ok.stderr)
            result=json.loads(ok.stdout)
            self.assertEqual([v['node'] for v in result['tasks'][0]['ranked']],['phone','edge'])
            link=root/'policy.link.json';link.symlink_to(root/'policy.json')
            bad=subprocess.run([x if x!=str(root/'policy.json') else str(link) for x in argv],
                               capture_output=True,text=True,timeout=15)
            self.assertNotEqual(bad.returncode,0)
            self.assertNotIn('Traceback',bad.stderr)

    def test_cli_rejects_duplicate_json_policy_fields(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            for name,doc in [('profile',PROFILE),('policy',POLICY),('advice',ADVICE)]:
                target=root/(name+'.json')
                target.write_text(json.dumps(doc,sort_keys=True),encoding='utf-8')
                target.chmod(0o600)
            policy=root/'policy.json'
            text=policy.read_text().replace('"schema": "omega.egress.guard.v1"',
                           '"schema": "omega.egress.guard.v1", "schema": "omega.egress.guard.v1"')
            policy.write_text(text)
            argv=[sys.executable,'-m','atlas.egress_gate','--profile',str(root/'profile.json'),
                  '--policy',str(policy),'--advice',str(root/'advice.json'),
                  '--profile-sha256',PROFILE_PIN,'--policy-sha256',digest(POLICY),'--now',str(NOW)]
            cp=subprocess.run(argv,capture_output=True,text=True,timeout=15)
            self.assertNotEqual(cp.returncode,0)
            self.assertNotIn('Traceback',cp.stderr)

    def test_per_task_budgets_are_not_global_reservations(self):
        a=copy.deepcopy(ADVICE);a['tasks'].append({'task':'b','ranked':[{'node':'edge','runtime_p95_ms':100,'transfer_ms':1004,'estimated_sum_ms':1104}]})
        p=copy.deepcopy(PROFILE);p['task_inputs'].append({'task':'b','sha256':SHA,'bytes':2097152})
        p['runtime'].append({'task':'b','node':'edge','observed_at':NOW,'samples_ms':[100]*10})
        a['profile_sha256']=digest(p)
        budget=copy.deepcopy(POLICY);budget['profile_sha256']=digest(p)
        result=filter_advice(a,p,digest(p),budget,digest(budget),NOW)
        self.assertEqual(len(result['tasks']),2)
        self.assertEqual(result['scope'],'ADVISORY_PER_TASK_NO_GLOBAL_RESERVATION')

if __name__=='__main__':unittest.main()
