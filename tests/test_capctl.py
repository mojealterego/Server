import copy
import json
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from tools.capctl import sign, admit, CapabilityError

class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / 'key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.key)],check=True)
        self.key.chmod(0o600)
        self.now = time.time_ns()
        self.node = dict(id='s24',ram_available_mb=5000,ram_headroom_mb=1024,disk_free_bytes=1000000,
                         thermal_c=36.5,capabilities=['llama'],models=['qwen'])
        self.env = sign(self.node,self.key,self.now)
        self.policy = {'s24': dict(public_key=self.env['public_key'],trust='local',priority=1,
                          max_ram_mb=6000,min_headroom_mb=1024,max_disk_bytes=2000000,
                          capabilities=['llama'],models=['qwen'])}
        self.db = self.root/'replay.sqlite'
    def check(self, env=None, policy=None, now=None):
        return admit([self.env if env is None else env],self.policy if policy is None else policy,
                     self.db,now_ns=self.now if now is None else now)
    def test_valid_and_replay_after_reopen(self):
        nodes = self.check()
        self.assertEqual(nodes,[{**self.node,'trust':'local','priority':1}])
        with self.assertRaises(CapabilityError): self.check()
        newer = sign(self.node,self.key,self.now+1)
        self.assertEqual(self.check(newer,now=self.now+1),nodes)
        with self.assertRaises(CapabilityError): self.check(now=self.now+1)
    def test_modified_payload(self):
        env=copy.deepcopy(self.env); env['node']['ram_available_mb']=5900
        with self.assertRaises(CapabilityError): self.check(env)
        self.assertEqual(len(self.check()),1)
    def test_untrusted_key_and_node(self):
        other=self.root/'other.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(other)],check=True)
        other.chmod(0o600)
        with self.assertRaises(CapabilityError):self.check(sign(self.node,other,self.now))
        with self.assertRaises(CapabilityError):self.check(sign({**self.node,'id':'other'},self.key,self.now))
    def test_policy_limits(self):
        for change in ({'ram_available_mb':7000},{'capabilities':['llama','wan']},
                       {'models':['unknown']},{'ram_headroom_mb':0},{'disk_free_bytes':3000000}):
            with self.subTest(change=change),self.assertRaises(CapabilityError):
                self.check(sign({**self.node,**change},self.key,self.now))
    def test_old_future_and_invalid_values(self):
        for now in (self.now+301_000_000_000,self.now-31_000_000_000):
            with self.assertRaises(CapabilityError): self.check(now=now)
        for value in (float('nan'),None,True):
            with self.assertRaises(CapabilityError): sign({**self.node,'thermal_c':value},self.key,self.now)
        with self.assertRaises(CapabilityError): sign({**self.node,'trust':'local'},self.key,self.now)
    def test_atomic_batch(self):
        bad=copy.deepcopy(self.env); bad['node']['id']='other'
        with self.assertRaises(CapabilityError):admit([self.env,bad],self.policy,self.db,now_ns=self.now)
        self.assertEqual(len(self.check()),1)
    def test_concurrent_replay(self):
        def attempt(_):
            try: self.check(); return True
            except CapabilityError: return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt,range(4))),1)
    def test_transaction_rollback_on_second_replay(self):
        other=self.root/'other.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(other)],check=True)
        other.chmod(0o600)
        second=sign({**self.node,'id':'other'},other,self.now)
        policy={**self.policy,'other':{**self.policy['s24'],'public_key':second['public_key']}}
        self.assertEqual(len(admit([second],policy,self.db,now_ns=self.now)),1)
        with self.assertRaises(CapabilityError):admit([self.env,second],policy,self.db,now_ns=self.now)
        self.assertEqual(len(self.check()),1)
    def test_private_key_permissions(self):
        self.key.chmod(0o644)
        with self.assertRaises(CapabilityError):sign(self.node,self.key,self.now)
    def test_duplicate_batch(self):
        with self.assertRaises(CapabilityError):admit([self.env,self.env],self.policy,self.db,now_ns=self.now)
        self.assertEqual(len(self.check()),1)

if __name__=='__main__':unittest.main()
