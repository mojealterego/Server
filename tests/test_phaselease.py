"""Lease fencing and crash recovery tests using real SQLite on local filesystem."""
import concurrent.futures
import copy
import hashlib
import tempfile
from pathlib import Path
import unittest
from atlas.phaseshift import compile_workflow
from atlas.phaselease import LeaseStore, LeaseError

CAT = {'m': {'bytes': 100, 'format': 'gguf', 'role': 'llm', 'lineage_verified': True}}
NODES = [{'id':'phone','trust':'local','capabilities':['llama'],'models':['m'],
          'ram_available_mb':4096,'ram_headroom_mb':256,'disk_free_bytes':100000,
          'thermal_c':35,'priority':0}]
JOBS = [{'id':'first','engine':'llama','models':['m'],'ram_mb':100,'duration_slots':1,'privacy':'local_only','output_bytes':100},
        {'id':'second','engine':'llama','models':['m'],'ram_mb':100,'duration_slots':1,'privacy':'local_only','output_bytes':100, 'depends_on':['first']}]

class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name)/'leases.db'
        self.plan = compile_workflow(JOBS,NODES,CAT,horizon=4)
        self.assertTrue(self.plan['admitted'])

    def tearDown(self):
        self.temp.cleanup()

    def store(self):
        return LeaseStore(self.db,self.plan,JOBS,NODES,CAT)

    def test_dependency_blocks_claim(self):
        with self.store() as s:
            with self.assertRaises(LeaseError): s.claim('second','phone',now=100,ttl=20)

    def test_claim_and_complete_with_actual_file_hash(self):
        output = Path(self.temp.name)/'answer.txt'
        output.write_bytes(b'hello world')
        with self.store() as s:
            claim = s.claim('first','phone',now=100,ttl=20)
            receipt = s.complete('first','phone',claim['token'],claim['epoch'],output,now=110)
            self.assertEqual(receipt['output_sha256'],hashlib.sha256(b'hello world').hexdigest())
            self.assertEqual(s.status('first')['state'],'COMPLETED')
            self.assertEqual(s.claim('second','phone',now=111,ttl=20)['epoch'],1)

    def test_wrong_node_and_token_rejected(self):
        with self.store() as s:
            with self.assertRaises(LeaseError): s.claim('first','vps',now=100,ttl=20)
            claim = s.claim('first','phone',now=100,ttl=20)
            with self.assertRaises(LeaseError): s.renew('first','phone','wrong',claim['epoch'],now=101,ttl=10)

    def test_expiry_fences_stale_worker(self):
        output = Path(self.temp.name)/'out'; output.write_bytes(b'ok')
        with self.store() as s:
            a = s.claim('first','phone',now=100,ttl=5)
            b = s.claim('first','phone',now=106,ttl=5)
            self.assertGreater(b['epoch'],a['epoch'])
            with self.assertRaises(LeaseError): s.complete('first','phone',a['token'],a['epoch'],output,now=107)
            self.assertEqual(s.complete('first','phone',b['token'],b['epoch'],output,now=107)['state'],'COMPLETED')

    def test_reopen_db_retains_state(self):
        with self.store() as s:
            claim = s.claim('first','phone',now=100,ttl=20)
        with self.store() as s:
            self.assertEqual(s.status('first')['epoch'],claim['epoch'])
            with self.assertRaises(LeaseError): s.claim('first','phone',now=101,ttl=10)

    def test_concurrent_claims_exactly_one_wins(self):
        def contender(_):
            with self.store() as s:
                try:
                    return s.claim('first','phone',now=100,ttl=20)
                except LeaseError:
                    return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            wins = [x for x in pool.map(contender,range(12)) if x is not None]
        self.assertEqual(len(wins),1)

    def test_tampered_plan_is_not_admitted(self):
        forged = copy.deepcopy(self.plan)
        forged['primary']['assignments'][0]['node'] = 'vps'
        with self.assertRaises(ValueError): LeaseStore(self.db,forged,JOBS,NODES,CAT)

    def test_strict_unresilient_plan_cannot_claim(self):
        strict = compile_workflow(JOBS,NODES,CAT,horizon=4,require_n_minus_one=True)
        self.assertFalse(strict['admitted'])
        with self.assertRaises(LeaseError): LeaseStore(self.db,strict,JOBS,NODES,CAT)

    def test_missing_output_and_symlink_rejected(self):
        output = Path(self.temp.name)/'out'; output.write_bytes(b'ok')
        link = Path(self.temp.name)/'link'; link.symlink_to(output)
        with self.store() as s:
            a = s.claim('first','phone',now=100,ttl=20)
            with self.assertRaises(LeaseError): s.complete('first','phone',a['token'],a['epoch'],link,now=101)
            with self.assertRaises(LeaseError): s.complete('first','phone',a['token'],a['epoch'],Path(self.temp.name)/'missing',now=101)

    def test_rejects_output_exceeding_reserved_disk(self):
        output = Path(self.temp.name)/'too-large'; output.write_bytes(b'x'*101)
        with self.store() as s:
            a = s.claim('first','phone',now=100,ttl=20)
            with self.assertRaises(LeaseError):
                s.complete('first','phone',a['token'],a['epoch'],output,now=101)
            self.assertEqual(s.status('first')['state'],'LEASED')

    def test_renew_extends_lease(self):
        with self.store() as s:
            a = s.claim('first','phone',now=100,ttl=5)
            renewed = s.renew('first','phone',a['token'],a['epoch'],now=103,ttl=20)
            self.assertEqual(renewed['expires_at'],123)
            with self.assertRaises(LeaseError): s.claim('first','phone',now=120,ttl=10)

if __name__ == '__main__': unittest.main()
