"""Runtime memory admission and explicit failure release (SQLite, not OS RAM)."""
from __future__ import annotations
import concurrent.futures
from pathlib import Path
import tempfile
import unittest
from atlas.phaseshift import compile_workflow
from atlas.phaselease import LeaseStore, LeaseError

CAT = {'m': {'bytes': 100, 'format': 'gguf', 'role': 'llm', 'lineage_verified': True}}
NODES = [{'id': 'phone', 'trust': 'local', 'capabilities': ['llama'], 'models': ['m'],
          'ram_available_mb': 1000, 'ram_headroom_mb': 100,
          'disk_free_bytes': 200000, 'thermal_c': 33, 'priority': 0}]

def task(ident):
    return {'id': ident, 'engine': 'llama', 'models': ['m'], 'ram_mb': 600,
            'duration_slots': 1, 'output_bytes': 100, 'privacy': 'local_only'}

class RuntimeAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / 'leases.sqlite'
        self.jobs = [task('alpha'), task('beta')]
        self.plan = compile_workflow(self.jobs, NODES, CAT, horizon=4)
        self.assertTrue(self.plan['admitted'])

    def tearDown(self):
        self.tmp.cleanup()

    def store(self, jobs=None, plan=None, nodes=None):
        return LeaseStore(self.db, plan or self.plan, jobs or self.jobs, nodes or NODES, CAT)

    def test_sequential_schedule_does_not_allow_concurrent_ram_overcommit(self):
        with self.store() as s:
            first = s.claim('alpha', 'phone', now=100, ttl=40)
            with self.assertRaisesRegex(LeaseError, 'RAM'):
                s.claim('beta', 'phone', now=101, ttl=40)
            self.assertEqual(s.status('alpha')['reserved_ram_mb'], 600)
            s.fail('alpha', 'phone', first['token'], first['epoch'], 'PROCESS_FAILED', now=102)
            second = s.claim('beta', 'phone', now=103, ttl=40)
            self.assertEqual(second['state'], 'LEASED')

    def test_cross_plan_budget_reservation_persists(self):
        jobs1 = [task('first')]
        jobs2 = [task('second')]
        plan1 = compile_workflow(jobs1, NODES, CAT)
        plan2 = compile_workflow(jobs2, NODES, CAT)
        with self.store(jobs1, plan1) as first, self.store(jobs2, plan2) as second:
            a = first.claim('first', 'phone', now=100, ttl=50)
            with self.assertRaisesRegex(LeaseError, 'RAM'):
                second.claim('second', 'phone', now=101, ttl=50)
            first.fail('first', 'phone', a['token'], a['epoch'], 'PROCESS_FAILED', now=102)
            self.assertEqual(second.claim('second', 'phone', now=103, ttl=50)['epoch'], 1)

    def test_expired_leases_release_ram(self):
        with self.store() as s:
            a = s.claim('alpha', 'phone', now=100, ttl=3)
            with self.assertRaises(LeaseError): s.claim('beta', 'phone', now=102, ttl=5)
            self.assertEqual(s.claim('beta', 'phone', now=103, ttl=5)['epoch'], 1)
            with self.assertRaises(LeaseError):
                s.fail('alpha', 'phone', a['token'], a['epoch'], 'PROCESS_FAILED', now=104)

    def test_failure_is_fenced_and_reclaimable(self):
        with self.store() as s:
            a = s.claim('alpha', 'phone', now=100, ttl=30)
            with self.assertRaises(LeaseError):
                s.fail('alpha', 'phone', 'invalid', a['epoch'], 'PROCESS_FAILED', now=101)
            s.fail('alpha', 'phone', a['token'], a['epoch'], 'PROCESS_FAILED', now=102)
            self.assertEqual(s.status('alpha')['state'], 'FAILED')
            self.assertEqual(s.status('alpha')['last_error'], 'PROCESS_FAILED')
            b = s.claim('alpha', 'phone', now=103, ttl=30)
            self.assertEqual(b['epoch'], a['epoch'] + 1)
            with self.assertRaises(LeaseError):
                s.fail('alpha', 'phone', a['token'], a['epoch'], 'PROCESS_FAILED', now=104)

    def test_node_capacity_contract_rejects_mismatch(self):
        smaller = [{**NODES[0], 'ram_available_mb': 900}]
        with self.store() as s:
            s.claim('alpha','phone',now=100,ttl=30)
        new_plan = compile_workflow([task('gamma')], smaller, CAT, horizon=4)
        with self.assertRaisesRegex(LeaseError, 'capacity'):
            self.store([task('gamma')], new_plan, smaller)

    def test_concurrent_claims_cannot_exceed_ram(self):
        def claim(i):
            with self.store() as s:
                try: return s.claim(self.jobs[i]['id'], 'phone', now=100, ttl=30)
                except LeaseError: return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(claim, [0,1]))
        self.assertEqual(sum(r is not None for r in results),1)

if __name__ == '__main__': unittest.main()
