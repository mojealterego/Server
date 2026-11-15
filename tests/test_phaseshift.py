"""Red/green tests for proof-carrying counterfactual planning."""
import copy
import json
import unittest
from atlas.phaseshift import compile_workflow
from atlas.phaseverify import verify_workflow

CATALOG = {'q': {'bytes': 100, 'format': 'gguf', 'role': 'llm', 'lineage_verified': True}}

def node(name, ram=1000, disk=1000, trust='trusted', priority=0):
    return {'id': name, 'trust': trust, 'ram_available_mb': ram,
            'ram_headroom_mb': 0, 'disk_free_bytes': disk,
            'thermal_c': 30, 'capabilities': ['llama'], 'models': ['q'], 'priority': priority}

def task(name, ram=600, duration=2, **kw):
    return {'id': name, 'engine': 'llama', 'models': ['q'], 'ram_mb': ram,
            'duration_slots': duration, **kw}

class PhaseShiftTests(unittest.TestCase):
    def test_no_memory_overcommit_parallel(self):
        jobs = [task('a'), task('b')]
        result = compile_workflow(jobs, [node('n')], CATALOG, horizon=4)
        self.assertEqual(result['status'], 'DEGRADED')
        slots = result['primary']['assignments']
        self.assertFalse(slots[0]['start_slot'] < slots[1]['end_slot'] and slots[1]['start_slot'] < slots[0]['end_slot'])
        self.assertTrue(verify_workflow(result, jobs, [node('n')], CATALOG)['valid'])

    def test_fails_closed_when_no_capacity_in_horizon(self):
        jobs = [task('a'), task('b')]
        result = compile_workflow(jobs, [node('n')], CATALOG, horizon=2)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['primary']['status'], 'BLOCKED')

    def test_n_minus_one_recovery(self):
        jobs = [task('a', duration=1), task('b', duration=1)]
        nodes = [node('one'), node('two')]
        result = compile_workflow(jobs, nodes, CATALOG, horizon=2, require_n_minus_one=True)
        self.assertEqual(result['status'], 'RESILIENT')
        self.assertTrue(result['admitted'])
        self.assertEqual(set(result['failures']), {'one', 'two'})
        self.assertEqual(result['failures']['one']['assignments'][0]['node'], 'two')
        self.assertTrue(verify_workflow(result, jobs, nodes, CATALOG)['valid'])

    def test_privacy_propagates_to_descendants(self):
        jobs = [task('source', duration=1, privacy='local_only'),
                task('derived', duration=1, depends_on=['source'], privacy='any')]
        nodes = [node('phone', trust='local'), node('cloud', priority=-5)]
        result = compile_workflow(jobs, nodes, CATALOG, horizon=3)
        stages = result['primary']['assignments']
        self.assertEqual([s['node'] for s in stages], ['phone', 'phone'])
        self.assertEqual(stages[1]['effective_privacy'], 'local_only')
        self.assertTrue(verify_workflow(result, jobs, nodes, CATALOG)['valid'])

    def test_strict_resilience_rejects_single_phone(self):
        jobs = [task('a', privacy='local_only', duration=1)]
        nodes = [node('phone', trust='local'), node('vps')]
        result = compile_workflow(jobs, nodes, CATALOG, horizon=2, require_n_minus_one=True)
        self.assertEqual(result['status'], 'BLOCKED_RESILIENCE')
        self.assertFalse(result['admitted'])
        self.assertEqual(result['failures']['phone']['status'], 'BLOCKED')
        self.assertTrue(verify_workflow(result, jobs, nodes, CATALOG)['valid'])

    def test_dependency_order(self):
        jobs = [task('first', duration=2), task('second', duration=1, depends_on=['first'])]
        nodes = [node('a'), node('b')]
        result = compile_workflow(jobs, nodes, CATALOG, horizon=3)
        assignments = {s['id']: s for s in result['primary']['assignments']}
        self.assertGreaterEqual(assignments['second']['start_slot'], assignments['first']['end_slot'])
        self.assertTrue(verify_workflow(result, jobs, nodes, CATALOG)['valid'])

    def test_disk_persistence_reservation(self):
        jobs = [task('a', duration=1, output_bytes=700), task('b', duration=1, output_bytes=700)]
        result = compile_workflow(jobs, [node('a', disk=1000)], CATALOG, horizon=4)
        self.assertEqual(result['primary']['status'], 'BLOCKED')

    def test_rejects_unverified_lineage(self):
        jobs = [task('a', requires_verified_lineage=True)]
        catalog = copy.deepcopy(CATALOG)
        catalog['q']['lineage_verified'] = False
        result = compile_workflow(jobs, [node('a')], catalog, horizon=3)
        self.assertEqual(result['status'], 'BLOCKED')

    def test_thermal_fails_closed(self):
        nodes = [dict(node('a'), thermal_c=44)]
        result = compile_workflow([task('a')], nodes, CATALOG, horizon=4)
        self.assertEqual(result['status'], 'BLOCKED')

    def test_reproducible_digest(self):
        jobs = [task('a', duration=1)]
        nodes = [node('a'), node('b')]
        self.assertEqual(compile_workflow(jobs, nodes, CATALOG), compile_workflow(jobs, nodes, CATALOG))

    def test_certificate_detects_mutation(self):
        jobs = [task('a', duration=1)]
        nodes = [node('a'), node('b')]
        result = compile_workflow(jobs, nodes, CATALOG)
        result['primary']['assignments'][0]['ram_mb'] = 99999
        with self.assertRaises(ValueError): verify_workflow(result, jobs, nodes, CATALOG)

    def test_verifier_rejects_rehashed_forged_overcommit(self):
        from atlas.phaseshift import digest
        jobs = [task('a'), task('b')]
        nodes = [node('a'), node('b')]
        result = compile_workflow(jobs, nodes, CATALOG, horizon=4)
        result['primary']['assignments'][1]['node'] = result['primary']['assignments'][0]['node']
        result['primary']['assignments'][1]['start_slot'] = 0
        result['primary']['assignments'][1]['end_slot'] = 2
        result['certificate_sha256'] = digest({k:v for k,v in result.items() if k!='certificate_sha256'})
        with self.assertRaises(ValueError): verify_workflow(result, jobs, nodes, CATALOG)

    def test_verifier_rejects_rehashed_privacy_leak(self):
        from atlas.phaseshift import digest
        jobs = [task('a', privacy='local_only', duration=1)]
        nodes = [node('phone', trust='local'), node('cloud')]
        result = compile_workflow(jobs, nodes, CATALOG)
        result['primary']['assignments'][0]['node'] = 'cloud'
        result['certificate_sha256'] = digest({k:v for k,v in result.items() if k!='certificate_sha256'})
        with self.assertRaises(ValueError): verify_workflow(result, jobs, nodes, CATALOG)

    def test_input_mismatch_rejected(self):
        jobs = [task('a', duration=1)]
        nodes = [node('a'), node('b')]
        result = compile_workflow(jobs, nodes, CATALOG)
        with self.assertRaises(ValueError): verify_workflow(result, [task('a', duration=1, ram=900)], nodes, CATALOG)

    def test_budget_exhaustion_is_not_false_infeasibility(self):
        jobs = [task('a', duration=1)]
        nodes = [node('a')]
        result = compile_workflow(jobs, nodes, CATALOG, max_states=1, horizon=4)
        self.assertEqual(result['primary']['status'], 'INDETERMINATE')

    def test_invalid_duration_and_ids_rejected(self):
        with self.assertRaises(ValueError): compile_workflow([task('a', duration=0)], [node('n')], CATALOG)
        with self.assertRaises(ValueError): compile_workflow([task('a')], [node('../n')], CATALOG)

if __name__ == '__main__': unittest.main()
