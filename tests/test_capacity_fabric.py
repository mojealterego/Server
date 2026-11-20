import copy
import tempfile
import unittest
from pathlib import Path
from atlas import capacity_fabric as f

NOW = 1800000000
M = 1024**2


def pool(name='a', domain=None, **changes):
    return dict(id=name, pool=name, domain=domain or name, kind='local',
                limit_bytes=20*M, used_bytes=2*M, reserve_bytes=M,
                write_budget_bytes=20*M, read_budget_bytes=20*M,
                block_budget=20, observed_at=NOW, authorized=True,
                zero_cost=True, **{}) | changes


def policy(*rows, copies=2):
    return dict(schema='omega.capacity.v1', copies=copies, chunk_bytes=M,
                max_age_seconds=60, pools=list(rows))


class CapacityTests(unittest.TestCase):
    def test_01_duplicate_account_pool_rejected(self):
        with self.assertRaises(f.PolicyError):
            f.capacity(policy(pool(), pool('b', pool='a')), NOW)

    def test_02_conservative_capacity_and_budgets(self):
        c = f.capacity(policy(pool(write_budget_bytes=4*M), pool('b', read_budget_bytes=3*M)), NOW)
        self.assertEqual(c['eligible_bytes'], 7*M)
        self.assertEqual(c['payload_upper_bound_bytes'], 3*M)

    def test_03_no_paid_or_unauthorized_pool(self):
        c = f.capacity(policy(pool(), pool('b', zero_cost=False), pool('c', authorized=False)), NOW)
        self.assertEqual(c['eligible_bytes'], 17*M)
        self.assertEqual(c['payload_upper_bound_bytes'], 0)
        self.assertEqual(c['excluded'], {'b':'cost', 'c':'authorization'})

    def test_04_stale_or_future_telemetry_excluded(self):
        c = f.capacity(policy(pool(observed_at=NOW-61), pool('b', observed_at=NOW+1)), NOW)
        self.assertEqual(c['excluded'], {'a':'stale', 'b':'stale'})

    def test_05_same_domain_cannot_claim_two_copies(self):
        p = policy(pool(domain='same'), pool('b', domain='same'))
        self.assertEqual(f.capacity(p, NOW)['payload_upper_bound_bytes'], 0)
        with self.assertRaises(f.PolicyError): f.plan(p, M, NOW)

    def test_06_planner_stripes_and_never_exceeds_budget(self):
        p = policy(pool(write_budget_bytes=2*M), pool('b'), pool('c'))
        result = f.plan(p, 4*M+7, NOW)
        self.assertTrue(f.verify(p, result, NOW))
        self.assertEqual(sum(x['length'] for x in result['blocks']), 4*M+7)
        self.assertEqual(len(result['blocks']), 5)
        self.assertEqual(result, f.plan(p, 4*M+7, NOW))

    def test_07_independent_verifier_rejects_tampering(self):
        p = policy(pool(), pool('b'), pool('c'))
        result = f.plan(p, 2*M, NOW)
        for change in ('copy', 'offset', 'size', 'policy'):
            bad = copy.deepcopy(result)
            if change=='copy': bad['blocks'][0]['pools']=['a','a']
            if change=='offset': bad['blocks'][0]['offset']=1
            if change=='size': bad['blocks'][1]['length']-=1
            if change=='policy': bad['policy_sha256']='0'*64
            with self.assertRaises(f.PolicyError): f.verify(p,bad,NOW)

    def test_08_logical_operation_budget_enforced(self):
        p = policy(pool(block_budget=1), pool('b',block_budget=1))
        self.assertTrue(f.verify(p, f.plan(p,M,NOW), NOW))
        with self.assertRaises(f.PolicyError): f.plan(p,M+1,NOW)

    def test_09_stale_plan_not_reused(self):
        p=policy(pool(),pool('b'))
        plan=f.plan(p,M,NOW)
        with self.assertRaises(f.PolicyError): f.verify(p,plan,NOW+61)

    def test_10_local_probe_reports_real_mount(self):
        with tempfile.TemporaryDirectory() as root:
            a=f.probe_local(Path(root),'host-a',NOW)
            b=f.probe_local(Path(root),'host-a',NOW)
            self.assertEqual(a['pool'],b['pool'])
            self.assertGreater(a['total_bytes'],0)
            self.assertGreaterEqual(a['free_bytes'],0)
            self.assertLessEqual(a['free_bytes'],a['total_bytes'])

    def test_11_strict_types_and_oversize(self):
        for row in (pool(used_bytes=True), pool(kind='unrecognized'),pool(reserve_bytes=-1),pool(id='../x')):
            with self.assertRaises(f.PolicyError): f.capacity(policy(row),NOW)
        with self.assertRaises(f.PolicyError): f.plan(policy(pool(),pool('b')), 0, NOW)
        with self.assertRaises(f.PolicyError): f.plan(policy(pool(),pool('b')), 65537*M, NOW)

    def test_order_independent_placement(self):
        a=policy(pool(),pool('b'),pool('c'))
        b=policy(pool('c'),pool('b'),pool())
        self.assertEqual(f.plan(a,4*M,NOW),f.plan(b,4*M,NOW))

    def test_capacity_bound_balanced_domains(self):
        p=policy(pool(limit_bytes=100*M),pool('b',limit_bytes=100*M),pool('c',limit_bytes=100*M),copies=3)
        self.assertEqual(f.capacity(p,NOW)['payload_upper_bound_bytes'],20*M)

class RemoteQuotaTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.binary=Path(tmp.name)/'rclone'

    def fake(self, text):
        self.binary.write_text('#!/usr/bin/env python3\nimport sys\nassert sys.argv[1:]==["about","test:","--json"]\nprint('+repr(text)+')\n')
        self.binary.chmod(0o700)

    def test_live_process_quota(self):
        self.fake('{"total":1000,"used":100,"free":300,"other":600}')
        r=f.probe_remote('test','provider-account',NOW,rclone=str(self.binary))
        self.assertEqual(r,dict(pool='provider-account',total_bytes=1000,free_bytes=300,observed_at=NOW))

    def test_unknown_quota_refused(self):
        for raw in ('{"used":100}', '{"total":1,"free":2}', '{"total":true,"free":0}', '{"total":100,"free":10,"free":20}', 'x'*70000):
            self.fake(raw)
            with self.assertRaises(f.PolicyError):f.probe_remote('test','p',NOW,rclone=str(self.binary))

    def test_deadline_and_alias(self):
        self.binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(20)\n');self.binary.chmod(0o700)
        with self.assertRaises(f.PolicyError):f.probe_remote('test','p',NOW,rclone=str(self.binary),timeout=1)
        with self.assertRaises(f.PolicyError):f.probe_remote('--config','p',NOW,rclone='/nonexistent')
