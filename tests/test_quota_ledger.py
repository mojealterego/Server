import concurrent.futures
from pathlib import Path
import sqlite3
import tempfile
import unittest

from atlas import quota_ledger as q


def amount(*, write=0, storage=0, read=0, wops=0, rops=0, egress=0):
    return dict(storage_bytes=storage,write_bytes=write,read_bytes=read,
                write_ops=wops,read_ops=rops,egress_bytes=egress)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        self.path=self.root/'ledger.db';self.ledger=q.Ledger(self.path)
        self.ledger.enroll('pool',amount(write=100,storage=100,read=100,wops=5,rops=5,egress=100),now=10)

    def test_parallel_reservation_does_not_overbook(self):
        def one(i):
            try:self.ledger.reserve('pool',f'req-{i}',amount(write=30,storage=30,wops=1),epoch=1,ttl=20,now=11);return True
            except q.QuotaError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            accepted=list(pool.map(one,range(12)))
        self.assertEqual(accepted.count(True),3)
        self.assertEqual(self.ledger.status('pool',now=12)['available']['write_bytes'],10)

    def test_durable_restart_idempotency_and_reuse_guard(self):
        request=amount(write=50,storage=50,wops=1)
        self.ledger.reserve('pool','x',request,epoch=1,ttl=20,now=11)
        reopened=q.Ledger(self.path)
        self.assertEqual(reopened.reserve('pool','x',request,epoch=1,ttl=99,now=12)['expires'],31)
        with self.assertRaises(q.QuotaError):reopened.reserve('pool','x',amount(write=51,storage=51,wops=1),epoch=1,ttl=20,now=12)
        self.assertEqual(reopened.commit('pool','x',epoch=1,now=13),'COMMITTED')
        self.assertEqual(reopened.commit('pool','x',epoch=1,now=14),'COMMITTED')
        self.assertEqual(reopened.status('pool',now=15)['available']['write_bytes'],50)

    def test_expired_unknown_holds_quota_until_reconcile(self):
        self.ledger.reserve('pool','x',amount(write=90,storage=90,wops=1),epoch=1,ttl=2,now=11)
        self.assertEqual(self.ledger.status('pool',now=13)['uncertain_count'],1)
        with self.assertRaises(q.QuotaError):self.ledger.reserve('pool','y',amount(write=20,storage=20,wops=1),epoch=1,ttl=5,now=14)
        with self.assertRaises(q.QuotaError):self.ledger.commit('pool','x',epoch=1,now=14)
        with self.assertRaises(q.QuotaError):self.ledger.reconcile('pool','x',epoch=1,outcome='ABSENT',confirmed=False,now=14)
        self.assertEqual(self.ledger.reconcile('pool','x',epoch=1,outcome='ABSENT',confirmed=True,now=15),'RELEASED')
        self.ledger.reserve('pool','y',amount(write=20,storage=20,wops=1),epoch=1,ttl=5,now=15)

    def test_fencing_rejects_old_owner(self):
        self.ledger.reserve('pool','x',amount(write=15,storage=15,wops=1),epoch=1,ttl=20,now=11)
        self.ledger.fence('pool',1,2,now=12)
        with self.assertRaises(q.QuotaError):self.ledger.commit('pool','x',epoch=1,now=13)
        with self.assertRaises(q.QuotaError):self.ledger.reserve('pool','y',amount(write=1,wops=1),epoch=1,ttl=20,now=13)
        with self.assertRaises(q.QuotaError):self.ledger.fence('pool',1,3,now=13)
        self.ledger.reserve('pool','y',amount(write=1,wops=1),epoch=2,ttl=20,now=14)

    def test_safe_release_only_before_write(self):
        self.ledger.reserve('pool','x',amount(write=80,storage=80,wops=1),epoch=1,ttl=20,now=11)
        with self.assertRaises(q.QuotaError):self.ledger.release_unwritten('pool','x',epoch=1,no_side_effects=False,now=12)
        self.ledger.release_unwritten('pool','x',epoch=1,no_side_effects=True,now=13)
        self.assertEqual(self.ledger.status('pool',now=14)['available']['write_bytes'],100)
        with self.assertRaises(q.QuotaError):self.ledger.reserve('pool','x',amount(write=80,storage=80,wops=1),epoch=1,ttl=20,now=14)

    def test_clock_rollback_rejected(self):
        self.ledger.status('pool',now=100)
        with self.assertRaises(q.QuotaError):self.ledger.status('pool',now=99)

    def test_failed_reservation_is_atomic(self):
        with self.assertRaises(q.QuotaError):self.ledger.reserve('pool','bad',amount(write=101,wops=1),epoch=1,ttl=10,now=11)
        self.assertEqual(self.ledger.status('pool',now=12)['available']['write_bytes'],100)

    def test_invalid_parent_permissions_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(q.QuotaError):q.Ledger(self.root/'another.db')

    def test_uncertain_reconciliation_committed_debits_once(self):
        self.ledger.reserve('pool','a',amount(write=10,storage=10,wops=1),epoch=1,ttl=20,now=11)
        self.ledger.uncertain('pool','a',epoch=1,now=12)
        self.assertEqual(self.ledger.reconcile('pool','a',epoch=1,outcome='COMMITTED',confirmed=True,now=13),'COMMITTED')
        with self.assertRaises(q.QuotaError):self.ledger.reconcile('pool','a',epoch=1,outcome='COMMITTED',confirmed=True,now=14)
        self.assertEqual(self.ledger.status('pool',now=14)['available']['write_bytes'],90)

if __name__=='__main__':unittest.main()

class LedgerRenewalTests(unittest.TestCase):
    def test_renewal_survives_restart_and_blocks_old_epoch(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root);path.chmod(0o700)
            ledger=q.Ledger(path/'db')
            ledger.enroll('p',amount(write=100,wops=10),epoch=1,now=10)
            ledger.reserve('p','x',amount(write=10,wops=1),epoch=1,ttl=5,now=11)
            self.assertEqual(ledger.renew('p','x',epoch=1,ttl=20,now=12),32)
            reopened=q.Ledger(path/'db')
            reopened.require_active('p','x',epoch=1,now=16)
            reopened.fence('p',1,2,now=17)
            with self.assertRaises(q.QuotaError):reopened.renew('p','x',epoch=1,ttl=5,now=18)
            with self.assertRaises(q.QuotaError):reopened.require_active('p','x',epoch=1,now=18)
