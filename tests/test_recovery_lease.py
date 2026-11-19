"""Regression: runtime guard failures release the SQLite reservation immediately."""
import sqlite3
import unittest
from unittest.mock import Mock
from atlas.phaselease import LeaseStore

class RecoveryLeaseTests(unittest.TestCase):
    def test_runtime_guard_failure_is_persisted(self):
        lease=LeaseStore.__new__(LeaseStore)
        lease.conn=sqlite3.connect(':memory:',isolation_level=None)
        self.addCleanup(lease.conn.close)
        lease.plan_hash='p'
        lease.conn.execute('CREATE TABLE leases (plan_hash TEXT,task_id TEXT,state TEXT,last_error TEXT,output_sha256 TEXT)')
        lease.conn.execute("INSERT INTO leases VALUES ('p','job','LEASED',NULL,NULL)")
        lease._check_owner=Mock()
        result=lease.fail('job','phone','token',1,'RUNTIME_GUARD',now=10)
        self.assertEqual(result['state'],'FAILED')
        self.assertEqual(lease.conn.execute('SELECT state,last_error FROM leases').fetchone(),('FAILED','RUNTIME_GUARD'))
        lease._check_owner.assert_called_once_with('job','phone','token',1,10.0)
