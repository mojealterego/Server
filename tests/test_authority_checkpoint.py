"""E20a regression: signed, pinned namespace checkpoints against real SQLite/WAL."""
from __future__ import annotations
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from atlas.authority_checkpoint import (AuditError, append, verify, snapshot, ZERO)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name);self.db=self.root/'namespace.sqlite';self.audit=self.root/'audit'
        self.audit.mkdir(mode=0o700);self.key=self.root/'signer.key'
        signer=Ed25519PrivateKey.generate();self.pub=signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.key.write_bytes(signer.private_bytes(Encoding.Raw, PrivateFormat.Raw,NoEncryption()))
        self.key.chmod(0o600)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executescript('''
             CREATE TABLE authority(id INTEGER PRIMARY KEY,epoch INTEGER,generation INTEGER);
             INSERT INTO authority VALUES(1,1,1);
             CREATE TABLE entries(tenant TEXT,key TEXT,path TEXT,manifest_sha256 TEXT,archive_sha256 TEXT,
                 policy_sha256 TEXT,size_bytes INTEGER,revision INTEGER,deleted INTEGER,
                 PRIMARY KEY(tenant,key));
             CREATE TABLE operations(tenant TEXT,operation_id TEXT,epoch INTEGER,request_sha256 TEXT,
                 receipt TEXT,PRIMARY KEY(tenant,operation_id));
            ''')
            db.execute('INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?)',('alice','f/a.gguf','f/a.gguf','a'*64,'b'*64,'c'*64,456,1,0))
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',('alice','op1',1,'d'*64,'{}'))
        self.db.chmod(0o600)
    def emit(self,tip=ZERO,now=100):
        return append(self.db,self.audit,tenant='alice',key_path=self.key,expected_tip=tip,now=now)
    def test_verified_history_reports_signed_tenant_without_database(self):
        receipt=self.emit()
        verified=verify(self.audit,self.pub,receipt['digest'])
        self.assertEqual(verified['tenant'],'alice')
        self.assertEqual(verified['status'],'CHAIN_VALID')

    def test_empty_chain_cannot_qualify_as_verified_recovery(self):
        with self.assertRaises(AuditError):
            verify(self.audit,self.pub,ZERO)

    def test_first_signed_and_externally_pinned(self):
        receipt=self.emit();self.assertEqual(receipt['sequence'],1)
        self.assertEqual(len(receipt['digest']),64)
        self.assertEqual(verify(self.audit,self.pub,receipt['digest'],db_path=self.db,tenant='alice')['status'],'MATCH')
    def test_wrong_external_pin_prevents_false_success(self):
        r=self.emit()
        with self.assertRaises(AuditError):verify(self.audit,self.pub,'f'*64)
        with self.assertRaises(AuditError):self.emit('e'*64)
        self.assertEqual(verify(self.audit,self.pub,r['digest'])['status'],'CHAIN_VALID')
    def test_tampered_receipt_detected(self):
        r=self.emit();p=next(self.audit.glob('*.json'));data=json.loads(p.read_text());data['generation']=99
        p.write_text(json.dumps(data));
        with self.assertRaises(AuditError):verify(self.audit,self.pub,r['digest'])
    def test_forged_signer_rejected(self):
        r=self.emit();other=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        with self.assertRaises(AuditError):verify(self.audit,other,r['digest'])
    def test_db_rollback_or_changed_object_detected(self):
        r=self.emit()
        with closing(sqlite3.connect(self.db)) as db, db:db.execute('UPDATE entries SET archive_sha256=? WHERE tenant=?',('e'*64,'alice'))
        with self.assertRaises(AuditError):verify(self.audit,self.pub,r['digest'],db_path=self.db,tenant='alice')
    def test_append_monotonic_generation_and_prev_hash(self):
        a=self.emit()
        with self.assertRaises(AuditError):self.emit(a['digest'],now=101)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE authority SET generation=2')
            db.execute('UPDATE entries SET size_bytes=999')
        b=self.emit(a['digest'],now=102)
        self.assertEqual(b['sequence'],2)
        self.assertEqual(verify(self.audit,self.pub,b['digest'],db_path=self.db,tenant='alice')['length'],2)
        with self.assertRaises(AuditError):verify(self.audit,self.pub,a['digest'])
    def test_epoch_rollback_rejected_even_with_larger_generation(self):
        a=self.emit()
        with closing(sqlite3.connect(self.db)) as db, db:db.execute('UPDATE authority SET epoch=0,generation=8')
        with self.assertRaises(AuditError):self.emit(a['digest'])
    def test_symlink_receipt_and_nonprivate_key_rejected(self):
        self.key.chmod(0o644)
        with self.assertRaises(AuditError):self.emit()
        self.key.chmod(0o600)
        self.audit.joinpath('00000000000000000001-'+'0'*64+'.json').symlink_to(self.key)
        with self.assertRaises(AuditError):verify(self.audit,self.pub,ZERO)
    def test_reject_unexpected_extra_audit_file(self):
        r=self.emit();(self.audit/'rogue').write_text('x')
        with self.assertRaises(AuditError):verify(self.audit,self.pub,r['digest'])
    def test_partial_external_write_fails_closed(self):
        r=self.emit();p=next(self.audit.glob('*.json'));p.write_bytes(b'{')
        with self.assertRaises(AuditError):self.emit(r['digest'])
    def test_concurrent_append_single_sequence(self):
        results=[];errors=[]
        def worker():
            try:results.append(self.emit())
            except AuditError as ex:errors.append(str(ex))
        threads=[threading.Thread(target=worker) for _ in range(6)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(len(results),1);self.assertEqual(len(errors),5)
    def test_actual_cli_process_and_current_snapshot(self):
        cmd=[sys.executable,'-m','atlas.authority_checkpoint','--db',str(self.db),'--dir',str(self.audit),'--tenant','alice']
        run=subprocess.run(cmd+['append','--key',str(self.key),'--expected-tip',ZERO,'--now','125'],capture_output=True,text=True,timeout=15)
        self.assertEqual(run.returncode,0,run.stderr);digest=json.loads(run.stdout)['digest']
        r=subprocess.run(cmd+['verify','--public-key',self.pub.hex(),'--tip',digest,'--match-current'],capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['status'],'MATCH')
    def test_wrong_tenant_never_exposes_namespace(self):
        r=self.emit();
        with self.assertRaises(AuditError):verify(self.audit,self.pub,r['digest'],db_path=self.db,tenant='bob')
    def test_database_snapshot_does_not_read_entire_sqlite_file(self):
        from unittest.mock import patch
        original=os.read
        def bounded(fd,count):
            self.assertLessEqual(count,MAX_SAFE_READ)
            return original(fd,count)
        MAX_SAFE_READ=8192
        with patch('atlas.authority_checkpoint.os.read',side_effect=bounded):
            result=snapshot(self.db,'alice')
        self.assertEqual(result['epoch'],1)

    def test_snapshot_closes_sqlite_handles_under_repeated_queries(self):
        import gc
        fds=Path('/proc/self/fd')
        if not fds.exists():self.skipTest('Linux proc fd inspection unavailable')
        before=len(list(fds.iterdir()))
        enabled=gc.isenabled()
        gc.disable()
        try:
            for _ in range(40):snapshot(self.db,'alice')
            self.assertLessEqual(len(list(fds.iterdir())),before+2)
        finally:
            if enabled:gc.enable()
            gc.collect()

    def test_reader_not_writable(self):
        x=snapshot(self.db,'alice')
        self.assertEqual(x['epoch'],1);self.assertEqual(x['generation'],1)
        self.assertIn('entries_sha256',x);self.assertIn('operations_sha256',x)

if __name__=='__main__':unittest.main()
