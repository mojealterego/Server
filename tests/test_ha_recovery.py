import hashlib
from contextlib import closing
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from atlas.ha_checkpoint import capture, recover, CheckpointError

class CheckpointTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.db=self.root/'leases';self.replay=self.root/'replay';self.cas=self.root/'cas';self.cas.mkdir(mode=0o700);(self.cas/'objects').mkdir(mode=0o700)
        self.blob=b'finished output';self.sha=hashlib.sha256(self.blob).hexdigest();(self.cas/'objects'/self.sha).write_bytes(self.blob);(self.cas/'objects'/self.sha).chmod(0o600)
        self.conn=sqlite3.connect(self.db);self.addCleanup(self.conn.close);self.db.chmod(0o600);self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.executescript('CREATE TABLE leases(plan_hash TEXT,task_id TEXT,node_id TEXT,epoch INTEGER,token_hash TEXT,expires_at REAL,state TEXT,output_sha256 TEXT,reserved_ram_mb INTEGER,last_error TEXT,PRIMARY KEY(plan_hash,task_id));CREATE TABLE node_registry(node_id TEXT PRIMARY KEY,ram_capacity_mb INTEGER,disk_free_bytes INTEGER,trust TEXT);CREATE TABLE retired_plans(plan_hash TEXT PRIMARY KEY,successor_hash TEXT,payload TEXT);CREATE TABLE attempt_limits(plan_hash TEXT PRIMARY KEY,root_hash TEXT,max_attempts INTEGER);')
        self.conn.execute('INSERT INTO leases VALUES(?,?,?,?,?,?,?,?,?,?)',('p','done','phone',2,'token',0,'COMPLETED',self.sha,0,None));self.conn.execute("INSERT INTO attempt_limits VALUES('p','p',3)"); self.conn.commit()
        r=sqlite3.connect(self.replay);r.execute('CREATE TABLE accepted(node TEXT PRIMARY KEY,issued_ns INTEGER NOT NULL)');r.execute("INSERT INTO accepted VALUES('phone',42)");r.commit();r.close();self.replay.chmod(0o600)
    def capture(self):return capture(self.db,self.replay,self.cas,self.root/'bundle',quiesced=True)
    def test_wal_backup_and_recover(self):
        r=self.capture(); out=recover(self.root/'bundle',r['sha256'],self.root/'standby',fenced=True,no_newer_state=True)
        self.assertEqual(out['status'],'RECOVERED_OFFLINE');p=self.root/'standby';self.assertEqual((p/'cas/objects'/self.sha).read_bytes(),self.blob)
        with closing(sqlite3.connect(p/'leases.db')) as c:self.assertEqual(c.execute('SELECT epoch,state FROM leases').fetchone(),(2,'COMPLETED'));self.assertEqual(c.execute('SELECT max_attempts FROM attempt_limits').fetchone(),(3,))
        with closing(sqlite3.connect(p/'replay.db')) as c:self.assertEqual(c.execute('SELECT issued_ns FROM accepted').fetchone(),(42,))
    def test_active_lease_refused(self):
        self.conn.execute("UPDATE leases SET state='LEASED',expires_at=?,output_sha256=NULL",(time.time()+100,));self.conn.commit()
        with self.assertRaises(CheckpointError):self.capture()
        self.assertFalse((self.root/'bundle').exists())
    def test_expired_lease_invalidated(self):
        self.conn.execute("UPDATE leases SET state='LEASED',expires_at=0,output_sha256=NULL");self.conn.commit();r=self.capture();recover(self.root/'bundle',r['sha256'],self.root/'standby',fenced=True,no_newer_state=True)
        with closing(sqlite3.connect(self.root/'standby/leases.db')) as c:self.assertEqual(c.execute('SELECT epoch,state,last_error FROM leases').fetchone(),(2,'FAILED','PROCESS_FAILED'))
    def test_corrupt_or_missing_object(self):
        (self.cas/'objects'/self.sha).write_bytes(b'bad')
        with self.assertRaises(ValueError):self.capture()
        self.assertFalse((self.root/'bundle').exists())
    def test_corrupt_backup_and_wrong_pin(self):
        r=self.capture();b=self.root/'bundle';d=self.root/'standby'
        with self.assertRaises(ValueError):recover(b,'0'*64,d,fenced=True,no_newer_state=True)
        (b/'cas/objects'/self.sha).write_bytes(b'tampered')
        with self.assertRaises(ValueError):recover(b,r['sha256'],d,fenced=True,no_newer_state=True)
        self.assertFalse(d.exists())
    def test_no_overwrite_and_explicit_fence(self):
        r=self.capture();b=self.root/'bundle';d=self.root/'standby'
        with self.assertRaises(ValueError):recover(b,r['sha256'],d,fenced=False,no_newer_state=True)
        with self.assertRaises(ValueError):recover(b,r['sha256'],d,fenced=True,no_newer_state=False)
        d.mkdir();(d/'keep').write_text('keep')
        with self.assertRaises(FileExistsError):recover(b,r['sha256'],d,fenced=True,no_newer_state=True)
        self.assertEqual((d/'keep').read_text(),'keep')
    def test_symlink_db_refused(self):
        p=self.root/'ln';p.symlink_to(self.db)
        with self.assertRaises(ValueError):capture(p,self.replay,self.cas,self.root/'bundle',quiesced=True)
    def test_checkpoint_denied_while_authority_active(self):
        from atlas.ha_authority import authority, AuthorityBusy
        with authority(self.db):
            with self.assertRaises(AuthorityBusy):self.capture()
        self.assertFalse((self.root/'bundle').exists())
    def test_cryptographic_replay_preserved(self):
        import subprocess
        from tools.capctl import sign, admit, CapabilityError
        from atlas.artifacts import ArtifactStore
        key=self.root/'key';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        node={'id':'phone','ram_available_mb':100,'ram_headroom_mb':1,'disk_free_bytes':100,'thermal_c':30,'capabilities':['llama'],'models':['q']}
        stamp=time.time_ns();env=sign(node,key,stamp);policy={'phone':{'public_key':env['public_key'],'trust':'trusted','priority':1,'max_ram_mb':100,'min_headroom_mb':1,'max_disk_bytes':100,'capabilities':['llama'],'models':['q']}}
        admit([env],policy,self.replay,now_ns=stamp);r=self.capture();recover(self.root/'bundle',r['sha256'],self.root/'standby',fenced=True,no_newer_state=True)
        with self.assertRaises(CapabilityError):admit([env],policy,self.root/'standby/replay.db',now_ns=stamp)
        self.assertTrue(ArtifactStore(self.root/'standby/cas').verify(self.sha))
        self.assertEqual(admit([sign(node,key,stamp+1)],policy,self.root/'standby/replay.db',now_ns=stamp+1)[0]['id'],'phone')
