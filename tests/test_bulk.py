import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from atlas.artifacts import ArtifactStore
from atlas.replication import Replica, Missing, ReplicationError, push, pull, CHUNK

class MemoryReplica(Replica):
    def __init__(self, root):
        super().__init__(root); self.data={}; self.lock=threading.Lock(); self.active=0; self.peak=0; self.writes=[]; self.barrier=None
    def ensure(self,key,data):
        if key.startswith('blocks/') and self.barrier:
            with self.lock:self.active+=1;self.peak=max(self.peak,self.active)
            self.barrier.wait(timeout=5)
            with self.lock:self.active-=1
        with self.lock:
            if key in self.data:
                if self.data[key]!=data:raise ReplicationError('conflict')
                return False
            self.data[key]=data;self.writes.append(key);return True
    def read(self,key,limit):
        if key.startswith('blocks/') and self.barrier:
            with self.lock:self.active+=1;self.peak=max(self.peak,self.active)
            self.barrier.wait(timeout=5)
            with self.lock:self.active-=1
        with self.lock:
            if key not in self.data:raise Missing('missing')
            return self.data[key]

class BulkTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.src=ArtifactStore(self.root/'src');self.dst=ArtifactStore(self.root/'dst');self.a=MemoryReplica('a:vault');self.b=MemoryReplica('b:vault')
        self.p=self.root/'input';self.p.write_bytes(b'a'*CHUNK+b'b'*CHUNK);self.sha=self.src.put(self.p)['sha256']
    def test_parallel_push_pull(self):
        self.a.barrier=threading.Barrier(2);r=push(self.src,self.sha,[self.a],workers=2);self.assertEqual(self.a.peak,2);self.assertTrue(self.a.writes[-1].startswith('manifests/'))
        self.a.peak=0;r=pull(self.dst,self.sha,r['manifest_sha256'],[self.a],workers=2);self.assertEqual(self.a.peak,2);self.assertEqual(r['copied_chunks'],2);self.assertTrue(self.dst.verify(self.sha))
    def test_duplicate_blocks_only_once(self):
        self.p.write_bytes(b'a'*CHUNK*3);sha=self.src.put(self.p)['sha256'];r=push(self.src,sha,[self.a],workers=4);self.assertEqual(r['replicas'][0]['uploaded_blocks'],1);self.assertEqual(len(self.a.writes),2)
    def test_resume_and_failover(self):
        r=push(self.src,self.sha,[self.a,self.b],workers=2);key='blocks/'+hashlib.sha256(b'b'*CHUNK).hexdigest();good=self.b.data.pop(key);self.a.data[key]=b'bad'
        with self.assertRaises(ReplicationError):pull(self.dst,self.sha,r['manifest_sha256'],[self.a,self.b],workers=2)
        self.assertFalse(self.dst._path(self.sha).exists());self.b.data[key]=good
        out=pull(self.dst,self.sha,r['manifest_sha256'],[self.a,self.b],workers=2);self.assertEqual(out['reused_chunks'],1);self.assertTrue(self.dst.verify(self.sha))
    def test_failed_push_no_manifest(self):
        self.a.data['blocks/'+hashlib.sha256(b'b'*CHUNK).hexdigest()]=b'bad'
        with self.assertRaises(ReplicationError):push(self.src,self.sha,[self.a],workers=2)
        self.assertFalse(any(k.startswith('manifests/') for k in self.a.data))
    def test_limits(self):
        for w in (0,9,True,1.5):
            with self.assertRaises(ValueError):push(self.src,self.sha,[self.a],workers=w)
            with self.assertRaises(ValueError):pull(self.dst,self.sha,'0'*64,[self.a],workers=w)
