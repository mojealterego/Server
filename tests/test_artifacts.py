"""Red/green behavioral tests for durable, content-addressed artifacts."""
from __future__ import annotations
import concurrent.futures
import hashlib
from pathlib import Path
import tempfile
import unittest
from atlas.artifacts import ArtifactStore, ArtifactError
from atlas.phaseshift import compile_workflow
from atlas.phaselease import LeaseStore, LeaseError

CAT = {'m': {'bytes':100, 'format':'gguf','role':'llm','lineage_verified':True}}
NODES = [{'id':'phone','trust':'local','capabilities':['llama'],'models':['m'],
          'ram_available_mb':1024,'ram_headroom_mb':128,'disk_free_bytes':1000000,
          'thermal_c':34, 'priority':0}]
JOBS = [{'id':'one','engine':'llama','models':['m'],'ram_mb':100,'duration_slots':1,
         'output_bytes':100,'privacy':'local_only'},
        {'id':'two','engine':'llama','models':['m'],'ram_mb':100,'duration_slots':1,
         'output_bytes':100,'privacy':'local_only','depends_on':['one']}]

class ArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ArtifactStore(self.root/'cas')
        self.source = self.root/'input.bin'
        self.source.write_bytes(b'proof-carrying checkpoints')
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def test_put_verify_restore_byte_identical(self):
        receipt=self.store.put(self.source)
        self.assertEqual(receipt['sha256'], self.digest)
        self.assertEqual(receipt['size_bytes'],self.source.stat().st_size)
        self.assertTrue(self.store.verify(self.digest))
        dest=self.root/'recovered.bin'
        self.store.restore(self.digest,dest)
        self.assertEqual(dest.read_bytes(),self.source.read_bytes())

    def test_repeated_put_idempotent(self):
        a=self.store.put(self.source)
        b=self.store.put(self.source)
        self.assertEqual(a,b)
        self.assertEqual(len(list((self.root/'cas'/'objects').iterdir())),1)

    def test_reject_corrupt_cas_object(self):
        self.store.put(self.source)
        (self.root/'cas'/'objects'/self.digest).write_bytes(b'malicious')
        with self.assertRaises(ArtifactError): self.store.verify(self.digest)
        with self.assertRaises(ArtifactError): self.store.restore(self.digest,self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_no_symlink_source_or_object(self):
        symlink=self.root/'link';symlink.symlink_to(self.source)
        with self.assertRaises(ArtifactError):self.store.put(symlink)
        (self.root/'cas'/'objects'/self.digest).symlink_to(self.source)
        with self.assertRaises(ArtifactError):self.store.put(self.source)

    def test_reject_preexisting_output_and_preserve_it(self):
        self.store.put(self.source)
        dest=self.root/'out';dest.write_bytes(b'keep')
        with self.assertRaises(ArtifactError):self.store.restore(self.digest,dest)
        self.assertEqual(dest.read_bytes(),b'keep')

    def test_size_limit_and_invalid_digests(self):
        with self.assertRaises(ArtifactError):self.store.put(self.source,max_bytes=3)
        self.assertEqual(list((self.root/'cas'/'objects').iterdir()),[])
        for invalid in ('../x','A'*64,'c'*63,'g'*64):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ArtifactError): self.store.verify(invalid)

    def test_concurrent_ingest_same_content(self):
        def ingest(_): return self.store.put(self.source)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            receipts=list(pool.map(ingest,range(10)))
        self.assertTrue(all(x==receipts[0] for x in receipts))
        self.assertEqual(len(list((self.root/'cas'/'objects').iterdir())),1)

    def test_lease_completes_from_durable_cas_after_source_removed(self):
        doc=compile_workflow(JOBS,NODES,CAT,horizon=3)
        with LeaseStore(self.root/'lease.sqlite',doc,JOBS,NODES,CAT,artifacts=self.store) as leases:
            a=leases.claim('one','phone',now=100,ttl=60)
            leases.complete('one','phone',a['token'],a['epoch'],self.source,now=101)
            self.source.unlink()
            self.assertTrue(self.store.verify(self.digest))
            self.assertEqual(leases.claim('two','phone',now=102,ttl=60)['epoch'],1)

    def test_lease_refuses_corrupted_predecessor(self):
        doc=compile_workflow(JOBS,NODES,CAT,horizon=3)
        with LeaseStore(self.root/'lease.sqlite',doc,JOBS,NODES,CAT,artifacts=self.store) as leases:
            a=leases.claim('one','phone',now=100,ttl=60)
            leases.complete('one','phone',a['token'],a['epoch'],self.source,now=101)
            (self.root/'cas'/'objects'/self.digest).write_bytes(b'broken')
            with self.assertRaises(LeaseError): leases.claim('two','phone',now=102,ttl=60)

if __name__=='__main__':unittest.main()
