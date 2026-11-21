"""E16a: deterministic safety and concurrency properties of namespace metadata."""
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from atlas.global_namespace import Namespace, NamespaceError

PIN = 'a' * 64
HASH = 'b' * 64
POLICY = 'c' * 64

class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.db = self.root / 'namespace.sqlite'
        self.ns = Namespace(self.db, tenant='team-a')
        self.addCleanup(self.ns.close)

    def put(self, name='models/vision.gguf', *, op='op-001', rev=0, size=91):
        return self.ns.put(name, PIN, HASH, POLICY, size, epoch=1,
                           expected_revision=rev, operation_id=op)

    def test_put_read_and_idempotent_replay(self):
        a = self.put()
        self.assertEqual(a['revision'], 1)
        self.assertEqual(self.put(), a)
        self.assertEqual(self.ns.get('models/vision.gguf')['manifest_sha256'], PIN)
        self.assertEqual(self.ns.status()['generation'], 1)

    def test_conflicting_reuse_of_operation_id_refused(self):
        self.put()
        with self.assertRaises(NamespaceError): self.put(size=92)

    def test_compare_and_swap_stale_writer(self):
        a = self.put()
        with self.assertRaises(NamespaceError): self.put(op='op-002', rev=0)
        b = self.put(op='op-003', rev=a['revision'], size=123)
        self.assertEqual(b['revision'], 2)
        with self.assertRaises(NamespaceError): self.put(op='op-004', rev=1)

    def test_delete_preserves_tombstone_and_rejects_stale_recreate(self):
        self.put()
        deleted = self.ns.delete('models/vision.gguf', epoch=1, expected_revision=1,
                                 operation_id='op-delete')
        self.assertEqual(deleted['revision'], 2)
        self.assertIsNone(self.ns.get('models/vision.gguf'))
        with self.assertRaises(NamespaceError): self.put(op='recreate-stale')
        self.assertEqual(self.put(op='recreate-new', rev=2)['revision'], 3)

    def test_atomic_rename_and_no_overwrite(self):
        self.put()
        moved = self.ns.rename('models/vision.gguf','models/vision-v2.gguf',
                               epoch=1, expected_revision=1, operation_id='op-move')
        self.assertEqual(moved['revision'], 1)
        self.assertEqual(self.ns.rename('models/vision.gguf','models/vision-v2.gguf',
                               epoch=1, expected_revision=1, operation_id='op-move'),moved)
        self.assertIsNone(self.ns.get('models/vision.gguf'))
        self.assertEqual(self.ns.get('models/vision-v2.gguf')['size_bytes'],91)
        with self.assertRaises(NamespaceError):
            self.ns.rename('models/vision-v2.gguf','models/vision.gguf',epoch=1,
                           expected_revision=1,operation_id='second-move')

    def test_fencing_revokes_stale_leader(self):
        self.put()
        self.assertEqual(self.ns.fence(expected_epoch=1,new_epoch=2),2)
        with self.assertRaises(NamespaceError): self.put(op='old',rev=1)
        self.assertEqual(self.ns.put('models/vision.gguf',PIN,HASH,POLICY,33,
                       epoch=2,expected_revision=1,operation_id='new')['revision'],2)
        with self.assertRaises(NamespaceError):self.ns.fence(expected_epoch=1,new_epoch=3)

    def test_private_tenant_view(self):
        self.put()
        other=Namespace(self.db,tenant='team-b')
        try:
            self.assertIsNone(other.get('models/vision.gguf'))
            other.put('models/vision.gguf','d'*64,HASH,POLICY,200,epoch=1,
                      expected_revision=0,operation_id='b-1')
            self.assertEqual(other.get('models/vision.gguf')['size_bytes'],200)
            self.assertEqual(self.ns.get('models/vision.gguf')['size_bytes'],91)
        finally: other.close()

    def test_case_insensitive_path_collision(self):
        self.put()
        with self.assertRaises(NamespaceError):self.put('MODELS/VISION.GGUF',op='conflict')

    def test_path_and_pin_validation(self):
        bad=['/absolute','../secret','a/../secret','a//b','a/./b','x\\y','x\ny','x\x00y','.hidden','x/'+('a'*256),'CON.txt','LPT1','a/trailing.']
        for path in bad:
            with self.subTest(path=path),self.assertRaises(NamespaceError): self.put(path,op='invalid-path')
        with self.assertRaises(NamespaceError):self.ns.put('ok',PIN.upper(),HASH,POLICY,1,epoch=1,expected_revision=0,operation_id='invalid-hash')
        with self.assertRaises(NamespaceError):self.ns.put('ok',PIN,HASH,POLICY,True,epoch=1,expected_revision=0,operation_id='invalid-size')

    def test_concurrent_cas_single_winner(self):
        self.put()
        def worker(i):
            with Namespace(self.db,tenant='team-a') as ns:
                try:return ns.put('models/vision.gguf',PIN,HASH,POLICY,100+i,
                                   epoch=1,expected_revision=1,operation_id=f'race-{i}')['revision']
                except NamespaceError:return None
        with ThreadPoolExecutor(max_workers=6) as pool: result=list(pool.map(worker,range(6)))
        self.assertEqual(result.count(2),1)
        self.assertEqual(result.count(None),5)

    def test_symlink_db_and_permissions_denied(self):
        target=self.root/'target';target.write_text('safe')
        link=self.root/'alias';link.symlink_to(self.db)
        with self.assertRaises(NamespaceError):Namespace(link,tenant='team-a')
        self.root.chmod(0o755)
        with self.assertRaises(NamespaceError):Namespace(self.db,tenant='team-a')

    def test_listing_stable_order_and_pagination(self):
        self.put()
        for i,name in enumerate(['c','a','b']):self.put(name,op=f'add-{i}')
        self.assertEqual([r['path'] for r in self.ns.list(limit=2)],['a','b'])
        self.assertEqual([r['path'] for r in self.ns.list(limit=2,after='b')],['c','models/vision.gguf'])
        with self.assertRaises(NamespaceError):self.ns.list(limit=0)

if __name__ == '__main__': unittest.main()
