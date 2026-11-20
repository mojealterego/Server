import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from atlas import capacity_fabric as capacity
from atlas import pooled_archive as archive

M = 1024**2
NOW = 1800000000
HOST = 'test-host'


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.a = self.root/'a'; self.a.mkdir(mode=0o700)
        self.raw = b'x'*M+b'x'*M+b'end'
        self.src = self.root/'source'; self.src.write_bytes(self.raw)
        self.manifest = self.root/'manifest.json'
        self.dest = self.root/'restored'

    def row(self, name, root):
        p = capacity.probe_local(root, HOST, NOW)
        return dict(id=name,pool=p['pool'],domain=name,kind='local',
                    limit_bytes=16*M,used_bytes=0,reserve_bytes=M,
                    write_budget_bytes=16*M,read_budget_bytes=16*M,block_budget=16,
                    observed_at=NOW,authorized=True,zero_cost=True)

    def policy(self, roots, copies=1):
        return dict(schema='omega.capacity.v1',copies=copies,chunk_bytes=M,
                    max_age_seconds=60,pools=[self.row(name,root) for name,root in roots.items()])

    def ingest(self, roots=None, copies=1):
        roots=roots or {'a':self.a}; policy=self.policy(roots,copies)
        proposal=capacity.plan(policy,len(self.raw),NOW)
        return archive.ingest(self.src,self.manifest,policy,proposal,roots,HOST,NOW)

    def two_mounts(self):
        if not Path('/dev/shm').is_dir() or os.stat('/dev/shm').st_dev==self.a.stat().st_dev:
            self.skipTest('test needs a second mounted filesystem')
        t=tempfile.TemporaryDirectory(dir='/dev/shm');self.addCleanup(t.cleanup)
        return {'a':self.a,'b':Path(t.name)}

    def test_real_roundtrip_and_deduplicated_blocks(self):
        result=self.ingest()
        files=list((self.a/'objects').iterdir())
        self.assertEqual(len(files),2)
        self.assertEqual(result['sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(archive.restore(self.manifest,result['manifest_sha256'],self.dest,{'a':self.a},HOST)['sha256'],result['sha256'])
        self.assertEqual(self.dest.read_bytes(),self.raw)

    def test_real_two_mounts_and_restore_when_one_missing(self):
        roots=self.two_mounts(); result=self.ingest(roots,2)
        self.assertEqual(len(list((roots['a']/'objects').iterdir())),2)
        self.assertEqual(len(list((roots['b']/'objects').iterdir())),2)
        archive.restore(self.manifest,result['manifest_sha256'],self.dest,{'b':roots['b']},HOST)
        self.assertEqual(self.dest.read_bytes(),self.raw)

    def test_corrupt_replica_fails_over(self):
        roots=self.two_mounts();result=self.ingest(roots,2)
        (roots['a']/'objects'/hashlib.sha256(b'x'*M).hexdigest()).write_bytes(b'corrupt')
        archive.restore(self.manifest,result['manifest_sha256'],self.dest,roots,HOST)
        self.assertEqual(self.dest.read_bytes(),self.raw)

    def test_corrupt_only_replica_never_publishes(self):
        result=self.ingest();(self.a/'objects'/hashlib.sha256(b'x'*M).hexdigest()).write_bytes(b'corrupt')
        with self.assertRaises(ValueError):archive.restore(self.manifest,result['manifest_sha256'],self.dest,{'a':self.a},HOST)
        self.assertFalse(self.dest.exists())

    def test_wrong_pin_or_existing_destination(self):
        result=self.ingest()
        with self.assertRaises(ValueError):archive.restore(self.manifest,'0'*64,self.dest,{'a':self.a},HOST)
        self.dest.write_text('keep')
        with self.assertRaises(FileExistsError):archive.restore(self.manifest,result['manifest_sha256'],self.dest,{'a':self.a},HOST)
        self.assertEqual(self.dest.read_text(),'keep')

    def test_duplicate_volume_or_wrong_identity_rejected(self):
        b=self.root/'b';b.mkdir(mode=0o700)
        with self.assertRaises(ValueError):self.ingest({'a':self.a,'b':b},2)
        policy=self.policy({'a':self.a});policy['pools'][0]['pool']='false:123'
        proposal=capacity.plan(policy,len(self.raw),NOW)
        with self.assertRaises(ValueError):archive.ingest(self.src,self.manifest,policy,proposal,{'a':self.a},HOST,NOW)
        self.assertFalse(self.manifest.exists())

    def test_reject_symlink_and_remote_placement(self):
        link=self.root/'link';link.symlink_to(self.src)
        p=self.policy({'a':self.a});proposal=capacity.plan(p,len(self.raw),NOW)
        with self.assertRaises(ValueError):archive.ingest(link,self.manifest,p,proposal,{'a':self.a},HOST,NOW)
        p['pools'][0]['kind']='crypt';proposal=capacity.plan(p,len(self.raw),NOW)
        with self.assertRaises(ValueError):archive.ingest(self.src,self.manifest,p,proposal,{'a':self.a},HOST,NOW)
        self.assertFalse(self.manifest.exists())

    def test_real_free_space_guard(self):
        p=self.policy({'a':self.a});p['pools'][0]['reserve_bytes']=2**62;p['pools'][0]['limit_bytes']=2**62+16*M
        proposal=capacity.plan(p,len(self.raw),NOW)
        with self.assertRaises(ValueError):archive.ingest(self.src,self.manifest,p,proposal,{'a':self.a},HOST,NOW)
        self.assertFalse(self.manifest.exists())

    def test_manifest_no_overwrite(self):
        self.manifest.write_text('keep')
        with self.assertRaises(FileExistsError):self.ingest()
        self.assertEqual(self.manifest.read_text(),'keep')
