import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from atlas.artifacts import ArtifactStore
from atlas.replication import Replica, ReplicationError, push, pull, CHUNK

FAKE = '''#!/usr/bin/env python3
import os,sys,pathlib
root=pathlib.Path(os.environ['FAKE_ROOT'])
cmd,*args=sys.argv[1:]
def remote(s):
    a,b=s.split(':',1);return root/a/b
if cmd=='cat':
    p=remote(args[0]);sys.stdout.buffer.write(p.read_bytes()) if p.is_file() else sys.exit(3)
elif cmd=='copyto':
    src=pathlib.Path(args[0]);p=remote(args[1]);p.parent.mkdir(parents=True,exist_ok=True)
    if os.environ.get('FAKE_FAIL')==p.name:sys.exit(9)
    if p.exists() and p.read_bytes()!=src.read_bytes():sys.exit(8)
    p.write_bytes(src.read_bytes())
    with (root/'writes').open('a') as f:f.write(str(p.relative_to(root))+'\\n')
else:sys.exit(2)
'''

class ReplicationTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup);self.root=Path(d.name)
        self.fake=self.root/'rclone';self.fake.write_text(FAKE);self.fake.chmod(0o700)
        self.env={**os.environ,'FAKE_ROOT':str(self.root)}
        self.a=Replica('one:vault',rclone=str(self.fake),env=self.env,timeout=10)
        self.b=Replica('two:vault',rclone=str(self.fake),env=self.env,timeout=10)
        self.src=ArtifactStore(self.root/'src');self.dst=ArtifactStore(self.root/'dst')
        self.payload=b'A'*CHUNK+b'B'*CHUNK+b'end'
        self.file=self.root/'input';self.file.write_bytes(self.payload)
        self.sha=self.src.put(self.file)['sha256']
        self.blocks=[hashlib.sha256(x).hexdigest() for x in (b'A'*CHUNK,b'B'*CHUNK,b'end')]
    def block(self,remote,h):return self.root/remote/'vault'/'blocks'/h
    def manifest(self,remote):return self.root/remote/'vault'/'manifests'/(self.sha+'.json')
    def test_roundtrip_two_targets(self):
        info=push(self.src,self.sha,[self.a,self.b]);self.assertEqual(len(info['replicas']),2)
        r=pull(self.dst,self.sha,info['manifest_sha256'],[self.a,self.b])
        self.assertEqual(r['copied_chunks'],3);self.assertTrue(self.dst.verify(self.sha))
        self.assertEqual((self.dst.objects/self.sha).read_bytes(),self.payload)
        self.assertEqual(pull(self.dst,self.sha,info['manifest_sha256'],[self.a])['status'],'ALREADY_PRESENT')
    def test_repeated_push_skips_all_writes(self):
        push(self.src,self.sha,[self.a]);before=(self.root/'writes').read_text()
        result=push(self.src,self.sha,[self.a]);self.assertEqual(result['replicas'][0]['uploaded_blocks'],0)
        self.assertEqual((self.root/'writes').read_text(),before)
    def test_missing_or_corrupt_block_failover(self):
        info=push(self.src,self.sha,[self.a,self.b]);self.block('one',self.blocks[0]).unlink()
        self.block('one',self.blocks[1]).write_bytes(b'bad')
        self.manifest('one').write_bytes(b'bad')
        r=pull(self.dst,self.sha,info['manifest_sha256'],[self.a,self.b]);self.assertTrue(self.dst.verify(self.sha));self.assertEqual(r['copied_chunks'],3)
    def test_partial_download_resume(self):
        info=push(self.src,self.sha,[self.a]);p=self.block('one',self.blocks[1]);data=p.read_bytes();p.unlink()
        with self.assertRaises(ReplicationError):pull(self.dst,self.sha,info['manifest_sha256'],[self.a])
        self.assertFalse((self.dst.objects/self.sha).exists());p.write_bytes(data)
        r=pull(self.dst,self.sha,info['manifest_sha256'],[self.a]);self.assertEqual(r['reused_chunks'],1);self.assertEqual(r['copied_chunks'],2)
    def test_interrupted_upload_manifest_last(self):
        failing=Replica('one:vault',rclone=str(self.fake),env={**self.env,'FAKE_FAIL':self.blocks[1]},timeout=10)
        with self.assertRaises(ReplicationError):push(self.src,self.sha,[failing])
        self.assertFalse(self.manifest('one').exists());self.assertTrue(self.block('one',self.blocks[0]).exists())
        result=push(self.src,self.sha,[self.a]);self.assertEqual(result['replicas'][0]['uploaded_blocks'],2)
    def test_pin_mismatch_fails_closed(self):
        push(self.src,self.sha,[self.a]);
        with self.assertRaises(ReplicationError):pull(self.dst,self.sha,'0'*64,[self.a])
        self.assertFalse((self.dst.objects/self.sha).exists())
    def test_corrupt_existing_remote_not_overwritten(self):
        push(self.src,self.sha,[self.a]);p=self.block('one',self.blocks[0]);p.write_bytes(b'bad')
        with self.assertRaises(ReplicationError):push(self.src,self.sha,[self.a])
        self.assertEqual(p.read_bytes(),b'bad')
    def test_local_corruption_never_exported(self):
        (self.src.objects/self.sha).write_bytes(b'bad')
        with self.assertRaises(ValueError):push(self.src,self.sha,[self.a])
        self.assertFalse((self.root/'writes').exists())
    def test_oversize_response(self):
        push(self.src,self.sha,[self.a]);
        with self.assertRaises(ReplicationError):self.a.read('blocks/'+self.blocks[0],16)
    def test_bad_remote_or_duplicate(self):
        for s in ('-evil:x','a:../b','a:/x','a:','a:foo//bar','a:foo/..'):
            with self.subTest(s=s),self.assertRaises(ValueError):Replica(s)
        with self.assertRaises(ValueError):push(self.src,self.sha,[self.a,self.a])
    def test_empty_object(self):
        self.file.write_bytes(b'');h=self.src.put(self.file)['sha256'];i=push(self.src,h,[self.a]);pull(self.dst,h,i['manifest_sha256'],[self.a]);self.assertTrue(self.dst.verify(h))
    def test_dedup_across_objects(self):
        push(self.src,self.sha,[self.a]);self.file.write_bytes(b'A'*CHUNK+b'new');h=self.src.put(self.file)['sha256'];i=push(self.src,h,[self.a]);self.assertEqual(i['replicas'][0]['uploaded_blocks'],1)
