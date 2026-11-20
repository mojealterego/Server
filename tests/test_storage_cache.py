import hashlib, os, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from atlas.storage_cache import sign_manifest, verify_manifest, stage, read_range, CacheError
from tools.capctl import public

class StorageCacheTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.key=self.root/'key';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.key)],check=True);self.key.chmod(0o600)
        self.file=self.root/'model.gguf';self.data=b'x'*(4*1024*1024)+b'end';self.file.write_bytes(self.data)
        self.sha=hashlib.sha256(self.data).hexdigest();self.env=sign_manifest(self.file,self.key);self.pin=self.env['public_key']
        self.cache=self.root/'cache';self.cache.mkdir(mode=0o700)
    def run_stage(self,reader,**kw):return stage(self.env,self.pin,self.sha,self.cache,['a','b'],reader=reader,reserve_bytes=0,**kw)
    def test_signature_and_hash_pin(self):
        self.assertEqual(verify_manifest(self.env,self.pin,self.sha)['sha256'],self.sha)
        with self.assertRaises(ValueError):verify_manifest(self.env,self.pin,'0'*64)
        self.env['manifest']['filename']='changed.gguf'
        with self.assertRaises(ValueError):verify_manifest(self.env,self.pin,self.sha)
    def test_corrupt_first_replica_and_cache_hit(self):
        calls=[]
        def reader(path,o,n):calls.append((path,o,n));return b'bad' if path.startswith('a:') else self.data[o:o+n]
        r=self.run_stage(reader);self.assertEqual(Path(r['path']).read_bytes(),self.data);self.assertEqual(len(calls),3)
        r=self.run_stage(lambda *_:self.fail('cache hit read network'));self.assertEqual(r['status'],'ALREADY_PRESENT')
    def test_resume_partial_and_reject_conflicting_final(self):
        def interrupted(path,o,n):
            if o:raise OSError('lost')
            return self.data[o:o+n]
        with self.assertRaises(CacheError):self.run_stage(interrupted)
        calls=[]
        def reader(path,o,n):calls.append(o);return self.data[o:o+n]
        r=self.run_stage(reader);self.assertEqual(r['reused_chunks'],1);self.assertEqual(calls,[4*1024*1024]);Path(r['path']).write_bytes(b'bad')
        with self.assertRaises(FileExistsError):self.run_stage(reader)
    def test_public_cache_and_bad_remotes(self):
        self.cache.chmod(0o755)
        with self.assertRaises(ValueError):self.run_stage(lambda *_:b'')
        self.cache.chmod(0o700)
        for remotes in (['a','a'],['-x'],['a:other'],[]):
            with self.assertRaises(ValueError):stage(self.env,self.pin,self.sha,self.cache,remotes,reader=lambda *_:b'',reserve_bytes=0)
    def test_disk_reserve_blocks_before_read(self):
        with patch('atlas.storage_cache.shutil.disk_usage',return_value=(100,100,0)):
            with self.assertRaises(CacheError):self.run_stage(lambda *_:self.fail('network read'))
    def test_bounded_subprocess(self):
        fake=self.root/'rclone';fake.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b"x"*100000)\n');fake.chmod(0o700)
        with self.assertRaises(CacheError):read_range('a:omega-models/model.gguf',0,64,rclone=str(fake),timeout=2)
        fake.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n')
        with self.assertRaises(CacheError):read_range('a:omega-models/model.gguf',0,64,rclone=str(fake),timeout=1)
    def test_refuse_non_model(self):
        bad=self.root/'password.txt';bad.write_bytes(b'a')
        with self.assertRaises(ValueError):sign_manifest(bad,self.key)
    def test_range_success_from_real_subprocess(self):
        fake=self.root/'rclone';fake.write_text('#!/usr/bin/env python3\nimport sys\no=int(sys.argv[sys.argv.index("--offset")+1]);n=int(sys.argv[sys.argv.index("--count")+1]);sys.stdout.buffer.write(b"0123456789"[o:o+n])\n');fake.chmod(0o700)
        self.assertEqual(read_range('a:omega-models/model.gguf',3,4,rclone=str(fake),timeout=2),b'3456')
