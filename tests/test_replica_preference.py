import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from atlas.storage_cache import stage, sign_manifest, CacheError
from atlas.merkle import DEFAULT_CHUNK

class ReplicaPreferenceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        key=self.root/'key';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        self.data=b'a'*DEFAULT_CHUNK+b'b'*DEFAULT_CHUNK+b'c';source=self.root/'model.gguf';source.write_bytes(self.data)
        self.sha=hashlib.sha256(self.data).hexdigest();self.env=sign_manifest(source,key);self.cache=self.root/'cache';self.cache.mkdir(mode=0o700)
    def stage(self,reader):return stage(self.env,self.env['public_key'],self.sha,self.cache,['a','b'],reader=reader,reserve_bytes=0)
    def test_last_verified_replica_preferred_and_offline_cache(self):
        calls=[]
        def read(path,o,n):
            calls.append((path[0],o))
            if path.startswith('a:'):return b'bad'
            return self.data[o:o+n]
        result=self.stage(read)
        self.assertEqual(Path(result['path']).read_bytes(),self.data)
        self.assertEqual(calls,[('a',0),('b',0),('b',DEFAULT_CHUNK),('b',2*DEFAULT_CHUNK)])
        self.assertEqual(self.stage(lambda *_:self.fail('network on cache hit'))['status'],'ALREADY_PRESENT')
    def test_preferred_failure_falls_back_and_switches(self):
        calls=[]
        def read(path,o,n):
            alias=path[0];calls.append((alias,o))
            if (alias=='a' and o==0) or (alias=='b' and o==DEFAULT_CHUNK):raise OSError('offline')
            return self.data[o:o+n]
        result=self.stage(read)
        self.assertEqual(Path(result['path']).read_bytes(),self.data)
        self.assertEqual(calls,[('a',0),('b',0),('b',DEFAULT_CHUNK),('a',DEFAULT_CHUNK),('a',2*DEFAULT_CHUNK)])
    def test_all_replicas_corrupt_never_publish(self):
        calls=[]
        def read(path,o,n):calls.append(path[0]);return b'z'*n
        with self.assertRaises(CacheError):self.stage(read)
        self.assertEqual(calls,['a','b']);self.assertFalse((self.cache/(self.sha+'.gguf')).exists())
