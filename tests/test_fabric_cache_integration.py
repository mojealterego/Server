"""Actual Fabric/cache/manifest/Merkle path; external Rclone process is a fixture."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from atlas.storage_cache import sign_manifest, CacheError
from atlas.storage_fabric import Fabric, digest
from atlas.merkle import DEFAULT_CHUNK

class FabricCacheIntegrationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.source=self.root/'model.gguf';self.data=b'a'*DEFAULT_CHUNK+b'b'*DEFAULT_CHUNK+b'c';self.source.write_bytes(self.data)
        key=self.root/'key';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        self.envelope=sign_manifest(self.source,key);self.sha=hashlib.sha256(self.data).hexdigest()
        self.cache=self.root/'cache';self.cache.mkdir(mode=0o700)
        self.doc={'schema':'omega.storage.fabric.v1','models':{'qwen':{'sha256':self.sha,'public_key':self.envelope['public_key'],'remotes':['wrong','broken','healthy']}},'recovery':{'sha256':'b'*64,'remotes':['backup:vault']}}
        fake=self.root/'rclone';fake.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
root=Path(os.environ['OMEGA_FIXTURE_ROOT']);cmd=sys.argv[1:]
with (root/'calls').open('a') as log:log.write(' '.join(cmd)+'\\n')
if cmd[0]=='config':
    assert cmd[1]=='redacted'
    alias=cmd[2];print(f'[{alias}]\\ntype = '+('sftp' if alias=='wrong' else 'smb'))
elif cmd[0]=='cat':
    alias=cmd[1].split(':')[0]
    if alias=='broken' or (root/'offline').exists():sys.exit(1)
    assert alias=='healthy' and cmd[1]=='healthy:omega-models/model.gguf'
    off=int(cmd[cmd.index('--offset')+1]);count=int(cmd[cmd.index('--count')+1])
    with (root/'model.gguf').open('rb') as f:f.seek(off);sys.stdout.buffer.write(f.read(count))
else:sys.exit(2)
''');fake.chmod(0o700)
        env=patch.dict(os.environ,{'PATH':str(self.root)+os.pathsep+os.environ['PATH'],'OMEGA_FIXTURE_ROOT':str(self.root)});env.start();self.addCleanup(env.stop)
    def test_verified_stage_rejects_wrong_backend_and_prefers_healthy(self):
        f=Fabric(self.doc,digest(self.doc));r=f.stage_model('qwen',self.envelope,self.cache)
        self.assertEqual(Path(r['path']).read_bytes(),self.data)
        calls=(self.root/'calls').read_text().splitlines()
        self.assertEqual(calls[:5],['config redacted wrong','config redacted broken','cat broken:omega-models/model.gguf --offset 0 --count 4194304','config redacted healthy','cat healthy:omega-models/model.gguf --offset 0 --count 4194304'])
        self.assertEqual(len(calls),7);self.assertTrue(all(x.startswith('cat healthy:') for x in calls[5:]))
        (self.root/'offline').touch();r=f.stage_model('qwen',self.envelope,self.cache)
        self.assertEqual(r['status'],'ALREADY_PRESENT');self.assertEqual((self.root/'calls').read_text().splitlines(),calls)
    def test_all_enrolled_backends_fail_without_publication(self):
        (self.root/'offline').touch();f=Fabric(self.doc,digest(self.doc))
        with self.assertRaises(CacheError):f.stage_model('qwen',self.envelope,self.cache)
        self.assertFalse((self.cache/(self.sha+'.gguf')).exists())
