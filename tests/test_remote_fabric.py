"""Real subprocess integration with a controlled Rclone CLI fixture; no cloud account."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from atlas import provider_registry as p, quota_ledger as q, secure_fabric as s


def limits():
    return dict(storage_bytes=10_000_000,write_bytes=10_000_000,
                read_bytes=10_000_000,write_ops=100,read_ops=100,egress_bytes=10_000_000)


class RemoteFabricFixtureTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        self.conf=self.root/'rclone.conf';self.conf.write_text('[cloud]\ntype = s3\nprovider = Cloudflare\nendpoint = https://'+'a'*32+'.r2.cloudflarestorage.com\n');self.conf.chmod(0o600)
        self.objects=self.root/'remote';self.objects.mkdir(mode=0o700)
        self.binary=self.root/'rclone'
        self.binary.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
argv=sys.argv[1:]
assert argv[0]=='--config'
a=argv[2:];root=Path(os.environ['OMEGA_TEST_REMOTE'])
if a[:2]==['config','redacted']:
    print('[cloud]\\ntype = s3\\nprovider = Cloudflare\\nendpoint = https://'+'a'*32+'.r2.cloudflarestorage.com\\n')
elif a[:2]==['about','cloud:']:
    print(json.dumps({'total':10000000,'free':10000000,'used':0}))
elif a[0]=='copyto':
    src,remote=a[1:3]
    if (root/'fail-copy').exists():sys.exit(1)
    filename=remote.split('/')[-1]
    (root/filename).write_bytes(Path(src).read_bytes())
elif a[0]=='cat':
    filename=a[1].split('/')[-1]
    sys.stdout.buffer.write((root/filename).read_bytes())
else:sys.exit(2)
''');self.binary.chmod(0o700)
        self.env=patch.dict(os.environ,{'OMEGA_TEST_REMOTE':str(self.objects)})
        self.env.start();self.addCleanup(self.env.stop)
        now=int(time.time());self.now=now
        self.row=dict(id='cloud1',provider='cloudflare_r2',account='account1',domain='cloud-domain',
                      alias='cloud',authorized=True,free_tier_attested=True,write_enabled=True,
                      attested_at=now,limit_bytes=9_000_000,reserve_bytes=1000,
                      monthly_write_bytes=9_000_000,monthly_read_bytes=9_000_000,monthly_operations=100)
        self.registry=dict(schema=p.SCHEMA,max_age_seconds=300,providers=[self.row])
        self.ledger=q.Ledger(self.root/'ledger.sqlite')
        self.ledger.enroll('cloud1',limits(),now=now)
        self.ledger.enroll('local1',limits(),now=now)
        self.localdir=self.root/'local';self.localdir.mkdir(mode=0o700)
        self.local=s.LocalStore(self.localdir,pool='local1',domain='owned-disk')
        self.key=self.root/'key';self.key.write_bytes(os.urandom(32));self.key.chmod(0o600)
        self.source=self.root/'source';self.content=os.urandom(140000);self.source.write_bytes(self.content)
        self.manifest=self.root/'archive.json'

    def remote(self,*,permit=True):
        return s.RcloneStore(pool='cloud1',domain='cloud-domain',alias='cloud',row=self.row,
                             config=self.conf,registry=self.registry,registry_pin=p.digest(self.registry),
                             ledger=self.ledger,epoch=1,permit_remote=permit,executable=str(self.binary))

    def test_remote_write_requires_explicit_opt_in(self):
        with self.assertRaises(s.SecureError):self.remote(permit=False)
        remote=self.remote()
        with self.assertRaises(q.QuotaError):remote.put('a'*32,0,s.hexdigest(b'good'),b'good')
        self.assertEqual(list(self.objects.iterdir()),[])

    def test_real_subprocess_encrypted_upload_readback_and_restore(self):
        remote=self.remote()
        stores={'cloud1':remote,'local1':self.local}
        result=s.ingest(self.source,self.manifest,key_path=self.key,
                        policy_sha256='a'*64,stores=stores,ledger=self.ledger,epoch=1,
                        archive_id='c'*32,chunk_bytes=65536)
        self.assertEqual(result['chunks'],3)
        self.assertEqual(len(list(self.objects.glob('*.enc'))),3)
        # Read only from the remote, charging a new budgeted read for each chunk.
        out=self.root/'restored'
        s.restore(self.manifest,result['manifest_sha256'],out,key_path=self.key,
                  stores={'cloud1':remote},ledger=self.ledger,epoch=1)
        self.assertEqual(out.read_bytes(),self.content)
        quota=self.ledger.status('cloud1',now=int(time.time()))
        self.assertEqual(quota['available']['read_ops'],94)

    def test_failed_remote_copy_quarantines_budget(self):
        (self.objects/'fail-copy').touch()
        remote=self.remote()
        with self.assertRaises(p.ProviderError):s.ingest(self.source,self.manifest,key_path=self.key,
                         policy_sha256='a'*64,stores={'cloud1':remote,'local1':self.local},
                         ledger=self.ledger,epoch=1,archive_id='c'*32,chunk_bytes=65536)
        self.assertFalse(self.manifest.exists())
        self.assertEqual(self.ledger.status('cloud1',now=int(time.time()))['uncertain_count'],1)

    def test_backend_drift_blocks_even_with_operator_flags(self):
        self.row['provider']='google_drive'
        with self.assertRaises(s.SecureError):self.remote()

if __name__=='__main__':unittest.main()
