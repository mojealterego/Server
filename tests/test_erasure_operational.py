"""Real subprocess CLI and E13 uncertain-reservation crash behavior."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from atlas import erasure_archive as ea, secure_fabric as s, quota_ledger as q


def budget():
    return {field:10_000_000 if field.endswith('bytes') else 200 for field in q.FIELDS}


class ErasureOperations(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        self.source=self.root/'source.bin'
        self.content=(b'OMEGA Erasure '+bytes(range(256)))*1600
        self.source.write_bytes(self.content)
        self.manifest=self.root/'manifest.json'
        self.key=self.root/'key';self.key.write_bytes(os.urandom(32));self.key.chmod(0o600)
        self.ledger=q.Ledger(self.root/'ledger.sqlite')
        self.stores={};self.roots={}
        self.time=int(time.time())
        for i in range(6):
            name=f'vol{i}';loc=self.root/name;loc.mkdir(mode=0o700)
            self.ledger.enroll(name,budget(),now=self.time)
            self.stores[name]=s.LocalStore(loc,pool=name,domain=f'faultdomain{i}')
            self.roots[name]={'path':str(loc),'domain':f'faultdomain{i}'}
        self.roots_path=self.root/'roots.json'
        self.roots_path.write_text(json.dumps(self.roots))

    def command(self,*args):
        project=Path(__file__).resolve().parents[1]
        return subprocess.run([sys.executable,'-m','atlas.erasure_archive',
                               '--manifest',str(self.manifest),'--key',str(self.key),
                               '--ledger',str(self.root/'ledger.sqlite'),
                               '--stores',str(self.roots_path),'--epoch','1',*args],
                              cwd=project,timeout=30,capture_output=True,text=True)

    def test_cli_ingest_restore_repair_and_pinned_manifest(self):
        r=self.command('ingest','--source',str(self.source),'--policy-sha256','a'*64,
                       '--archive-id','f'*32,'--chunk-bytes','131072','--profile','auto')
        self.assertEqual(r.returncode,0,r.stderr)
        doc=json.loads(r.stdout)
        self.assertEqual(doc['profile'],'4+2')
        raw=json.loads(self.manifest.read_text())
        pool=raw['blocks'][0]['shards'][0]
        damaged=self.stores[pool['pool']].objects/pool['sha256']
        damaged.unlink()
        recovered=self.root/'recovered.bin'
        r=self.command('restore','--pin',doc['manifest_sha256'],'--destination',str(recovered))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(recovered.read_bytes(),self.content)
        r=self.command('repair','--pin',doc['manifest_sha256'],'--repair-id','incident-20261121')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)['repaired_shards'],1)
        self.assertEqual(damaged.read_bytes(),self.stores[pool['pool']].get('f'*32,0,pool['sha256'],pool['size']))
        r=self.command('restore','--pin','0'*64,'--destination',str(self.root/'denied'))
        self.assertNotEqual(r.returncode,0)
        self.assertFalse((self.root/'denied').exists())

    def test_uncertain_quota_after_ambiguous_partial_write(self):
        first=self.stores['vol0'];original=first.put
        def drop_after_write(*args):
            original(*args)
            raise OSError('lost write acknowledgement')
        first.put=drop_after_write
        with self.assertRaises(OSError):
            ea.ingest(self.source,self.manifest,key_path=self.key,policy_sha256='a'*64,
                      stores=self.stores,ledger=self.ledger,epoch=1,
                      archive_id='c'*32,chunk_bytes=131072,k=4,parity=2,now=self.time)
        self.assertFalse(self.manifest.exists())
        for name in self.stores:
            self.assertEqual(self.ledger.status(name,now=self.time)['uncertain_count'],1)


if __name__=='__main__':unittest.main()
