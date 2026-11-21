"""Actual on-disk AES-GCM + RS CAS recovery, integrity and E13 quota tests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from atlas import erasure_archive as archive
from atlas import secure_fabric as secure
from atlas import quota_ledger as quotas


def limits():
    return {name: 12 * 1024 * 1024 if name.endswith('bytes') else 300
            for name in quotas.FIELDS}


class ErasureArchiveTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.key=self.root/'key';self.key.write_bytes(os.urandom(32));self.key.chmod(0o600)
        self.source=self.root/'source';self.data=(bytes(range(256))+b'OMEGA-E15')*2800
        self.source.write_bytes(self.data)
        self.manifest=self.root/'manifest.json'
        self.ledger=quotas.Ledger(self.root/'ledger.sqlite')
        self.archive_id='a'*32;self.pin='b'*64;self._time=1
        self.stores={}

    def configure(self,k=4,p=2):
        self.stores={}
        for i in range(k+p):
            name=f'p{i}';folder=self.root/name;folder.mkdir(mode=0o700,exist_ok=True)
            self.ledger.enroll(name,limits(),now=self._time)
            self.stores[name]=secure.LocalStore(folder,pool=name,domain=f'domain{i}')
        return self.stores

    def ingest(self,k=4,p=2):
        self.configure(k,p)
        return archive.ingest(self.source,self.manifest,key_path=self.key,policy_sha256=self.pin,
                              stores=self.stores,ledger=self.ledger,epoch=1,
                              archive_id=self.archive_id,chunk_bytes=262144,k=k,parity=p,now=self._time+1)

    def drop_shards(self,ids):
        doc=json.loads(self.manifest.read_text())
        for block in doc['blocks']:
            for shard in block['shards']:
                if shard['pool'] in ids:
                    target=self.stores[shard['pool']].objects/shard['sha256']
                    target.unlink()

    def test_both_profiles_real_disk_recovery_at_parity_limit(self):
        for k,p in ((4,2),(8,3)):
            with self.subTest(profile=(k,p)):
                if self.manifest.exists():self.manifest.unlink()
                self.archive_id='a'*31+format(k,'x')
                self._time=30 if k==8 else 1
                receipt=self.ingest(k,p)
                self.assertEqual(receipt['profile'],f'{k}+{p}')
                doc=json.loads(self.manifest.read_text())
                self.assertNotIn('OMEGA-E15',str(doc))
                unavailable={f'p{i}' for i in range(p)}
                self.drop_shards(unavailable)
                surviving={name:store for name,store in self.stores.items() if name not in unavailable}
                output=self.root/('recovered_'+str(k))
                report=archive.restore(self.manifest,receipt['manifest_sha256'],output,
                                       key_path=self.key,stores=surviving)
                self.assertEqual(report['status'],'RESTORED_AUTHENTICATED')
                self.assertEqual(output.read_bytes(),self.data)
                self.assertEqual(hashlib.sha256(self.data).hexdigest(),report['sha256'])
                repaired=archive.repair(self.manifest,receipt['manifest_sha256'],key_path=self.key,
                                        stores=self.stores,ledger=self.ledger,epoch=1,
                                        repair_id='repair'+str(k),now=self._time+2)
                self.assertEqual(repaired['repaired_shards'],p*len(doc['blocks']))
                other=self.root/('restored_after_repair_'+str(k))
                archive.restore(self.manifest,receipt['manifest_sha256'],other,
                                key_path=self.key,stores=self.stores)
                self.assertEqual(other.read_bytes(),self.data)

    def test_more_losses_than_parity_refused_and_no_output(self):
        receipt=self.ingest(4,2)
        self.drop_shards({'p0','p1','p2'})
        target=self.root/'lost'
        with self.assertRaises(archive.ErasureArchiveError):
            archive.restore(self.manifest,receipt['manifest_sha256'],target,
                            key_path=self.key,stores=self.stores)
        self.assertFalse(target.exists())

    def test_wrong_key_and_manifest_tamper_refused(self):
        receipt=self.ingest(4,2)
        doc=json.loads(self.manifest.read_text());doc['blocks'][0]['shards'][0]['sha256']='0'*64
        self.manifest.write_text(json.dumps(doc));self.manifest.chmod(0o600)
        out=self.root/'bad'
        with self.assertRaises(archive.ErasureArchiveError):
            archive.restore(self.manifest,archive.digest(doc),out,key_path=self.key,stores=self.stores)
        self.assertFalse(out.exists())

    def test_no_double_registration_and_no_duplicate_domains(self):
        self.configure(4,2)
        self.stores['p1'].domain=self.stores['p0'].domain
        with self.assertRaises(archive.ErasureArchiveError):
            archive.ingest(self.source,self.manifest,key_path=self.key,policy_sha256=self.pin,
                           stores=self.stores,ledger=self.ledger,epoch=1,
                           archive_id=self.archive_id,chunk_bytes=262144,k=4,parity=2,now=10)
        self.assertFalse(self.manifest.exists())

    def test_quota_exhaustion_blocks_writes(self):
        self.configure(4,2)
        self.ledger.fence('p0',1,2,now=2)
        with self.assertRaises(quotas.QuotaError):
            archive.ingest(self.source,self.manifest,key_path=self.key,policy_sha256=self.pin,
                           stores=self.stores,ledger=self.ledger,epoch=1,
                           archive_id=self.archive_id,chunk_bytes=262144,k=4,parity=2,now=10)
        self.assertFalse(self.manifest.exists())
        for store in self.stores.values():self.assertFalse(any(store.objects.iterdir()))

    def test_no_overwrite_and_ciphertext_shards(self):
        receipt=self.ingest()
        output=self.root/'previous';output.write_bytes(b'KEEP')
        with self.assertRaises(archive.ErasureArchiveError):
            archive.restore(self.manifest,receipt['manifest_sha256'],output,
                            key_path=self.key,stores=self.stores)
        self.assertEqual(output.read_bytes(),b'KEEP')
        doc=json.loads(self.manifest.read_text())
        for stripe in doc['blocks']:
            for entry in stripe['shards']:
                blob=self.stores[entry['pool']].get(self.archive_id,stripe['index'],entry['sha256'],entry['size'])
                self.assertNotIn(b'OMEGA-E15',blob)

    def test_corrupted_fragment_treated_as_erasure(self):
        receipt=self.ingest()
        doc=json.loads(self.manifest.read_text())
        bad=doc['blocks'][0]['shards'][0]
        (self.stores[bad['pool']].objects/bad['sha256']).write_bytes(b'tampered')
        target=self.root/'recovered'
        archive.restore(self.manifest,receipt['manifest_sha256'],target,
                        key_path=self.key,stores=self.stores)
        self.assertEqual(target.read_bytes(),self.data)


if __name__ == '__main__':unittest.main()
