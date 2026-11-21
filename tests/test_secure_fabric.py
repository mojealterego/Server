import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidTag

from atlas import secure_fabric as s
from atlas import quota_ledger as q


def limits(max_bytes=3_000_000):
    return dict(storage_bytes=max_bytes,write_bytes=max_bytes,read_bytes=max_bytes,
                write_ops=100,read_ops=100,egress_bytes=max_bytes)


class EncryptedArchiveTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        self.key=self.root/'key';self.key.write_bytes(os.urandom(32));self.key.chmod(0o600)
        self.source=self.root/'source.bin'
        self.data=os.urandom(140000)
        self.source.write_bytes(self.data)
        self.policy='a'*64;self.archive='b'*32
        self.ledger=q.Ledger(self.root/'ledger.sqlite')
        self.roots=[]
        self.stores={}
        for name in ('one','two'):
            path=self.root/name;path.mkdir(mode=0o700)
            self.roots.append(path)
            self.ledger.enroll(name,limits(),now=10)
            self.stores[name]=s.LocalStore(path,pool=name,domain=name+'-domain')
        self.manifest=self.root/'manifest.json'

    def ingest(self):
        return s.ingest(self.source,self.manifest,key_path=self.key,policy_sha256=self.policy,
                        stores=self.stores,ledger=self.ledger,epoch=1,archive_id=self.archive,
                        chunk_bytes=65536,now=11)

    def test_encrypted_readback_and_verified_restore(self):
        record=self.ingest();self.assertEqual(record['chunks'],3)
        doc=json.loads(self.manifest.read_text())
        self.assertEqual(record['manifest_sha256'],s.hexdigest(s.canon(doc)))
        first=doc['blocks'][0]['cipher_sha256']
        self.assertNotIn(self.data[:24], (self.roots[0]/'objects'/first).read_bytes())
        out=self.root/'restored'
        result=s.restore(self.manifest,record['manifest_sha256'],out,key_path=self.key,stores=self.stores)
        self.assertEqual(out.read_bytes(),self.data);self.assertEqual(result['sha256'],hashlib.sha256(self.data).hexdigest())
        self.assertEqual(self.ledger.status('one',now=12)['available']['write_ops'],97)

    def test_ciphertext_mutation_fails_over(self):
        record=self.ingest();doc=json.loads(self.manifest.read_text())
        first=doc['blocks'][0]['cipher_sha256'];(self.roots[0]/'objects'/first).write_bytes(b'BAD')
        out=self.root/'recovered'
        s.restore(self.manifest,record['manifest_sha256'],out,key_path=self.key,stores=self.stores)
        self.assertEqual(out.read_bytes(),self.data)

    def test_all_replicas_lost_refuses_publication(self):
        record=self.ingest();doc=json.loads(self.manifest.read_text())
        first=doc['blocks'][0]['cipher_sha256']
        for p in self.roots:(p/'objects'/first).unlink()
        out=self.root/'denied'
        with self.assertRaises(s.SecureError):s.restore(self.manifest,record['manifest_sha256'],out,key_path=self.key,stores=self.stores)
        self.assertFalse(out.exists())

    def test_hmac_tamper_even_with_rehashed_manifest(self):
        record=self.ingest();doc=json.loads(self.manifest.read_text())
        doc['blocks'][0]['length']=100
        self.manifest.write_text(json.dumps(doc))
        with self.assertRaises(s.SecureError):s.restore(self.manifest,s.hexdigest(s.canon(doc)),self.root/'out',key_path=self.key,stores=self.stores)
        self.assertFalse((self.root/'out').exists())

    def test_wrong_key_fails_closed(self):
        record=self.ingest()
        self.key.write_bytes(os.urandom(32))
        with self.assertRaises(s.SecureError):s.restore(self.manifest,record['manifest_sha256'],self.root/'out',key_path=self.key,stores=self.stores)

    def test_two_domains_enforced_and_quota_check(self):
        self.stores['two'].domain=self.stores['one'].domain
        with self.assertRaises(s.SecureError):self.ingest()
        self.stores['two'].domain='two-domain'
        self.ledger.fence('one',1,2,now=11)
        with self.assertRaises(q.QuotaError):self.ingest()
        self.assertFalse(self.manifest.exists())

    def test_existing_destination_preserved(self):
        record=self.ingest()
        out=self.root/'out';out.write_bytes(b'KEEP')
        with self.assertRaises(s.SecureError):s.restore(self.manifest,record['manifest_sha256'],out,key_path=self.key,stores=self.stores)
        self.assertEqual(out.read_bytes(),b'KEEP')

    def test_replay_reservation_does_not_publish_new_version(self):
        self.ingest();self.manifest.unlink()
        with self.assertRaises((q.QuotaError,s.SecureError)):
            self.ingest()
        self.assertFalse(self.manifest.exists())

    def test_nonce_unique_and_wrong_aad(self):
        root=s.private_key(self.key)
        a=s.encrypt_chunk(root,self.archive,0,self.policy,b'hello')
        b=s.encrypt_chunk(root,self.archive,0,self.policy,b'hello')
        self.assertNotEqual(a,b)
        with self.assertRaises(InvalidTag):s.decrypt_chunk(root,self.archive,1,self.policy,a,5)

    def test_crash_after_first_put_keeps_conservative_holds(self):
        first=self.stores['one']
        old=first.put
        def fail_after_put(*args):old(*args);raise OSError('reply lost')
        first.put=fail_after_put
        with self.assertRaises(OSError):self.ingest()
        self.assertFalse(self.manifest.exists())
        self.assertEqual(self.ledger.status('one',now=12)['uncertain_count'],1)
        self.assertEqual(self.ledger.status('two',now=12)['uncertain_count'],1)

    def test_quota_insufficiency_prevents_any_write(self):
        self.ledger.fence('one',1,2,now=11)
        self.ledger.enroll('tiny',limits(max_bytes=1),now=11)
        self.stores['one'].pool='tiny'
        with self.assertRaises(s.SecureError):self.ingest()
        self.assertEqual(list((self.roots[0]/'objects').iterdir()),[])

if __name__=='__main__':unittest.main()

class SecurityBoundaryTests(unittest.TestCase):
    def test_key_permissions_and_duplicate_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            key=root/'key';key.write_bytes(os.urandom(32));key.chmod(0o644)
            with self.assertRaises(s.SecureError):s.private_key(key)
            key.chmod(0o600)
            self.assertEqual(len(s.private_key(key)),32)
            with self.assertRaises(s.SecureError):s.validate_manifest({'schema':s.SCHEMA},s.private_key(key),'0'*64)

    def test_stores_require_distinct_operator_failure_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            a=root/'a';b=root/'b';a.mkdir(mode=0o700);b.mkdir(mode=0o700)
            stores={'a':s.LocalStore(a,pool='a',domain='same'),
                    'b':s.LocalStore(b,pool='b',domain='same')}
            with self.assertRaises(s.SecureError):s._store_info(stores)
