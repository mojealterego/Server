"""Seeded boundary and failure tests; no external provider access."""
import hashlib
import json
import os
from pathlib import Path
import random
import tempfile
import unittest

from atlas import quota_ledger as q, secure_fabric as s


def costs(n):
    return dict(storage_bytes=n,write_bytes=n,read_bytes=0,
                write_ops=1,read_ops=0,egress_bytes=0)


class SecurityInvariants(unittest.TestCase):
    def test_seeded_quota_history_never_overbooks(self):
        rng=random.Random(20261120)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            ledger=q.Ledger(root/'ledger')
            limits=dict(storage_bytes=3000,write_bytes=3000,read_bytes=0,
                        write_ops=100,read_ops=0,egress_bytes=0)
            ledger.enroll('p',limits,now=1)
            now=2
            for i in range(250):
                now+=rng.choice([0,0,1])
                try:
                    request=f'key-{i}'
                    ledger.reserve('p',request,costs(rng.randint(1,150)),epoch=1,
                                   ttl=rng.randint(1,10),now=now)
                    if rng.random()<.45:
                        ledger.commit('p',request,epoch=1,now=now)
                except q.QuotaError:
                    pass
                available=ledger.status('p',now=now)['available']
                self.assertTrue(all(0<=v<=limits[k] for k,v in available.items()),i)

    def test_many_malformed_authentication_tamper_cases(self):
        root=os.urandom(32)
        doc={'schema':s.SCHEMA,'archive':'a'*32,'policy_sha256':'b'*64,
             'size_bytes':4,'chunk_bytes':65536,'sha256':hashlib.sha256(b'data').hexdigest(),
             'key_id':s.hexdigest(root)[:16],
             'stores':{'p1':{'domain':'one','adapter':'local'},
                       'p2':{'domain':'two','adapter':'local'}},
             'blocks':[{'index':0,'length':4,'plain_sha256':hashlib.sha256(b'data').hexdigest(),
                        'cipher_sha256':'c'*64,'pools':['p1','p2']}]}
        signed=s.sign_manifest(doc,root)
        pin=s.hexdigest(s.canon(signed));s.validate_manifest(signed,root,pin)
        rng=random.Random(20261120)
        for _ in range(100):
            corrupted=json.loads(json.dumps(signed))
            idx=rng.randint(0,5)
            if idx==0:corrupted['size_bytes']+=1
            elif idx==1:corrupted['archive']='f'*32
            elif idx==2:corrupted['blocks'][0]['plain_sha256']='d'*64
            elif idx==3:corrupted['stores']['p2']['domain']='one'
            elif idx==4:corrupted['blocks'][0]['cipher_sha256']='e'*64
            else:corrupted['policy_sha256']='f'*64
            with self.assertRaises(s.SecureError):
                s.validate_manifest(corrupted,root,s.hexdigest(s.canon(corrupted)))

    def test_no_symlink_source_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            source=root/'source';source.write_bytes(b'x'*65536)
            link=root/'link';link.symlink_to(source)
            key=root/'key';key.write_bytes(os.urandom(32));key.chmod(0o600)
            ledger=q.Ledger(root/'db')
            stores={}
            for id in ('one','two'):
                p=root/id;p.mkdir(mode=0o700)
                ledger.enroll(id,dict(storage_bytes=200000,write_bytes=200000,
                                      read_bytes=200000,write_ops=10,read_ops=10,
                                      egress_bytes=200000),now=10)
                stores[id]=s.LocalStore(p,pool=id,domain=id)
            target=root/'manifest'
            with self.assertRaises(s.SecureError):
                s.ingest(link,target,key_path=key,policy_sha256='a'*64,stores=stores,
                         ledger=ledger,epoch=1,archive_id='d'*32,chunk_bytes=65536,now=11)
            target.write_text('preserve')
            with self.assertRaises(s.SecureError):
                s.ingest(source,target,key_path=key,policy_sha256='a'*64,stores=stores,
                         ledger=ledger,epoch=1,archive_id='d'*32,chunk_bytes=65536,now=11)
            self.assertEqual(target.read_text(),'preserve')

if __name__=='__main__':unittest.main()
