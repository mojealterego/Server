"""Red/green malformed-authentication boundary: valid MAC must not bypass schema typing."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import unittest

from atlas import secure_fabric as fabric


def manifest(root: bytes) -> dict:
    return {
        'schema': fabric.SCHEMA, 'archive': 'a' * 32,
        'policy_sha256': 'b' * 64, 'size_bytes': 4,
        'chunk_bytes': 65536, 'sha256': hashlib.sha256(b'data').hexdigest(),
        'key_id': fabric.hexdigest(root)[:16],
        'stores': {'p1': {'domain': 'rack-a', 'adapter': 'local'},
                   'p2': {'domain': 'rack-b', 'adapter': 'local'}},
        'blocks': [{'index': 0, 'length': 4,
                    'plain_sha256': hashlib.sha256(b'data').hexdigest(),
                    'cipher_sha256': 'c' * 64, 'pools': ['p1', 'p2']}],
    }


class ManifestInputTypes(unittest.TestCase):
    def test_reject_invalid_types_with_safely_verified_mac(self):
        root = os.urandom(32)
        mutations = [
            ('archive-list', lambda d: d.update(archive=[])),
            ('policy-int', lambda d: d.update(policy_sha256=42)),
            ('hash-null', lambda d: d.update(sha256=None)),
            ('invalid-domain', lambda d: d['stores']['p2'].update(domain=[])),
            ('plain-hash-object', lambda d: d['blocks'][0].update(plain_sha256={})),
            ('cipher-hash-array', lambda d: d['blocks'][0].update(cipher_sha256=[])),
            ('unhashable-pool-id', lambda d: d['blocks'][0].update(pools=['p1', ['p2']])),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                doc = copy.deepcopy(manifest(root))
                mutate(doc)
                signed = fabric.sign_manifest(doc, root)
                pin = fabric.hexdigest(fabric.canon(signed))
                with self.assertRaises(fabric.SecureError):
                    fabric.validate_manifest(signed, root, pin)

    def test_valid_signed_manifest_via_symlink_is_refused(self):
        import tempfile
        from atlas import quota_ledger
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); base.chmod(0o700)
            root = os.urandom(32)
            key_file = base/'key';key_file.write_bytes(root);key_file.chmod(0o600)
            source=base/'source';source.write_bytes(b'ARCHIVE' * 10000)
            ledger=quota_ledger.Ledger(base/'quota.sqlite')
            stores={}
            for name in ('p1','p2'):
                loc=base/name;loc.mkdir(mode=0o700)
                ledger.enroll(name,{'storage_bytes':1000000,'write_bytes':1000000,
                                    'read_bytes':1000000,'write_ops':20,
                                    'read_ops':20,'egress_bytes':1000000},now=1)
                stores[name]=fabric.LocalStore(loc,pool=name,domain=name)
            original=base/'archive.json'
            receipt=fabric.ingest(source,original,key_path=key_file,policy_sha256='b'*64,
                                  stores=stores,ledger=ledger,epoch=1,archive_id='c'*32,
                                  chunk_bytes=65536,now=2)
            link=base/'symlink.json';link.symlink_to(original)
            out=base/'out'
            with self.assertRaises(fabric.SecureError):
                fabric.restore(link,receipt['manifest_sha256'],out,key_path=key_file,
                               stores=stores)
            self.assertFalse(out.exists())

    def test_special_and_world_readable_manifest_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); base.chmod(0o700)
            pipe = base/'fifo'
            os.mkfifo(pipe, 0o600)
            with self.assertRaises(fabric.SecureError):
                fabric._read_manifest(pipe)
            readable = base/'world.json'
            readable.write_text('{}');readable.chmod(0o644)
            with self.assertRaises(fabric.SecureError):
                fabric._read_manifest(readable)

    def test_valid_manifest_unaffected(self):
        root = os.urandom(32)
        doc = fabric.sign_manifest(manifest(root), root)
        fabric.validate_manifest(doc, root, fabric.hexdigest(fabric.canon(doc)))


if __name__ == '__main__':
    unittest.main()
