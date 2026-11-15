"""Host-level negative-security tests for authenticated offline snapshots and publish."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative)
    mod=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name]=mod
    spec.loader.exec_module(mod)
    return mod

class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=load('snapshot_v2','tools/snapshot_manifest.py')
        cls.publish=load('publish_v2','tools/atomic_publish.py')

    def setup_snapshot(self,base):
        src=base/'src'; src.mkdir()
        (src/'models').mkdir()
        (src/'models'/'Huihui.gguf').write_bytes(b'example source file only, not model weights')
        (src/'empty').write_bytes(b'')
        snapshot=base/'snapshot';snapshot.mkdir()
        self.m.create(src,snapshot/'SHA256SUMS')
        self.m.keyfile(base/'key',generate=True)
        self.m.seal(snapshot,'snap12345',base/'key')
        (snapshot/'models').mkdir()
        (snapshot/'models'/'Huihui.gguf').write_bytes((src/'models'/'Huihui.gguf').read_bytes())
        (snapshot/'empty').write_bytes(b'')
        return src,snapshot,base/'key'

    def test_round_trip_manifest_and_hmac_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            _,snapshot,key=self.setup_snapshot(Path(d))
            self.assertEqual(self.m.verify(snapshot,key,'snap12345'),2)

    def test_modified_file_fails_hash_check(self):
        with tempfile.TemporaryDirectory() as d:
            _,snapshot,key=self.setup_snapshot(Path(d))
            (snapshot/'models/Huihui.gguf').write_text('attacker mutated data')
            with self.assertRaisesRegex(ValueError,'mismatch'):self.m.verify(snapshot,key)

    def test_modified_receipt_fails_authentication(self):
        with tempfile.TemporaryDirectory() as d:
            _,snapshot,key=self.setup_snapshot(Path(d))
            marker=snapshot/'COMPLETE.json'
            obj=json.loads(marker.read_text())
            obj['hmac_sha256']='0'*64
            marker.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError,'HMAC'):self.m.verify(snapshot,key)

    def test_wrong_key_fails_authentication(self):
        with tempfile.TemporaryDirectory() as d:
            _,snapshot,key=self.setup_snapshot(Path(d))
            other=Path(d)/'other';self.m.keyfile(other,generate=True)
            with self.assertRaisesRegex(ValueError,'HMAC'):self.m.verify(snapshot,other)

    def test_path_traversal_in_manifest_fails(self):
        with tempfile.TemporaryDirectory() as d:
            _,snapshot,key=self.setup_snapshot(Path(d))
            (snapshot/'SHA256SUMS').write_text('0'*64+'  ../../escape\n')
            with self.assertRaises(ValueError):self.m.verify(snapshot,key)
            with self.assertRaisesRegex(ValueError,'Unsafe'):self.m.entries(snapshot/'SHA256SUMS')

    def test_extra_unexpected_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            _,snapshot,key=self.setup_snapshot(Path(d))
            (snapshot/'surprise.exe').write_text('unverified file')
            with self.assertRaisesRegex(ValueError,'extra='):self.m.verify(snapshot,key)

    def test_source_symlink_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'src';src.mkdir();(src/'secrets').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError,'symlink'):self.m.create(src,Path(d)/'manifest')

    def test_duplicate_manifest_paths_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'man';p.write_text(('0'*64+'  item\n')*2)
            with self.assertRaisesRegex(ValueError,'Duplicate'):self.m.entries(p)

    def test_fails_on_symlink_key_and_unsafe_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);key=root/'key';self.m.keyfile(key,generate=True)
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'0600'):self.m.keyfile(key)
            key.chmod(0o600)
            link=root/'link';link.symlink_to(key)
            with self.assertRaises(ValueError):self.m.keyfile(link)

    def test_atomic_publish_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'new';src.mkdir();(src/'a').write_text('source')
            dest=root/'existing';dest.mkdir();(dest/'b').write_text('existing')
            with self.assertRaises(FileExistsError):self.publish.publish(src,dest)
            self.assertEqual((dest/'b').read_text(),'existing')
            dest2=root/'published';self.publish.publish(src,dest2)
            self.assertFalse(src.exists());self.assertEqual((dest2/'a').read_text(),'source')

    def test_bad_snapshot_id_and_reserved_source_name(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'src';src.mkdir();(src/'COMPLETE.json').write_text('shadow')
            with self.assertRaisesRegex(ValueError,'Reserved'):self.m.create(src,Path(d)/'man')
            (src/'COMPLETE.json').unlink()
            root=Path(d)/'snapshot';root.mkdir();(root/'SHA256SUMS').write_text('')
            key=Path(d)/'key';self.m.keyfile(key,generate=True)
            with self.assertRaisesRegex(ValueError,'snapshot ID'):self.m.seal(root,'../fake',key)

if __name__=='__main__':unittest.main()
