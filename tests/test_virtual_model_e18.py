"""E18a pinned stream hydration, no reference-only storage magic."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from atlas.virtual_model import validate_reference, rehydrate, VirtualModelError

DATA = (b'public model GGUF bytes\n' + bytes(range(256))) * 100
HASH = hashlib.sha256(DATA).hexdigest()
REV = 'a' * 40
URL = 'https://huggingface.co/acme/example-model/resolve/'+REV+'/weights/model.Q4_K_M.gguf'

def ref(**kw):
    data={'schema':'omega.virtual-model.v1','url':URL,'sha256':HASH,
          'size_bytes':len(DATA),'revision':REV,'license':'apache-2.0'}
    data.update(kw)
    return data

class VirtualModelTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup)
        self.root=Path(d.name);self.root.chmod(0o700)
        self.dest=self.root/'model.gguf'
        self.reads=0

    def stream(self,doc):
        self.reads+=1
        return io.BytesIO(DATA)

    def test_verified_hydration_and_offline_hit(self):
        rec=rehydrate(ref(),self.dest,open_source=self.stream)
        self.assertEqual(rec['status'],'HYDRATED_VERIFIED')
        self.assertEqual(self.dest.read_bytes(),DATA)
        self.assertEqual(self.reads,1)
        hit=rehydrate(ref(),self.dest,open_source=lambda *_:self.fail('network on cache hit'))
        self.assertEqual(hit['status'],'ALREADY_VERIFIED')

    def test_bad_hash_or_length_never_publishes(self):
        for manifest,content in [(ref(sha256='1'*64),DATA),
                                 (ref(),DATA[:-5]),(ref(),DATA+b'evil')]:
            with self.subTest(length=len(content)),self.assertRaises(VirtualModelError):
                rehydrate(manifest,self.dest,open_source=lambda _:io.BytesIO(content))
            self.assertFalse(self.dest.exists())
            self.assertFalse(list(self.root.glob('.omega-hydrate-*')))

    def test_preexisting_wrong_object_preserved(self):
        self.dest.write_bytes(b'not ours')
        with self.assertRaises(VirtualModelError):
            rehydrate(ref(),self.dest,open_source=lambda *_:self.fail('unwanted network'))
        self.assertEqual(self.dest.read_bytes(),b'not ours')

    def test_invalid_https_origin_and_filename(self):
        bad=['http://huggingface.co/acme/example-model/resolve/'+REV+'/weights.gguf',
             'https://evil.com/acme/example-model/resolve/'+REV+'/weights.gguf',
             'https://127.0.0.1/acme/example-model/resolve/'+REV+'/weights.gguf',
             'https://huggingface.co:8443/acme/example-model/resolve/'+REV+'/weights.gguf',
             'https://user:pass@huggingface.co/acme/example-model/resolve/'+REV+'/weights.gguf',
             'https://huggingface.co/acme/example-model/resolve/main/weights.gguf',
             'https://huggingface.co/acme/example-model/resolve/'+REV+'/../weights.gguf']
        for url in bad:
            with self.subTest(url=url),self.assertRaises(VirtualModelError):validate_reference(ref(url=url))

    def test_revision_must_match_path_and_sha(self):
        for data in [ref(revision='b'*40),ref(sha256='x'*64),ref(license=''),ref(size_bytes=True),ref(size_bytes=-1),
                     ref(extra='unexpected')]:
            with self.subTest(data=data),self.assertRaises(VirtualModelError):validate_reference(data)

    def test_no_symlink_or_public_destination(self):
        other=self.root/'elsewhere';other.write_bytes(b'untouched')
        self.dest.symlink_to(other)
        with self.assertRaises(VirtualModelError):rehydrate(ref(),self.dest,open_source=self.stream)
        self.assertEqual(other.read_bytes(),b'untouched')
        self.dest.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(VirtualModelError):rehydrate(ref(),self.dest,open_source=self.stream)

    def test_bounded_streaming_does_not_read_all_at_once(self):
        class Checked(io.BytesIO):
            def read(self,n=-1):
                if n<0 or n>2*1024*1024:raise AssertionError('unbounded read')
                return super().read(n)
        result=rehydrate(ref(),self.dest,open_source=lambda _:Checked(DATA))
        self.assertEqual(result['size_bytes'],len(DATA))

    def test_transport_failure_removes_partial(self):
        class Fail(io.BytesIO):
            def __init__(self):super().__init__(DATA[:1024]);self.calls=0
            def read(self,n=-1):
                self.calls+=1
                if self.calls>1:raise OSError('link failed')
                return super().read(n)
        with self.assertRaises(VirtualModelError):
            rehydrate(ref(),self.dest,open_source=lambda _:Fail())
        self.assertFalse(self.dest.exists())

if __name__=='__main__':unittest.main()
