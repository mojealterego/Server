"""ATLAS resumable, integrity-verified model staging tests."""
from pathlib import Path
import tempfile
import unittest
from atlas.merkle import make_manifest, stage_file, verify_file, ManifestError

class MerkleTests(unittest.TestCase):
    def test_manifest_and_stage(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'model.gguf'; dest=root/'staged.gguf'
            source.write_bytes(b'abcd'*307+ b'xyz')
            manifest=make_manifest(source,chunk_size=128)
            self.assertTrue(verify_file(source,manifest))
            result=stage_file(source,dest,manifest)
            self.assertEqual(result['status'],'STAGED')
            self.assertEqual(dest.read_bytes(),source.read_bytes())
            self.assertEqual(result['copied_chunks'],len(manifest['chunks']))
            self.assertEqual(stage_file(source,dest,manifest)['status'],'ALREADY_PRESENT')
    def test_corruption_is_repaired_on_resume(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'model.gguf';dest=root/'staged.gguf'
            source.write_bytes(bytes(range(256))*4)
            manifest=make_manifest(source,chunk_size=64)
            partial=dest.with_name(dest.name+'.omega-part')
            partial.write_bytes(source.read_bytes()[:64]+b'Q'*64)
            result=stage_file(source,dest,manifest)
            self.assertEqual(result['reused_chunks'],1)
            self.assertEqual(result['copied_chunks'],15)
            self.assertTrue(verify_file(dest,manifest))
    def test_source_mismatch_fails_without_publish(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';dest=root/'target'
            source.write_bytes(b'a'*200)
            manifest=make_manifest(source,chunk_size=64)
            source.write_bytes(b'b'*200)
            with self.assertRaises(ManifestError):stage_file(source,dest,manifest)
            self.assertFalse(dest.exists())
    def test_corrupt_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'m';p.write_bytes(b'abcd'*50)
            m=make_manifest(p,chunk_size=64)
            m['chunks'][0]='0'*64
            with self.assertRaises(ManifestError):stage_file(p,Path(d)/'out',m)
    def test_symlink_and_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);s=root/'source';s.write_bytes(b'a'*200)
            m=make_manifest(s,chunk_size=64)
            link=root/'link';link.symlink_to(s)
            with self.assertRaises(ManifestError):make_manifest(link,chunk_size=64)
            target=root/'dest';target.write_bytes(b'different')
            with self.assertRaises(FileExistsError):stage_file(s,target,m)
    def test_hardlinked_partial_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'src';src.write_bytes(b'A'*512)
            m=make_manifest(src,chunk_size=64);dest=root/'dest'
            (root/'dest.omega-part').hardlink_to(src)
            with self.assertRaises(ManifestError):stage_file(src,dest,m)
            self.assertEqual(src.read_bytes(),b'A'*512)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);s=root/'empty';s.write_bytes(b'')
            m=make_manifest(s,chunk_size=64)
            self.assertEqual(m['chunks'],[])
            self.assertTrue(verify_file(s,m))
            self.assertEqual(stage_file(s,root/'new',m)['status'],'STAGED')

if __name__=='__main__':unittest.main()
