"""ATLAS simulated Rclone range backend: real subprocess, no cloud credentials."""
import os
from pathlib import Path
import tempfile
import unittest
from atlas.remote import make_remote_manifest, stage_remote, validate_remote

FAKE='''#!/bin/sh
[ "$1" = cat ] || exit 2
printf '%s\\n' "$*" >> "$ATLAS_FAKE_LOG"
if [ "$3" = --offset ]; then
  dd if="$ATLAS_FAKE_SOURCE" bs=1 skip="$4" count="$6" status=none
else
  cat "$ATLAS_FAKE_SOURCE"
fi
'''


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.src=self.root/'remote.gguf';self.src.write_bytes(bytes(range(256))*8)
        self.fake=self.root/'rclone';self.fake.write_text(FAKE);self.fake.chmod(0o700)
        self.log=self.root/'calls'
        self.env=dict(os.environ,ATLAS_FAKE_SOURCE=str(self.src),ATLAS_FAKE_LOG=str(self.log))
    def tearDown(self):self.tmp.cleanup()
    def test_stream_manifest_and_stage(self):
        m=make_remote_manifest('drive:models/model.gguf',len(self.src.read_bytes()),rclone=str(self.fake),env=self.env,chunk_size=128)
        self.assertEqual(m['size_bytes'],self.src.stat().st_size)
        dst=self.root/'staged.gguf'
        res=stage_remote('drive:models/model.gguf',dst,m,rclone=str(self.fake),env=self.env)
        self.assertEqual(res['status'],'STAGED')
        self.assertEqual(dst.read_bytes(),self.src.read_bytes())
    def test_resume_fetches_only_missing_blocks(self):
        m=make_remote_manifest('drive:models/model.gguf',self.src.stat().st_size,rclone=str(self.fake),env=self.env,chunk_size=128)
        self.log.write_text('')
        dst=self.root/'staged.gguf';part=self.root/'staged.gguf.omega-part'
        part.write_bytes(self.src.read_bytes()[:256])
        res=stage_remote('drive:models/model.gguf',dst,m,rclone=str(self.fake),env=self.env)
        self.assertEqual(res['reused_chunks'],2)
        self.assertEqual(res['copied_chunks'],14)
        self.assertEqual(len(self.log.read_text().splitlines()),14)
    def test_corrupted_remote_fails_closed(self):
        m=make_remote_manifest('drive:models/model.gguf',self.src.stat().st_size,rclone=str(self.fake),env=self.env,chunk_size=128)
        self.src.write_bytes(b'Z'*self.src.stat().st_size)
        dst=self.root/'staged.gguf'
        with self.assertRaises(ValueError):stage_remote('drive:models/model.gguf',dst,m,rclone=str(self.fake),env=self.env)
        self.assertFalse(dst.exists())
    def test_unsafe_remote_rejected(self):
        for remote in ['drive:../secrets','drive:/abs','drive:folder/../../etc','-evil:path','drive:','drive:models/\\n']:
            with self.subTest(remote=remote),self.assertRaises(ValueError):validate_remote(remote)
    def test_remote_manifest_requires_exact_size(self):
        with self.assertRaises(ValueError):make_remote_manifest('drive:model.gguf',100,rclone=str(self.fake),env=self.env,chunk_size=128)

if __name__=='__main__':unittest.main()
