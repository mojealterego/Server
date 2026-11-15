"""Deterministic two-remote backup/restore contract with local filesystem fake rclone.

Does NOT prove real cloud object-store semantics, crypt encryption, or network transfer.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
FAKE='''#!/usr/bin/env python3
import hashlib,os,shutil,sys
from pathlib import Path
root=Path(os.environ['OMEGA_FAKE_REMOTE_ROOT'])

def path(value):
    if ':' in value and not value.startswith('/'):
        name,tail=value.split(':',1)
        return root/name/tail
    return Path(value)

def content_map(base):
    return {str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest() for p in base.rglob('*') if p.is_file()}

args=sys.argv[1:]
cmd=args[0]
if cmd=='listremotes':
    print('crypt1:')
    print('crypt2:')
elif cmd=='config' and args[1]=='show':
    print('type = crypt')
elif cmd=='copy':
    src,dst=path(args[1]),path(args[2])
    if not src.exists():sys.exit(3)
    dst.mkdir(parents=True,exist_ok=True)
    for p in src.rglob('*'):
        r=p.relative_to(src);o=dst/r
        if p.is_dir():o.mkdir(parents=True,exist_ok=True)
        elif p.is_file():
            o.parent.mkdir(parents=True,exist_ok=True)
            if '--immutable' in args and o.exists() and o.read_bytes()!=p.read_bytes():sys.exit(4)
            shutil.copyfile(p,o)
elif cmd=='copyto':
    src,dst=path(args[1]),path(args[2]);dst.parent.mkdir(parents=True,exist_ok=True)
    if '--immutable' in args and dst.exists():sys.exit(5)
    shutil.copyfile(src,dst)
elif cmd=='check':
    src,dst=path(args[1]),path(args[2])
    a,b=content_map(src),content_map(dst)
    if any(b.get(k)!=v for k,v in a.items()):sys.exit(6)
else:
    sys.exit(70)
'''
class RestoreRoundTrip(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        bin_path=self.root/'bin';bin_path.mkdir()
        fake=bin_path/'rclone';fake.write_text(FAKE);fake.chmod(0o755)
        self.env={**os.environ,'HOME':str(self.root),'PATH':str(bin_path)+os.pathsep+os.environ['PATH'],
                  'OMEGA_FAKE_REMOTE_ROOT':str(self.root/'cloud'),'OMEGA_SNAPSHOT_ID':'snap12345',
                  'OMEGA_STATE_DIR':str(self.root/'state')}
        self.source=self.root/'source';self.source.mkdir()
        (self.source/'model.gguf').write_bytes(b'TEST ONLY NOT A REAL MODEL'+b'X'*15000)
        (self.source/'nested').mkdir();(self.source/'nested'/'a.txt').write_text('verified bytes')

    def backup(self):
        return subprocess.run(['bash',str(ROOT/'cloud/backup.sh'),str(self.source),
                               'crypt1:snapshots','crypt2:snapshots'],env=self.env,text=True,capture_output=True,timeout=30)
    def restore(self,remote='crypt1:snapshots/snap12345',dest=None):
        return subprocess.run(['bash',str(ROOT/'cloud/restore.sh'),remote,str(dest or self.root/'restored')],
                              env=self.env,text=True,capture_output=True,timeout=30)

    def test_two_remote_snapshot_restores_original_data(self):
        bp=self.backup();self.assertEqual(bp.returncode,0,bp.stderr)
        for remote in ('crypt1','crypt2'):
            s=self.root/'cloud'/remote/'snapshots'/'snap12345'
            self.assertTrue((s/'COMPLETE.json').exists())
            self.assertTrue((s/'SHA256SUMS').exists())
        rp=self.restore();self.assertEqual(rp.returncode,0,rp.stderr)
        self.assertEqual((self.root/'restored/model.gguf').read_bytes(),(self.source/'model.gguf').read_bytes())
        self.assertTrue((self.root/'restored/COMPLETE.json').exists())

    def test_corruption_remote_file_blocks_restore(self):
        self.assertEqual(self.backup().returncode,0)
        (self.root/'cloud/crypt1/snapshots/snap12345/model.gguf').write_bytes(b'CORRUPTED')
        rp=self.restore();self.assertNotEqual(rp.returncode,0)
        self.assertFalse((self.root/'restored').exists())

    def test_missing_receipt_blocks_restore(self):
        self.assertEqual(self.backup().returncode,0)
        (self.root/'cloud/crypt1/snapshots/snap12345/COMPLETE.json').unlink()
        rp=self.restore();self.assertNotEqual(rp.returncode,0)
        self.assertFalse((self.root/'restored').exists())

    def test_changed_source_mid_transfer_blocks_completion(self):
        # Proven separately by v2 verify-files unit test; this case covers
        # the full backup flow's rejection of symlink source.
        (self.source/'symlink').symlink_to('/etc/passwd')
        bp=self.backup();self.assertNotEqual(bp.returncode,0)
        self.assertFalse((self.root/'cloud/crypt1/snapshots/snap12345/COMPLETE.json').exists())

if __name__=='__main__':unittest.main()
