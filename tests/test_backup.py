"""Integration-level tests for backup command contract with a fake rclone boundary."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
FAKE_RCLONE='''#!/bin/sh
case "$1" in
  listremotes) printf 'r1:\\nr2:\\n' ;;
  config) printf '[%s]\\ntype = crypt\\n' "$3" ;;
  copy|check|copyto)
    printf '%s\\n' "$*" >> "$OMEGA_TEST_LOG"
    case "$*" in
      *r2:models* ) [ "${OMEGA_FAIL_REMOTE:-0}" != 1 ] || exit 88 ;;
    esac ;;
  *) exit 80 ;;
esac
'''

class BackupContracts(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.base=Path(self.t.name)
        (self.base/'bin').mkdir()
        rclone=self.base/'bin/rclone'
        rclone.write_text(FAKE_RCLONE)
        rclone.chmod(0o755)
        (self.base/'models').mkdir()
        (self.base/'models/sample.gguf').write_bytes(b'GGUF sample data')
        self.log=self.base/'commands.log'
        self.env={**os.environ,'HOME':str(self.base),'PATH':str(self.base/'bin')+os.pathsep+os.environ['PATH'],
                  'OMEGA_TEST_LOG':str(self.log),'OMEGA_SNAPSHOT_ID':'abc123'}

    def run_backup(self, env=None):
        return subprocess.run(['bash',str(ROOT/'cloud/backup.sh'),str(self.base/'models'),'r1:models','r2:models'],
                             env=env or self.env,text=True,capture_output=True,timeout=20)

    def test_success_requires_independent_download_checks(self):
        p=self.run_backup()
        self.assertEqual(p.returncode,0,p.stderr)
        lines=self.log.read_text().splitlines()
        self.assertEqual(sum(x.startswith('check ') and '--download' in x for x in lines),2)
        self.assertEqual(sum('COMPLETE.json' in x for x in lines),2)
        self.assertTrue(any('--immutable' in x for x in lines))

    def test_single_failed_remote_never_claims_complete(self):
        p=self.run_backup({**self.env,'OMEGA_FAIL_REMOTE':'1'})
        self.assertNotEqual(p.returncode,0)
        self.assertIn('Partial replication',p.stderr)
        self.assertNotIn('All 2 independent',p.stdout)
        lines=self.log.read_text().splitlines()
        self.assertFalse(any('COMPLETE.json' in x and 'r2:models' in x for x in lines))

    def test_reject_duplicate_remote_names(self):
        p=subprocess.run(['bash',str(ROOT/'cloud/backup.sh'),str(self.base/'models'),'r1:a','r1:b'],
                         env=self.env,text=True,capture_output=True,timeout=20)
        self.assertNotEqual(p.returncode,0)
        self.assertIn('Duplicate remote alias',p.stderr)

if __name__=='__main__':unittest.main()
