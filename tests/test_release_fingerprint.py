"""RED/GREEN: verified source tree pin must catch stale or changed package inputs."""
from __future__ import annotations
import os
from pathlib import Path
import tempfile
import unittest
from tools.release_fingerprint import fingerprint, verify_pin, FingerprintError

class FingerprintTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        (self.root/'code').mkdir()
        self.a = self.root/'code'/'a.py'
        self.a.write_bytes(b'print(1)\n')
        self.allow = lambda p: p.suffix == '.py' and p.parent == self.root/'code'

    def test_stale_report_rejected_after_modification(self):
        pin = fingerprint(self.root, self.allow)
        verify_pin(self.root, self.allow, pin)
        self.a.write_bytes(b'print(2)\n')
        with self.assertRaises(FingerprintError):
            verify_pin(self.root, self.allow, pin)

    def test_add_remove_allowed_files_detected(self):
        original=fingerprint(self.root,self.allow)
        second=self.root/'code'/'b.py';second.write_bytes(b'print(99)\n')
        self.assertNotEqual(original,fingerprint(self.root,self.allow))
        second.unlink()
        self.assertEqual(original,fingerprint(self.root,self.allow))
        self.a.unlink()
        with self.assertRaises(FingerprintError): verify_pin(self.root,self.allow,original)

    def test_order_and_unlisted_files_do_not_change_digest(self):
        p=self.root/'code'/'b.py';p.write_bytes(b'x')
        a=fingerprint(self.root,self.allow)
        (self.root/'code'/'secret.key').write_bytes(b'private')
        self.assertEqual(a,fingerprint(self.root,self.allow))
        self.assertEqual(a['files'],2)

    def test_untrusted_or_malformed_pin_fails_closed(self):
        pin=fingerprint(self.root,self.allow)
        for invalid in ({}, {'sha256':pin['sha256'],'files':True},
                        {'sha256':'z'*64,'files':1}, {'sha256':pin['sha256'],'files':2}):
            with self.subTest(invalid=invalid),self.assertRaises(FingerprintError):
                verify_pin(self.root,self.allow,invalid)

    def test_symlink_input_is_denied(self):
        target=self.a
        alias=self.root/'code'/'b.py';alias.symlink_to(target)
        with self.assertRaises(FingerprintError): fingerprint(self.root,self.allow)

    def test_hardlinked_input_is_denied(self):
        alias=self.root/'code'/'b.py';os.link(self.a,alias)
        with self.assertRaises(FingerprintError): fingerprint(self.root,self.allow)

    def test_large_input_bound_is_enforced(self):
        with self.assertRaises(FingerprintError): fingerprint(self.root,self.allow,max_file_bytes=2)

    def test_empty_allowlist_is_not_success(self):
        with self.assertRaises(FingerprintError):fingerprint(self.root,lambda _:False)

    def test_deterministic_digest(self):
        p=fingerprint(self.root,self.allow)
        self.assertEqual(p,fingerprint(self.root,self.allow))
        self.assertEqual(len(p['sha256']),64)
        self.assertEqual(p['files'],1)

if __name__=='__main__':unittest.main()
