"""Release-bundle integration gates: prior PASS cannot certify modified code."""
from __future__ import annotations
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile
from tools import package
from tools.release_fingerprint import fingerprint

class PackageReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'Server'
        for dirname in ('atlas','reports','tools'):
            (self.root/dirname).mkdir(parents=True)
        (self.root/'README.md').write_text('trusted documentation\n')
        self.code = self.root/'atlas'/'worker.py'
        self.code.write_text('print(123)\n')
        self.report = self.root/'reports'/'verification.json'
        self.output = self.root.parent/'Server.zip'
        self.patch_root = patch.object(package,'ROOT',self.root)
        self.patch_out = patch.object(package,'OUTPUT',self.output)
        self.patch_root.start();self.patch_out.start()
        self.addCleanup(self.patch_root.stop);self.addCleanup(self.patch_out.stop)

    def generate_report(self, *, pinned=True):
        local = {'status':'PASS','unittest': {'executed': 3,'failures':0,'errors':0,'skipped':0}}
        if pinned:
            state = fingerprint(self.root, lambda p: package.allowed(p)
                                and p != self.report)
            local['verified_sources'] = state
        self.report.write_text(json.dumps({'local':local}))

    def package_quietly(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return package.main(['--skip-verify'])

    def test_stale_pass_report_cannot_package_changed_source(self):
        self.generate_report()
        self.assertEqual(self.package_quietly(),0)
        self.code.write_text('print(999)\n')
        with self.assertRaisesRegex(SystemExit,'reverify|changed|verification|source'):
            self.package_quietly()

    def test_missing_source_pin_does_not_package(self):
        self.generate_report(pinned=False)
        with self.assertRaisesRegex(SystemExit,'pin|verification|source'):
            self.package_quietly()

    def test_archived_evidence_present_while_unknown_reports_excluded(self):
        known = self.root/'reports'/'e21b-tenant-verification.txt'
        known.write_text('red green controlled fixture\n')
        unknown = self.root/'reports'/'secret-keys.txt'
        unknown.write_text('PRIVATE SECRET MATERIAL\n')
        self.generate_report()
        self.assertEqual(self.package_quietly(),0)
        with ZipFile(self.output) as bundle:
            names=set(bundle.namelist())
            self.assertIn('Server/reports/e21b-tenant-verification.txt',names)
            self.assertNotIn('Server/reports/secret-keys.txt',names)
            self.assertEqual(bundle.read('Server/reports/e21b-tenant-verification.txt'),known.read_bytes())

    def test_unchanged_bundle_is_deterministic_and_source_pin_survives_manifest(self):
        self.generate_report()
        self.assertEqual(self.package_quietly(),0)
        original=self.output.read_bytes()
        self.assertEqual(self.package_quietly(),0)
        self.assertEqual(self.output.read_bytes(),original)

if __name__=='__main__':unittest.main()
