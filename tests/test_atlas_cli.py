"""CLI end-to-end local file staging, planning, provenance and packaging gates."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from atlas.cli import doctor

ROOT=Path(__file__).resolve().parents[1]
CMD=[sys.executable,str(ROOT/'tools/atlasctl.py')]

class AtlasCLITests(unittest.TestCase):
    def run_cli(self,*args):
        return subprocess.run([*CMD,*map(str,args)],capture_output=True,text=True,timeout=20)
    def test_merkle_manifest_stage_verify_cli(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'model.gguf';src.write_bytes(b'x'*200000);manifest=root/'manifest.json';dst=root/'staged.gguf'
            self.assertEqual(self.run_cli('manifest',src,manifest,'--chunk-mib','1').returncode,0)
            self.assertEqual(self.run_cli('stage',src,dst,manifest).returncode,0)
            self.assertEqual(self.run_cli('verify-model',dst,manifest).returncode,0)
            dst.write_bytes(b'evil')
            self.assertNotEqual(self.run_cli('verify-model',dst,manifest).returncode,0)
    def test_audit_keygen_attest_verify_cli(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);key=root/'key';log=root/'log';rec=root/'record.json';out=root/'output'
            rec.write_text(json.dumps({'stage':'demo','status':'completed','prompt':'secret'}))
            out.write_bytes(b'real output')
            self.assertEqual(self.run_cli('audit-keygen',key).returncode,0)
            self.assertEqual(self.run_cli('attest','--log',log,'--key',key,'--record',rec,'--output',out).returncode,0)
            self.assertEqual(self.run_cli('verify-audit','--log',log,'--key',key,'--outputs').returncode,0)
            out.write_bytes(b'tamper')
            self.assertNotEqual(self.run_cli('verify-audit','--log',log,'--key',key,'--outputs').returncode,0)
    def test_doctor_never_calls_metadata_verified_execution(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'model.gguf').write_bytes(b'abc')
            report=doctor(p,{'model':{'filename':'model.gguf','bytes':3,'format':'gguf','role':'llm','lineage_verified':False}})
            self.assertEqual(report['size_matches'],1)
            self.assertEqual(report['items'][0]['status'],'SIZE_MATCH_METADATA_ONLY')
    def test_package_allowlist_blocks_secrets_and_weights(self):
        from tools.package import allowed
        secret=ROOT/'atlas'/'secret.key';weight=ROOT/'catalog'/'weight.gguf'
        secret.write_bytes(b'secret');weight.write_bytes(b'weights')
        try:
            self.assertFalse(allowed(secret));self.assertFalse(allowed(weight))
        finally:
            secret.unlink();weight.unlink()
    def test_catalog_has_44_drive_metadata_items(self):
        inv=json.loads((ROOT/'catalog/drive_inventory.json').read_text())
        self.assertEqual(inv['item_count'],44)
        self.assertEqual(len(inv['items']),44)
        self.assertEqual(sum(x['name']=='mmproj-F16.gguf' for x in inv['items']),2)

if __name__=='__main__':unittest.main()
