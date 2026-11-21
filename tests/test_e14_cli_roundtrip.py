"""CLI E2E with a real subprocess and two local private CAS volumes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from atlas.quota_ledger import Ledger


class CLIRoundtrip(unittest.TestCase):
    def test_cli_ingest_restore_1mib_three_chunks_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            input_path=root/'source.bin';payload=(b'OMEGA-SERVER-E14\x00'+bytes(range(256)))*4300
            input_path.write_bytes(payload)
            original=hashlib.sha256(payload).hexdigest()
            stores={}
            db=root/'ledger.sqlite';ledger=Ledger(db)
            for index in range(2):
                pool=f'pool{index}';p=root/pool;p.mkdir(mode=0o700)
                stores[pool]={'path':str(p),'domain':f'domain{index}'}
                ledger.enroll(pool,{k:4000000 if k.endswith('bytes') else 500 for k in
                   ('storage_bytes','write_bytes','read_bytes','write_ops','read_ops','egress_bytes')},now=1)
            store_file=root/'stores.json';store_file.write_text(json.dumps(stores))
            key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            doc=root/'manifest.json';out=root/'recovered.bin'
            args=[sys.executable,'-m','atlas.secure_fabric','--manifest',str(doc),'--key',str(key),
                  '--ledger',str(db),'--stores',str(store_file),'--epoch','1']
            repo=Path(__file__).resolve().parents[1]
            p=subprocess.run(args+['ingest','--source',str(input_path),'--policy-sha256','d'*64,
                               '--archive-id','c'*32,'--chunk-bytes','524288','--copies','2'],cwd=repo,
                               capture_output=True,text=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            receipt=json.loads(p.stdout)
            self.assertEqual(receipt['sha256'],original)
            self.assertGreater(receipt['chunks'],1)
            q=subprocess.run(args+['restore','--pin',receipt['manifest_sha256'],'--destination',str(out)],
                              cwd=repo,capture_output=True,text=True,timeout=30)
            self.assertEqual(q.returncode,0,q.stderr)
            self.assertEqual(out.read_bytes(),payload)
            self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(),original)
            blocked=subprocess.run(args+['restore','--pin',receipt['manifest_sha256'],'--destination',str(out)],
                                   cwd=repo,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(blocked.returncode,0)
            self.assertEqual(out.read_bytes(),payload)


if __name__=='__main__':unittest.main()
