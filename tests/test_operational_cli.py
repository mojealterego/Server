"""Subprocess acceptance for E16 namespace and E18 pinned offline cache."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]

class CliTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)

    def command(self,module,*args):
        return subprocess.run([sys.executable,'-m',module,*map(str,args)],cwd=PROJECT,
                              capture_output=True,text=True,timeout=10)

    def test_namespace_cli_transaction_reopen(self):
        db=self.root/'namespace.sqlite'
        common=['--db',str(db),'--tenant','owner']
        put=self.command('atlas.global_namespace',*common,'put','models/demo.gguf',
             '--manifest','a'*64,'--archive','b'*64,'--policy','c'*64,
             '--bytes','1024','--epoch','1','--expect','0','--op','transaction-1')
        self.assertEqual(put.returncode,0,put.stderr)
        self.assertEqual(json.loads(put.stdout)['revision'],1)
        get=self.command('atlas.global_namespace',*common,'get','models/demo.gguf')
        self.assertEqual(get.returncode,0,get.stderr)
        self.assertEqual(json.loads(get.stdout)['size_bytes'],1024)
        stale=self.command('atlas.global_namespace',*common,'put','models/demo.gguf',
             '--manifest','a'*64,'--archive','b'*64,'--policy','c'*64,
             '--bytes','200','--epoch','1','--expect','0','--op','transaction-2')
        self.assertNotEqual(stale.returncode,0)

    def test_virtual_model_cli_cached_file_no_network(self):
        content=b'verified-offline-public-model'
        file=self.root/'model.gguf';file.write_bytes(content)
        doc={'schema':'omega.virtual-model.v1',
             'url':'https://huggingface.co/acme/model/resolve/'+ 'a'*40+'/model.gguf',
             'revision':'a'*40,'license':'apache-2.0',
             'sha256':hashlib.sha256(content).hexdigest(),'size_bytes':len(content)}
        spec=self.root/'reference.json';spec.write_text(json.dumps(doc))
        r=self.command('atlas.virtual_model','--reference',spec,'--destination',file)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout)['status'],'ALREADY_VERIFIED')
        doc['sha256']='f'*64;spec.write_text(json.dumps(doc))
        r=self.command('atlas.virtual_model','--reference',spec,'--destination',file)
        self.assertNotEqual(r.returncode,0)

if __name__=='__main__':unittest.main()
