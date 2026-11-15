"""OMEGA-X v2 regression and negative-security tests (host/simulation)."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]

def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative)
    mod=importlib.util.module_from_spec(spec)
    sys.modules[name]=mod
    spec.loader.exec_module(mod)
    return mod

class V2ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.m=load('model_v2','termux/model_inventory.py')
    def write_safetensors(self,root,entries,payload=b"abcdefgh"):
        header=json.dumps(entries).encode()
        p=root/'model.safetensors'
        p.write_bytes(struct.pack('<Q',len(header))+header+payload)
        return p
    def test_reject_overlapping_safetensors_ranges(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d)
            p=self.write_safetensors(r,{'a':{'dtype':'F32','shape':[1],'data_offsets':[0,4]},'b':{'dtype':'F32','shape':[1],'data_offsets':[2,6]}})
            with self.assertRaisesRegex(ValueError,'overlap'): self.m.inspect_binary_header(p)
    def test_reject_wrong_tensor_size(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d)
            p=self.write_safetensors(r,{'a':{'dtype':'F32','shape':[3],'data_offsets':[0,4]}})
            with self.assertRaisesRegex(ValueError,'size'): self.m.inspect_binary_header(p)
    def test_reject_negative_tensor_dimension(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d)
            p=self.write_safetensors(r,{'a':{'dtype':'F16','shape':[-2],'data_offsets':[0,4]}})
            with self.assertRaisesRegex(ValueError,'dimension'): self.m.inspect_binary_header(p)

class V2WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.m=load('media_v2','vps/media_worker.py')
    def test_success_artifact_staged_then_published(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); q=r/'queue';models=r/'models';models.mkdir()
            for name in ['wan.gguf','t5.safetensors','vae.safetensors']:(models/name).write_bytes(b'x')
            fake=r/'sd-cli';fake.write_text('#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then shift; echo X > "$1"; exit 0; fi; shift; done\nexit 1\n');fake.chmod(0o755)
            j={'id':'v2job','engine':'wan','prompt':'test','diffusion_model':'wan.gguf','t5xxl':'t5.safetensors','vae':'vae.safetensors'}
            self.m.enqueue(q,j)
            result=self.m.run_once(q,models,fake,timeout=10)
            self.assertEqual(result['state'],'COMPLETED')
            self.assertTrue((q/'outputs/v2job.avi').is_file())
            self.assertEqual(list((q/'staging').glob('*.avi')),[])
    def test_reject_unexpected_job_command_fields(self):
        with tempfile.TemporaryDirectory() as d:
            m=Path(d);(m/'wan.gguf').write_bytes(b'x');(m/'t5.safetensors').write_bytes(b'x');(m/'vae.safetensors').write_bytes(b'x')
            j={'id':'j','engine':'wan','prompt':'test','diffusion_model':'wan.gguf','t5xxl':'t5.safetensors','vae':'vae.safetensors','pre_command':'rm -rf ~'}
            with self.assertRaisesRegex(ValueError,'Unsupported job fields'): self.m.validate_job(j,m)

class V2BackupTests(unittest.TestCase):
    def test_restore_refuses_non_empty_destination(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); destination=r/'existing';destination.mkdir();(destination/'keep').write_text('important')
            res=subprocess.run(['bash',str(ROOT/'cloud/restore.sh'),'crypt-one:backups/123456',str(destination)],capture_output=True,text=True)
            self.assertNotEqual(res.returncode,0)
            self.assertEqual((destination/'keep').read_text(),'important')
    def test_backup_refuses_symlink_in_source(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);src=r/'src';src.mkdir();(src/'unsafe').symlink_to('/etc/passwd')
            res=subprocess.run(['bash',str(ROOT/'cloud/backup.sh'),str(src),'crypt-one:backup','crypt-two:backup'],capture_output=True,text=True)
            self.assertNotEqual(res.returncode,0)
            self.assertIn('symlink',res.stderr.lower())

class V2MobileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.node=load('omega_node_v2','termux/omega_node.py')
    def test_lan_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError): self.node.validate_sftp_exposure('192.168.1.5',False)
        self.assertEqual(self.node.validate_sftp_exposure('192.168.1.5',True),'192.168.1.5')
        with self.assertRaises(ValueError): self.node.validate_sftp_exposure('0.0.0.0',True)

if __name__=='__main__':unittest.main()

class V2IdempotencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.m=load('media_v2_id','vps/media_worker.py')
    def test_duplicate_id_after_queue_transition_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            q=Path(d)
            self.m.enqueue(q,{'id':'repeat001','prompt':'x'})
            (q/'pending/repeat001.json').rename(q/'running/repeat001.json')
            with self.assertRaises(FileExistsError):
                self.m.enqueue(q,{'id':'repeat001','prompt':'y'})
    def test_concurrent_submit_single_owner(self):
        with tempfile.TemporaryDirectory() as d:
            q=Path(d);success=[];fail=[]
            def run():
                try:success.append(self.m.enqueue(q,{'id':'race001','prompt':'x'}))
                except (FileExistsError,RuntimeError):fail.append(1)
            threads=[threading.Thread(target=run) for _ in range(8)]
            for t in threads:t.start()
            for t in threads:t.join()
            self.assertEqual(len(success),1)
            self.assertEqual(len(fail),7)
    def test_reject_oversized_job_payload(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'64 KiB'):
                self.m.enqueue(Path(d),{'id':'oversized','prompt':'x'*70000})
