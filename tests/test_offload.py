"""Safe remote job offload contracts, using a local stub at the rclone boundary."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('offload_v2',ROOT/'termux/offload.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class SubmitTests(unittest.TestCase):
    def job(self):
        return {'id':'media2026','engine':'wan','prompt':'test scene',
                'diffusion_model':'wan.gguf','t5xxl':'umt5.safetensors','vae':'vae.safetensors'}
    def test_accept_valid_job_and_reject_path(self):
        self.assertEqual(module.validate_submission(self.job()),'media2026')
        job=self.job();job['vae']='../etc/passwd'
        with self.assertRaises(ValueError):module.validate_submission(job)
    def test_reject_extra_command_and_invalid_name(self):
        job=self.job();job['command']='sh -c stuff'
        with self.assertRaises(ValueError):module.validate_submission(job)
        with self.assertRaises(ValueError):module.validate_remote('sftp:../secrets')
    def test_pinned_remote_required(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);jobfile=root/'job.json';jobfile.write_text(json.dumps(self.job()))
            fake=root/'rclone';fake.write_text('#!/bin/sh\nif [ "$1" = config ]; then echo "type = sftp"; exit 0; fi\nexit 0\n');fake.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError,'pinning'):
                module.submit(jobfile,'vps:queue/pending',rclone=str(fake))
    def test_mocked_sftp_submission(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);jobfile=root/'job.json';jobfile.write_text(json.dumps(self.job()))
            fake=root/'rclone';fake.write_text('#!/bin/sh\nif [ "$1" = config ]; then printf "type = sftp\\nknown_hosts_file = /private/hosts\\n"; exit 0; fi\nif [ "$1" = copyto ]; then printf "%s" "$3" > "'+str(root/'result')+'"; exit 0; fi\nexit 1\n');fake.chmod(0o755)
            target=module.submit(jobfile,'vps:queue/pending',rclone=str(fake))
            self.assertEqual(target,'vps:queue/pending/media2026.json')
            self.assertEqual((root/'result').read_text(),target)
    def test_doctor_is_offline(self):
        spec=importlib.util.spec_from_file_location('doctor_v2',ROOT/'tools/doctor.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as d:
            result=mod.doctor(Path(d))
            self.assertIn('available_memory_mb',result)
            self.assertIn('listening_ports_only',result)

if __name__=='__main__':unittest.main()
