"""Executable contract tests for OMEGA-X v1; no real device required."""
from __future__ import annotations
import importlib.util
import json
import os
import pathlib
import struct
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def kv(key, typ, value):
    s = key.encode()
    if typ == 8:
        v = value.encode()
        return struct.pack('<Q', len(s)) + s + struct.pack('<IQ', typ, len(v)) + v
    return struct.pack('<Q', len(s)) + s + struct.pack('<II', typ, value)


def gguf(arch='qwen3vl', embedding=2560, extra=b''):
    pairs = [kv('general.architecture', 8, arch), kv('general.file_type', 4, 15), kv(arch+'.embedding_length',4,embedding)]
    return b'GGUF' + struct.pack('<IQQ',3,0,len(pairs)+bool(extra)) + b''.join(pairs) + extra


class HeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = load('inventory_v1','termux/model_inventory.py')

    def test_full_gguf_metadata_and_quantization(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'Huihui-Qwen.gguf'
            p.write_bytes(gguf())
            h=self.inv.inspect_binary_header(p)
            self.assertEqual(h['architecture'],'qwen3vl')
            self.assertEqual(h['quantization'],'Q4_K_M')
            self.assertEqual(h['metadata']['qwen3vl.embedding_length'],2560)
            self.assertEqual(h['version'],3)

    def test_metadata_larger_than_64k(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'large.gguf'
            long=kv('general.description',8,'x'*90000)
            p.write_bytes(gguf(extra=long))
            self.assertEqual(len(self.inv.inspect_binary_header(p)['metadata']['general.description']),90000)

    def test_reject_truncated_gguf(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'bad.gguf'
            p.write_bytes(b'GGUF'+struct.pack('<IQQ',3,0,1))
            with self.assertRaises(ValueError): self.inv.inspect_binary_header(p)

    def test_safetensors_header_over_2_mb_and_dtype(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'wan.safetensors'
            header={'__metadata__':{'modelspec.architecture':'wan'}, 'w':{'dtype':'F16','shape':[1], 'data_offsets':[0,2]},'padding':{'dtype':'F16','shape':[0],'data_offsets':[2,2]}}
            # Padding JSON beyond 2 MB, permitted by safetensors header format.
            raw=json.dumps(header).encode() + b' '*(2_100_000-len(json.dumps(header).encode()))
            p.write_bytes(struct.pack('<Q',len(raw))+raw+b'xx')
            h=self.inv.inspect_binary_header(p)
            self.assertEqual(h['architecture'],'wan')
            self.assertEqual(h['tensor_count'],2)
            self.assertIn('F16',h['quantization'])

    def test_reject_out_of_bounds_safetensors_offset(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'bad.safetensors'
            raw=json.dumps({'w':{'dtype':'F16','shape':[4],'data_offsets':[0,1000]}}).encode()
            p.write_bytes(struct.pack('<Q',len(raw))+raw+b'xx')
            with self.assertRaises(ValueError): self.inv.inspect_binary_header(p)

    def test_no_false_mmproj_pairing_from_dimensions_only(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)
            (path/'Huihui-Qwen3.gguf').write_bytes(gguf())
            (path/'mmproj-F16.gguf').write_bytes(gguf('clip',2560))
            result=self.inv.scan_inventory(path)
            llm=next(x for x in result['models'] if x['role']=='llm_backbone')
            self.assertNotEqual(llm['mmproj_compatibility']['status'],'VERIFIED')

    def test_onxx_classified_without_attempting_gguf_parser(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'xor-neural.onnx'
            p.write_bytes(b'\x08\x09')
            self.assertEqual(self.inv.scan_inventory(pathlib.Path(d))['models'][0]['role'],'onnx_model')


class ArbiterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod=load('arbiter_v1','termux/resource_arbiter.py')

    def test_compute_sync_mutex(self):
        m=self.mod
        a=m.OmegaResourceArbiter(m.StaticProbe(5000,35.0))
        self.assertTrue(a.try_start(m.Job('a','LLM',1024))[0])
        self.assertFalse(a.try_start(m.Job('b','SYNC',1024))[0])
        a.complete('a')
        self.assertTrue(a.try_start(m.Job('b','SYNC',1024))[0])

    def test_thermal_hysteresis_and_unknown_fail_closed(self):
        m=self.mod
        probe=m.StaticProbe(6000,43.1)
        a=m.OmegaResourceArbiter(probe)
        self.assertFalse(a.try_start(m.Job('a','LLM',512))[0])
        probe.thermal_celsius=40.0
        self.assertFalse(a.try_start(m.Job('a','LLM',512))[0])
        probe.thermal_celsius=39.0
        self.assertTrue(a.try_start(m.Job('a','LLM',512))[0])
        a.complete('a')
        probe.thermal_celsius=None
        self.assertFalse(a.try_start(m.Job('b','VIDEO_LOCAL',512))[0])

    def test_reject_unknown_ram_and_overcommit(self):
        m=self.mod
        probe=m.StaticProbe(None,35.0)
        a=m.OmegaResourceArbiter(probe)
        self.assertFalse(a.try_start(m.Job('a','LLM',512))[0])
        probe.mem_available_mb=1300
        self.assertFalse(a.try_start(m.Job('a','LLM',512))[0])
        probe.mem_available_mb=2000
        self.assertTrue(a.try_start(m.Job('a','LLM',512))[0])

    def test_offload_does_not_allocate_local_video_ram(self):
        m=self.mod
        a=m.OmegaResourceArbiter(m.StaticProbe(2048,43.5))
        self.assertTrue(a.try_start(m.Job('remote','VIDEO_OFFLOAD',0))[0])


class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker=load('worker_v1','vps/media_worker.py')

    def test_reject_paths_outside_model_directory(self):
        with tempfile.TemporaryDirectory() as d:
            base=pathlib.Path(d)
            with self.assertRaises(ValueError):
                self.worker.validate_job({'id':'job1','engine':'wan','diffusion_model':'../../etc/passwd','t5xxl':'x','vae':'x','prompt':'test'},base)

    def test_no_completed_state_if_binary_fails(self):
        with tempfile.TemporaryDirectory() as d:
            base=pathlib.Path(d)
            media=base/'models';media.mkdir()
            for fn in ('wan.gguf','t5.safetensors','vae.safetensors'):(media/fn).write_bytes(b'weights')
            queue=base/'queue';queue.mkdir()
            job={'id':'job1','engine':'wan','diffusion_model':'wan.gguf','t5xxl':'t5.safetensors','vae':'vae.safetensors','prompt':'x','steps':2,'width':256,'height':256,'frames':5}
            self.worker.enqueue(queue,job)
            bad=base/'bad';bad.write_text('#!/bin/sh\nexit 5\n');bad.chmod(0o755)
            result=self.worker.run_once(queue,media,bad,timeout=5)
            self.assertEqual(result['state'],'FAILED')
            self.assertFalse((queue/'completed'/'job1.json').exists())

    def test_interrupted_running_job_is_not_silently_completed(self):
        with tempfile.TemporaryDirectory() as d:
            queue=pathlib.Path(d)
            (queue/'running').mkdir()
            (queue/'running'/'job9.json').write_text('{"id":"job9"}')
            self.worker.recover_interrupted(queue)
            self.assertTrue((queue/'failed'/'job9.json').exists())
            status=json.loads((queue/'outputs'/'job9.status.json').read_text())
            self.assertEqual(status['state'],'FAILED_INTERRUPTED')

    def test_success_only_when_artifact_written(self):
        with tempfile.TemporaryDirectory() as d:
            base=pathlib.Path(d)
            media=base/'models';media.mkdir()
            for fn in ('wan.gguf','t5.safetensors','vae.safetensors'):(media/fn).write_bytes(b'weights')
            queue=base/'queue';queue.mkdir()
            job={'id':'job2','engine':'wan','diffusion_model':'wan.gguf','t5xxl':'t5.safetensors','vae':'vae.safetensors','prompt':'test','steps':2,'width':256,'height':256,'frames':5}
            self.worker.enqueue(queue,job)
            fake=base/'fake';fake.write_text('#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then shift; printf xx > "$1"; exit 0; fi; shift; done\nexit 10\n');fake.chmod(0o755)
            result=self.worker.run_once(queue,media,fake,timeout=5)
            self.assertEqual(result['state'],'COMPLETED')
            self.assertTrue((queue/'completed'/'job2.json').exists())
            self.assertTrue(any((queue/'outputs').iterdir()))


if __name__ == '__main__': unittest.main()
