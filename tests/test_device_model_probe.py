"""Bounded preflight regression tests (not hardware or LLM E2E)."""
from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from termux import device_model_probe as m


class DeviceModelProbeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name)
        (self.path / 'Huihui-Qwen3-VL-2B.gguf').write_bytes(b'GGUF' + b'Z' * 1024)

    @staticmethod
    def metadata(_):
        return {'format': 'gguf', 'architecture': 'qwen3vl', 'tensor_count': 3}

    def runprobe(self, **kwargs):
        return m.probe(self.path, metadata_reader=self.metadata, get_affinity=lambda: {2, 4},
                       clock=lambda: 42, **kwargs)

    def test_actual_readonly_mmap_of_fixture(self):
        r = self.runprobe(expected_count=1)
        self.assertEqual(r['status'], 'PASS_READONLY_PROBES')
        self.assertTrue(r['models'][0]['mmap_read_page'])
        self.assertEqual(r['process_allowed_cpus'], [2, 4])
        self.assertEqual(r['evidence_scope']['S24_mobile_e2e'], 'NOT_RUN')

    def test_full_file_hash_optional(self):
        r = self.runprobe(sha256=True)
        import hashlib
        self.assertEqual(r['models'][0]['sha256'], hashlib.sha256(
            (self.path / 'Huihui-Qwen3-VL-2B.gguf').read_bytes()).hexdigest())

    def test_hash_not_falsely_claimed(self):
        self.assertIsNone(self.runprobe()['models'][0]['sha256'])
        self.assertFalse(self.runprobe()['evidence_scope']['full_file_sha256'])

    def test_count_mismatch_fails_closed(self):
        r = self.runprobe(expected_count=6)
        self.assertEqual(r['status'], 'FAIL')
        self.assertEqual(r['observed_file_count'], 1)

    def test_symlink_model_refused(self):
        (self.path / 'other.gguf').symlink_to(self.path / 'Huihui-Qwen3-VL-2B.gguf')
        r = self.runprobe()
        self.assertEqual(r['status'], 'FAIL')
        self.assertEqual(r['models'][1]['status'], 'FAIL')

    def test_invalid_model_header_fails(self):
        r = m.probe(self.path, metadata_reader=lambda p: {'format': 'other'}, get_affinity=lambda: set())
        self.assertEqual(r['status'], 'FAIL')

    def test_header_parsing_exception_fails(self):
        def broken(_):
            raise ValueError('Corrupt GGUF')
        r = m.probe(self.path, metadata_reader=broken, get_affinity=lambda: {2})
        self.assertEqual(r['status'], 'FAIL')

    def test_file_mutation_during_probe_fails(self):
        def mutate(p):
            p.write_bytes(b'different')
            return self.metadata(p)
        self.assertEqual(m.probe(self.path, metadata_reader=mutate)['status'], 'FAIL')

    def test_reject_invalid_options(self):
        for kw in ({'expected_count': True}, {'expected_count': 0},
                   {'expected_count': 257}, {'sha256': 'yes'}):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.runprobe(**kw)

    def test_missing_directory_fails(self):
        with self.assertRaises(ValueError):
            m.probe(self.path / 'missing')

    def test_wrong_file_format_not_counted(self):
        (self.path / 'readme.txt').write_text('unrelated')
        self.assertEqual(self.runprobe()['observed_file_count'], 1)

    def test_report_no_fake_inference_pass(self):
        r = self.runprobe()
        payload = json.dumps(r)
        self.assertNotIn('GREEN-MOBILE VERIFIED', payload)
        for field in ('OpenCL_NPU_acceleration', 'TTFT_and_thermal_benchmark', 'actual_llm_inference'):
            self.assertEqual(r['evidence_scope'][field], 'NOT_RUN')

    def test_json_report_written_privately(self):
        output = self.path / 'report.json'
        # This test checks probe output structure directly, without requiring device-specific CLI.
        stub = types.ModuleType('model_inventory')
        stub.resolve_default_model_dir = lambda: self.path
        stub.inspect_binary_header = self.metadata
        with patch.dict(sys.modules, {'model_inventory': stub}):
            rc = m.main(['--dir', str(self.path), '--expect-count', '1',
                         '--json-out', str(output)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output.read_text())['status'], 'PASS_READONLY_PROBES')
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
