"""Benchmark contract must report measured times, not invented speedup."""
import unittest
from tools import bench_erasure


class BenchContractTests(unittest.TestCase):
    def test_real_encode_decode_bench_reports_bytes_and_validation(self):
        data=bench_erasure.run(size=65536,repeats=1,seed=20261121)
        self.assertEqual(data['case_bytes'],65536)
        self.assertEqual(data['repeat_count'],1)
        self.assertEqual(len(data['profiles']),2)
        for row in data['profiles']:
            self.assertGreaterEqual(row['encode_ms_median'],0)
            self.assertGreaterEqual(row['recover_ms_median'],0)
            self.assertTrue(row['sha256_verified'])
            self.assertLess(row['encoded_bytes'],row['two_copy_bytes'])
        with self.assertRaises(ValueError):bench_erasure.run(size=True,repeats=1,seed=1)
        with self.assertRaises(ValueError):bench_erasure.run(size=65536,repeats=0,seed=1)

if __name__=='__main__':unittest.main()
