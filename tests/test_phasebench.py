import unittest
from tools.phasebench import benchmark

class PhaseBenchTests(unittest.TestCase):
    def test_deterministic_synthetic_replay(self):
        a=benchmark(cases=60,seed=20261115)
        b=benchmark(cases=60,seed=20261115)
        self.assertEqual(a,b)
        self.assertEqual(a['verified_certificates'],60)
        self.assertGreater(a['naive_overcommit_cases'],0)
        self.assertGreater(a['primary_feasible'],0)
        self.assertGreater(a['blocked'],0)

if __name__=='__main__':unittest.main()
