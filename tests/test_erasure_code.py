"""Deterministic property tests for systematic Cauchy Reed-Solomon GF(256)."""
from __future__ import annotations

import itertools
import random
import unittest

from atlas import reed_solomon as rs


class CauchyErasureProperties(unittest.TestCase):
    def test_all_erasure_patterns_at_limit(self):
        rng = random.Random(20261121)
        for k, parity in ((4, 2), (8, 3)):
            content = bytes(rng.getrandbits(8) for _ in range(733))
            encoded = rs.encode(content, k=k, parity=parity)
            self.assertEqual(len(encoded), k + parity)
            self.assertEqual(len({len(x) for x in encoded}), 1)
            self.assertEqual(b''.join(encoded[:k])[:len(content)], content)
            for erased in itertools.combinations(range(k + parity), parity):
                surviving = {i: shard for i, shard in enumerate(encoded) if i not in erased}
                rebuilt = rs.recover(surviving, length=len(content), k=k, parity=parity)
                self.assertEqual(rebuilt, encoded, (k, parity, erased))

    def test_seeded_random_erasures_and_byte_lengths(self):
        rng = random.Random(750917)
        for k, parity in ((4, 2), (8, 3)):
            for size in (1, 2, 3, k - 1, k, k + 1, 253, 4097, 8199):
                payload = rng.randbytes(size)
                coded = rs.encode(payload, k=k, parity=parity)
                for losses in range(parity + 1):
                    missing = set(rng.sample(range(k + parity), losses))
                    available = {i: b for i, b in enumerate(coded) if i not in missing}
                    got = rs.recover(available, length=size, k=k, parity=parity)
                    self.assertEqual(got, coded)
                    self.assertEqual(b''.join(got[:k])[:size], payload)

    def test_corruption_in_surviving_shard_detected_with_redundancy(self):
        encoded = rs.encode(b'ABCDEFGH' * 700, k=4, parity=2)
        original = {i: b for i, b in enumerate(encoded)}
        corrupted = dict(original)
        bad = bytearray(corrupted[5]); bad[0] ^= 1; corrupted[5] = bytes(bad)
        with self.assertRaises(rs.ErasureError):
            rs.recover(corrupted, length=5600, k=4, parity=2)
        # Without independent hashes, k of n corrupted shards cannot be trusted.

    def test_missing_beyond_parity_fails_closed(self):
        for k, p in ((4, 2), (8, 3)):
            encoded = rs.encode(b'Z' * 133, k=k, parity=p)
            survivors = {i: b for i, b in enumerate(encoded[:k - 1])}
            with self.assertRaises(rs.ErasureError):
                rs.recover(survivors, length=133, k=k, parity=p)

    def test_invalid_profiles_and_shard_indices(self):
        for k, parity in ((2, 1), (4, 3), (8, 2), (0, 0)):
            with self.subTest(k=k, p=parity), self.assertRaises(rs.ErasureError):
                rs.encode(b'A', k=k, parity=parity)
        code = rs.encode(b'a' * 500, k=4, parity=2)
        invalid = [
            {-1: code[0], 1: code[1], 2: code[2], 3: code[3]},
            {True: code[0], 1: code[1], 2: code[2], 3: code[3]},
            {0: code[0], 1: code[1], 2: code[2], 6: code[3]},
            {0: code[0], 1: code[1], 2: code[2], 3: code[3][:-1]},
        ]
        for shards in invalid:
            with self.assertRaises(rs.ErasureError):
                rs.recover(shards, length=500, k=4, parity=2)

    def test_adaptive_profile_only_when_domains_suffice(self):
        self.assertEqual(rs.select_profile(6), (4, 2))
        self.assertEqual(rs.select_profile(10), (4, 2))
        self.assertEqual(rs.select_profile(11), (8, 3))
        with self.assertRaises(rs.ErasureError):
            rs.select_profile(5)
        for invalid in (True, 0, 256, -1):
            with self.assertRaises(rs.ErasureError):
                rs.select_profile(invalid)

    def test_actual_storage_overhead_less_than_two_copies(self):
        for size in (65536, 2097152):
            for k, p in ((4, 2), (8, 3)):
                payload = bytes((i * 19 + 3) % 256 for i in range(size))
                shards = rs.encode(payload, k=k, parity=p)
                self.assertEqual(sum(map(len, shards)), ((size + k - 1) // k) * (k + p))
                self.assertLess(sum(map(len, shards)), size * 2)


if __name__ == '__main__':
    unittest.main()
