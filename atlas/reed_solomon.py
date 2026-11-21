"""Bounded systematic Cauchy Reed-Solomon erasure codec over GF(2^8).

Supported profiles: 4 data + 2 parity; 8 data + 3 parity. This codec
handles erasures, not arbitrary undetected Byzantine shard corruption.
Callers MUST verify independently pinned per-shard digests before decode.

All parity arithmetic is deterministic, offline and dependency-free.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Mapping

PROFILES = frozenset({(4, 2), (8, 3)})
MAX_PAYLOAD = 16 * 1024 * 1024 + 64
_POLY = 0x11D
_EXP = [0] * 512
_LOG = [0] * 256
v = 1
for i in range(255):
    _EXP[i] = v
    _LOG[v] = i
    v <<= 1
    if v & 256:
        v ^= _POLY
assert v == 1
for i in range(255, 512):
    _EXP[i] = _EXP[i-255]


class ErasureError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ErasureError(reason)


def _mul(a: int, b: int) -> int:
    return 0 if not a or not b else _EXP[_LOG[a] + _LOG[b]]


def _inv(a: int) -> int:
    require(0 < a < 256, "Division by zero or invalid finite-field value")
    return _EXP[255 - _LOG[a]]


def _profile(k: int, parity: int) -> None:
    require(type(k) is int and type(parity) is int and (k, parity) in PROFILES,
            "Unsupported Reed-Solomon profile")


def select_profile(distinct_domains: int) -> tuple[int, int]:
    """Explicit domain-count policy; NOT automatic reliability or cost proof."""
    require(type(distinct_domains) is int and 0 < distinct_domains <= 128,
            "Invalid independent-domain count")
    if distinct_domains >= 11:
        return (8, 3)
    if distinct_domains >= 6:
        return (4, 2)
    raise ErasureError("At least six distinct failure domains required")


@lru_cache(maxsize=2)
def generator(k: int, parity: int) -> tuple[tuple[int, ...], ...]:
    _profile(k, parity)
    rows = [tuple(int(i == j) for j in range(k)) for i in range(k)]
    # Cauchy parity matrix C[i,j] = (x_i XOR y_j)^(-1).
    # x_i=k+i and y_j=j are pairwise disjoint GF(256) elements.
    for i in range(parity):
        rows.append(tuple(_inv((k + i) ^ j) for j in range(k)))
    return tuple(rows)


@lru_cache(maxsize=256)
def _table(coefficient: int) -> bytes:
    return bytes(_mul(coefficient, x) for x in range(256))


def _linear(shards: list[bytes], coefficients: tuple[int, ...] | list[int], size: int) -> bytes:
    require(len(shards) == len(coefficients), "Invalid linear combination")
    accum = 0
    for data, coef in zip(shards, coefficients):
        if not coef:
            continue
        transformed = data if coef == 1 else data.translate(_table(coef))
        accum ^= int.from_bytes(transformed, "little")
    return accum.to_bytes(size, "little")


def _inverse(matrix: list[tuple[int, ...]]) -> tuple[tuple[int, ...], ...]:
    n = len(matrix)
    require(n > 0 and all(len(row) == n for row in matrix), "Invalid decoder matrix")
    rows = [[*matrix[i], *(int(i == j) for j in range(n))] for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if rows[r][col]), None)
        require(pivot is not None, "Erasure reconstruction matrix singular")
        rows[col], rows[pivot] = rows[pivot], rows[col]
        factor = _inv(rows[col][col])
        rows[col] = [_mul(factor, x) for x in rows[col]]
        for r in range(n):
            if r == col:
                continue
            factor = rows[r][col]
            if factor:
                rows[r] = [a ^ _mul(factor, b) for a, b in zip(rows[r], rows[col])]
    return tuple(tuple(r[n:]) for r in rows)


def encode(payload: bytes, *, k: int, parity: int) -> list[bytes]:
    _profile(k, parity)
    require(type(payload) is bytes and 0 < len(payload) <= MAX_PAYLOAD,
            "Invalid payload size or type")
    shard_size = (len(payload) + k - 1) // k
    data = [payload[i * shard_size:(i+1) * shard_size].ljust(shard_size, b'\x00')
            for i in range(k)]
    return data + [_linear(data, row, shard_size) for row in generator(k, parity)[k:]]


def recover(available: Mapping[int, bytes], *, length: int, k: int, parity: int) -> list[bytes]:
    """Reconstruct and cross-check every supplied shard. Returns all k+m shards.

    Integrity requires caller-supplied authenticated per-shard hashes; if only
    k shards survive an undetected corruption cannot be discovered by FEC alone.
    """
    _profile(k, parity)
    require(type(length) is int and 0 < length <= MAX_PAYLOAD and
            isinstance(available, dict) and k <= len(available) <= k+parity,
            "Invalid reconstruction size/count")
    shard_size = (length + k - 1)//k
    require(all(type(i) is int and 0 <= i < k + parity and
                type(data) is bytes and len(data) == shard_size
                for i, data in available.items()), "Invalid surviving shard")
    positions = sorted(available)[:k]
    decoder = _inverse([generator(k, parity)[i] for i in positions])
    inputs = [available[i] for i in positions]
    data = [_linear(inputs, row, shard_size) for row in decoder]
    result = data + [_linear(data, row, shard_size) for row in generator(k, parity)[k:]]
    require(all(result[index] == shard for index, shard in available.items()),
            "Surviving shards disagree with recovered codeword")
    return result
