"""Deterministic majority/partition fault model for the E20 etcd v3 JSON contract.

This is deliberately *not* a Raft implementation, an etcd server, a TLS test,
or physical fencing. All commits are applied to one serialized logical ledger;
quorum eligibility is modeled explicitly before linearizable client operations.
The caller under test is the real atlas.distributed_authority.Authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import Callable


class SimulationError(ValueError):
    """An invalid scenario or an unavailable logical quorum."""


_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z', re.ASCII)


class QuorumSimulation:
    """Bounded fault injector with a linearizable, majority-gated KV ledger.

    Three, five or seven uniquely named nodes are supported. Connectivity is
    represented by disjoint partitions. A request is admitted only from an
    active node whose live partition contains >N/2 nodes. A single lock makes
    all compare-and-swap transitions atomic across client threads.
    """

    def __init__(self, members: tuple[str, ...], *, cluster_id: str):
        if (type(members) is not tuple or len(members) not in (3, 5, 7)
                or any(type(m) is not str or not _NAME.fullmatch(m) for m in members)
                or len(set(members)) != len(members)):
            raise SimulationError('Require three, five or seven distinct member identities')
        if type(cluster_id) is not str or not re.fullmatch(r'[0-9]{1,19}', cluster_id) or int(cluster_id) < 1:
            raise SimulationError('Invalid positive simulated cluster ID')
        self.members = members
        self.cluster_id = cluster_id
        self._lock = threading.RLock()
        self._groups = (members,)
        self._alive = set(members)
        self._rows: dict[str, dict[str, str]] = {}
        self._revision = 1
        self._commits: list[tuple[int, str, str]] = []
        self._drop_ack: set[str] = set()
        self._trace: list[dict] = []

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    @property
    def commits(self) -> tuple[tuple[int, str, str], ...]:
        with self._lock:
            return tuple(self._commits)

    def connected_quorum(self) -> tuple[str, ...]:
        with self._lock:
            for group in self._groups:
                active = tuple(member for member in group if member in self._alive)
                if len(active) > len(self.members) // 2:
                    return active
            return ()

    def partition(self, groups: tuple[tuple[str, ...], ...]) -> None:
        """Replace the entire connectivity partition; empty groups are ignored."""
        with self._lock:
            if (type(groups) is not tuple or any(type(g) is not tuple for g in groups)):
                raise SimulationError('Partitions must be tuples of groups')
            flat = [n for group in groups for n in group]
            if (len(flat) != len(self.members) or len(set(flat)) != len(flat)
                    or set(flat) != set(self.members)):
                raise SimulationError('Every member must appear in exactly one group')
            self._groups = tuple(group for group in groups if group)
            self._trace.append({'event': 'partition', 'groups': self._groups})

    def heal(self) -> None:
        with self._lock:
            self._groups = (self.members,)
            self._trace.append({'event': 'heal'})

    def crash(self, member: str) -> None:
        with self._lock:
            self._member(member)
            self._alive.discard(member)
            self._trace.append({'event': 'crash', 'member': member})

    def recover(self, member: str) -> None:
        with self._lock:
            self._member(member)
            self._alive.add(member)
            self._trace.append({'event': 'recover', 'member': member})

    def drop_reply_after_commit(self, member: str) -> None:
        """One-shot fault: perform one successful CAS and lose its response."""
        with self._lock:
            self._member(member)
            self._drop_ack.add(member)

    def _member(self, member: str) -> None:
        if member not in self.members:
            raise SimulationError('Unknown quorum member')

    def rpc(self, member: str) -> Callable[[str, dict], dict]:
        self._member(member)

        def transact(path: str, body: dict) -> dict:
            return self._request(member, path, body)

        return transact

    def _request(self, member: str, path: str, body: dict) -> dict:
        with self._lock:
            if member not in self.connected_quorum():
                self._trace.append({'event': 'quorum_denied', 'node': member, 'path': path})
                raise OSError('Simulated quorum unavailable')
            if not isinstance(body, dict):
                raise SimulationError('Invalid RPC body')
            header = {'revision': str(self._revision), 'cluster_id': self.cluster_id}
            if path == '/v3/kv/range':
                if set(body) != {'key', 'serializable'} or body['serializable'] is not False:
                    raise SimulationError('Only linearizable etcd range is implemented')
                key = body['key']
                if type(key) is not str:
                    raise SimulationError('Invalid key')
                row = self._rows.get(key)
                self._trace.append({'event': 'range', 'node': member, 'key': key,
                                    'revision': self._revision})
                return {'header': header, 'kvs': [dict(row)] if row else [],
                        'count': '1' if row else '0'}
            if path != '/v3/kv/txn':
                raise SimulationError('Unsupported RPC path')
            comparisons, success = body.get('compare'), body.get('success')
            if (type(comparisons) is not list or len(comparisons) != 1
                    or type(success) is not list or len(success) != 1
                    or type(comparisons[0]) is not dict or type(success[0]) is not dict
                    or set(success[0]) != {'request_put'}):
                raise SimulationError('Exactly one CAS and one PUT supported')
            cmp = comparisons[0]
            put = success[0]['request_put']
            if (type(put) is not dict or set(put) != {'key', 'value'}
                    or type(put['key']) is not str or type(put['value']) is not str
                    or cmp.get('key') != put['key'] or cmp.get('result') != 'EQUAL'):
                raise SimulationError('Invalid CAS target')
            row = self._rows.get(put['key'])
            target = cmp.get('target')
            if target == 'VERSION' and set(cmp) == {'key', 'result', 'target', 'version'}:
                matched = cmp['version'] == '0' and row is None
            elif target == 'MOD' and set(cmp) == {'key', 'result', 'target', 'mod_revision'}:
                matched = row is not None and cmp['mod_revision'] == row['mod_revision']
            else:
                raise SimulationError('Unsupported CAS comparator')
            if matched:
                self._revision += 1
                self._rows[put['key']] = {'key': put['key'], 'value': put['value'],
                                          'mod_revision': str(self._revision), 'lease': '0'}
                self._commits.append((self._revision, put['key'], put['value']))
            self._trace.append({'event': 'txn', 'node': member, 'key': put['key'],
                                'revision': self._revision, 'committed': matched,
                                'value_sha256': hashlib.sha256(put['value'].encode()).hexdigest()})
            if matched and member in self._drop_ack:
                self._drop_ack.remove(member)
                self._trace.append({'event': 'lost_ack', 'node': member})
                raise OSError('Simulated reply lost after committed CAS')
            return {'header': {'revision': str(self._revision), 'cluster_id': self.cluster_id},
                    'succeeded': matched}

    def trace_digest(self) -> str:
        """Stable evidence for an identical sequential action/nonce schedule."""
        with self._lock:
            raw = json.dumps(self._trace, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True).encode()
            return hashlib.sha256(raw).hexdigest()
