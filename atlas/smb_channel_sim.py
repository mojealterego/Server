"""Deterministic E22b SMB2/SMB3 *application-contract* channel fault model.

Simulates data-plane effects of transport loss, ambiguous acknowledgments,
replay and integrity checks. It does not perform SMB negotiation, signing,
AES wire encryption, server authentication, durable handles or TCP transport.
The production server remains Samba; this module is test-only and offline.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading


class ChannelError(ValueError):
    """A simulated policy, network or verified-integrity failure."""


NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z', re.ASCII)
OP_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
MAX_PAYLOAD = 1024 * 1024
CONTRACTS = {
    'omega-compat': ('SMB2_10', 'sign', frozenset(('omega-compat',)), True),
    'omega-secure': ('SMB3_11', 'encrypt', frozenset(('omega-secure',)), True),
    'omega-models': ('SMB3_11', 'encrypt',
                     frozenset(('omega-secure', 'omega-model-reader')), False),
}


class ChannelSimulation:
    """Single logical server state, multiple simulated independent channels.

    The server-side operation receipt is an application-idempotency abstraction,
    not a claim that Samba promises exactly-once packet delivery. All methods
    use a lock so each channel sees one committed version of each file.
    """

    def __init__(self, channels: tuple[str, ...]):
        if (type(channels) is not tuple or not 2 <= len(channels) <= 8
                or any(type(c) is not str or NAME.fullmatch(c) is None for c in channels)
                or len(set(channels)) != len(channels)):
            raise ChannelError('Require 2..8 distinct simulated channel names')
        self._lock = threading.RLock()
        self._channels = set(channels)
        self._online = set(channels)
        self._sessions: dict[str, tuple[str, str]] = {}
        self._files: dict[tuple[str, str], bytes] = {}
        self._operations: dict[tuple[str, str], tuple[str, str, dict]] = {}
        self._write_count = 0
        self._next_session = 0
        self._abort: set[str] = set()
        self._lost_ack: set[str] = set()
        self._corrupt: set[str] = set()
        self._events: list[dict] = []

    @property
    def commits(self) -> int:
        with self._lock:
            return self._write_count

    def _event(self, name: str, **fields) -> None:
        self._events.append({'name': name, **fields})

    def _channel(self, channel: str) -> None:
        if type(channel) is not str or channel not in self._channels:
            raise ChannelError('Unknown channel')

    def _active(self, channel: str) -> None:
        self._channel(channel)
        if channel not in self._online:
            self._event('network_denied', channel=channel)
            raise ChannelError('Channel is unavailable')

    def _session(self, token: str) -> tuple[str, str]:
        try:
            return self._sessions[token]
        except (TypeError, KeyError) as exc:
            raise ChannelError('Invalid simulated session') from exc

    @staticmethod
    def _name(name: str, *, operation: bool = False) -> None:
        matcher = OP_ID if operation else NAME
        if type(name) is not str or matcher.fullmatch(name) is None:
            raise ChannelError('Invalid object or operation identity')

    @staticmethod
    def _payload(data: bytes) -> str:
        if type(data) is not bytes or not 1 <= len(data) <= MAX_PAYLOAD:
            raise ChannelError('Payload must be 1..1048576 bytes')
        return hashlib.sha256(data).hexdigest()

    def open(self, account: str, share: str, dialect: str, protection: str) -> str:
        """Trusted identity fixture only; does not authenticate user credentials."""
        with self._lock:
            contract = CONTRACTS.get(share)
            if (contract is None or account not in contract[2]
                    or dialect != contract[0] or protection != contract[1]):
                raise ChannelError('Share ACL, dialect or protection contract rejected')
            self._next_session += 1
            token = f'sim-session-{self._next_session:04d}'
            self._sessions[token] = (account, share)
            self._event('open', account=account, share=share, session=token)
            return token

    def fail(self, channel: str) -> None:
        with self._lock:
            self._channel(channel)
            self._online.discard(channel)
            self._event('channel_down', channel=channel)

    def recover(self, channel: str) -> None:
        with self._lock:
            self._channel(channel)
            self._online.add(channel)
            self._event('channel_up', channel=channel)

    def drop_ack(self, channel: str) -> None:
        with self._lock:
            self._channel(channel)
            self._lost_ack.add(channel)

    def abort_before_commit(self, channel: str) -> None:
        with self._lock:
            self._channel(channel)
            self._abort.add(channel)

    def corrupt_next_read(self, channel: str) -> None:
        with self._lock:
            self._channel(channel)
            self._corrupt.add(channel)

    def put(self, token: str, key: str, data: bytes, operation_id: str,
            channel: str) -> dict:
        with self._lock:
            self._active(channel)
            _, share = self._session(token)
            self._name(key)
            self._name(operation_id, operation=True)
            digest = self._payload(data)
            if not CONTRACTS[share][3]:
                raise ChannelError('Read-only share cannot be modified')
            replay_key = (share, operation_id)
            if replay_key in self._operations:
                previous_name, previous_sha, receipt = self._operations[replay_key]
                if previous_name != key or previous_sha != digest:
                    raise ChannelError('Conflicting replay identity')
                self._event('idempotent_replay', share=share, operation=operation_id)
                return {**receipt, 'status': 'ALREADY_COMMITTED'}
            if (share, key) in self._files:
                raise ChannelError('No overwrite allowed by simulated workflow')
            if channel in self._abort:
                self._abort.remove(channel)
                self._event('abort_before_commit', channel=channel, operation=operation_id)
                raise ChannelError('Injected pre-commit abort')
            receipt = {'sha256': digest, 'bytes': len(data), 'key': key,
                       'share': share, 'status': 'COMMITTED'}
            self._files[(share, key)] = data
            self._operations[replay_key] = (key, digest, receipt)
            self._write_count += 1
            self._event('commit', share=share, key=key, sha256=digest,
                        operation=operation_id)
            if channel in self._lost_ack:
                self._lost_ack.remove(channel)
                self._event('ack_lost', channel=channel, operation=operation_id)
                raise ChannelError('Commit succeeded but acknowledgment was lost')
            return dict(receipt)

    def seed_model(self, key: str, data: bytes, *, sha256: str) -> None:
        """Provision a preverified read-only image without changing model ACLs."""
        with self._lock:
            self._name(key)
            actual = self._payload(data)
            if type(sha256) is not str or not HEX.fullmatch(sha256) or sha256 != actual:
                raise ChannelError('Model pin mismatch')
            if ('omega-models', key) in self._files:
                raise ChannelError('Model object exists')
            self._files[('omega-models', key)] = data
            self._write_count += 1
            self._event('provision_model', key=key, sha256=actual)

    def get(self, token: str, key: str, expected_sha256: str, channel: str) -> bytes:
        with self._lock:
            self._active(channel)
            _, share = self._session(token)
            self._name(key)
            if type(expected_sha256) is not str or HEX.fullmatch(expected_sha256) is None:
                raise ChannelError('Missing external SHA-256 pin')
            data = self._files.get((share, key))
            if data is None:
                raise ChannelError('Simulated object unavailable')
            if channel in self._corrupt:
                self._corrupt.remove(channel)
                data = bytes([data[0] ^ 1]) + data[1:]
            if hashlib.sha256(data).hexdigest() != expected_sha256:
                self._event('integrity_denied', share=share, key=key, channel=channel)
                raise ChannelError('Data integrity SHA-256 mismatch')
            self._event('read', share=share, key=key, channel=channel)
            return data

    def trace_digest(self) -> str:
        with self._lock:
            raw = json.dumps(self._events, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True).encode()
            return hashlib.sha256(raw).hexdigest()
