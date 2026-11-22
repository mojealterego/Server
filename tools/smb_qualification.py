"""E22a: opt-in SMB2/SMB3 integrity and transfer measurement, not HA certification.

Uses real smbclient when invoked on an enrolled VPS. No server configuration changes.
Physical evidence is NOT provided by test fixtures or this program alone.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

MIB = 1024 * 1024
SCENARIOS = (
    ('omega-compat', 'compat', 'omega-compat', 'SMB2_10', 'sign'),
    ('omega-secure', 'secure', 'omega-secure', 'SMB3_11', 'encrypt'),
)
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(block) for block in
    ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))
PASSWORD = re.compile(rb'[0-9a-f]{64}\n\Z')


class QualificationError(ValueError):
    """A qualification prerequisite, transfer, cleanup or integrity check failed."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise QualificationError(reason)


def _bind(address: str, port: int, allow_network: bool) -> str:
    try:
        ip = ipaddress.IPv4Address(address)
    except (ValueError, TypeError) as exc:
        raise QualificationError('Literal IPv4 bind required') from exc
    require(type(port) is int and 1 <= port <= 65535, 'Invalid TCP port')
    require(ip.is_loopback or (allow_network is True and any(ip in x for x in PRIVATE_NETWORKS)),
            'Private network opt-in required; public targets forbidden')
    return str(ip)


def _private_directory(path: Path) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise QualificationError('Required private directory missing') from exc
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
            'Directory must be private and owned by invoking user')


def _credential(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as source:
            st = os.fstat(source.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
                    and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600
                    and st.st_size == 65, 'Unsafe SMB credential metadata')
            raw = source.read(66)
        require(PASSWORD.fullmatch(raw) is not None, 'Invalid SMB credential format')
        return raw
    except OSError as exc:
        raise QualificationError('SMB credentials unavailable') from exc


def _auth_file(folder: Path, username: str, password: bytes) -> Path:
    path = folder / (username + '.auth')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(b'username = ' + username.encode('ascii') + b'\npassword = ' + password)
        out.flush()
        os.fsync(out.fileno())
    return path


def _checksum(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as src:
        while chunk := src.read(MIB):
            size += len(chunk)
            require(size <= 16 * MIB, 'Unexpected oversized qualification data')
            digest.update(chunk)
    return digest.hexdigest(), size


def _payload(path: Path, mib: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    with path.open('xb') as out:
        for _ in range(mib):
            data = secrets.token_bytes(MIB)
            out.write(data)
            digest.update(data)
        out.flush()
        os.fsync(out.fileno())
    return digest.hexdigest(), mib * MIB


def _command(client: str, host: str, port: int, share: str, auth: Path,
             dialect: str, protection: str, command: str, work: Path, timeout: int) -> float:
    argv = [client, f'//{host}/{share}', '-p', str(port), '-A', str(auth), '-m', dialect,
            f'--option=client min protocol={dialect}', f'--client-protection={protection}',
            '--use-kerberos=off', '-c', command]
    start = time.perf_counter_ns()
    try:
        # Explicit output sinks prevent a malicious peer filling memory with logs.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=err, cwd=work, timeout=timeout, check=False)
        require(result.returncode == 0, 'SMB operation failed: ' + command.split()[0])
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise QualificationError('SMB operation timed out or failed to launch') from exc
    return max(0.001, (time.perf_counter_ns() - start) / 1_000_000)


def p95(values: list[float]) -> float:
    require(len(values) > 0 and all(math.isfinite(v) and v >= 0 for v in values),
            'Invalid latency sample')
    values = sorted(values)
    return values[math.ceil(.95 * len(values)) - 1]


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def _sample(client: str, host: str, port: int, scenario: tuple[str, ...],
            auth: Path, work: Path, mib: int, timeout: int) -> dict:
    share, _, _, dialect, protection = scenario
    nonce = secrets.token_hex(16)
    name = 'omega-e22-' + nonce + '.bin'
    sent = work / ('send-' + nonce + '.bin')
    received = work / ('receive-' + nonce + '.bin')
    digest, size = _payload(sent, mib)
    started_upload = False
    original_error: Exception | None = None
    metrics: dict = {}
    try:
        started_upload = True
        write_ms = _command(client, host, port, share, auth, dialect, protection,
                            f'put {sent.name} {name}', work, timeout)
        read_ms = _command(client, host, port, share, auth, dialect, protection,
                           f'get {name} {received.name}', work, timeout)
        received_digest, received_size = _checksum(received)
        require(received_size == size and received_digest == digest,
                'SMB readback integrity mismatch')
        metrics = {'bytes': size, 'sha256': digest,
                   'write_ms': round(write_ms, 3), 'read_ms': round(read_ms, 3),
                   'write_mib_s': round((size / MIB) / (write_ms / 1000), 3),
                   'read_mib_s': round((size / MIB) / (read_ms / 1000), 3)}
    except Exception as exc:
        original_error = exc
    finally:
        if started_upload:
            try:
                _command(client, host, port, share, auth, dialect, protection,
                         'del ' + name, work, timeout)
            except Exception as exc:
                raise QualificationError('SMB cleanup uncertain for ' + name +
                                         '; operator inspection required') from exc
        sent.unlink(missing_ok=True)
        received.unlink(missing_ok=True)
    if original_error is not None:
        if isinstance(original_error, QualificationError):
            raise original_error
        raise QualificationError('SMB qualification interrupted') from original_error
    return metrics


def _write_report(path: Path, report: dict) -> None:
    path = Path(path)
    _private_directory(path.parent)
    require(path.is_absolute(), 'Report must use an absolute path')
    data = (json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    require(len(data) <= 128 * 1024, 'Report limit exceeded')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except FileExistsError as exc:
        raise QualificationError('Report already exists; never overwrite prior evidence') from exc
    except OSError as exc:
        raise QualificationError('Cannot publish private evidence report') from exc


def qualify(*, root: Path, address: str, port: int, allow_network: bool,
            mib: int, samples: int, timeout: int, report_path: Path | None = None) -> dict:
    require(type(mib) is int and 1 <= mib <= 16, 'Payload MiB must be 1..16')
    require(type(samples) is int and 3 <= samples <= 20, 'Samples must be 3..20')
    require(type(timeout) is int and 5 <= timeout <= 180, 'Timeout must be 5..180 seconds')
    host = _bind(address, port, allow_network)
    root = Path(root)
    _private_directory(root / 'smb-secrets')
    if report_path is not None:
        path = Path(report_path)
        require(path.is_absolute(), 'Report must use an absolute path')
        _private_directory(path.parent)
        require(not path.exists() and not path.is_symlink(), 'Report already exists or is unsafe')
    passwords = {name: _credential(root / 'smb-secrets' / f'{name}_password')
                 for name in ('compat', 'secure')}
    client = shutil.which('smbclient')
    require(client is not None, 'Native smbclient executable required')
    observations = []
    with tempfile.TemporaryDirectory(prefix='omega-e22-') as directory:
        work = Path(directory)
        _private_directory(work)
        for scenario in SCENARIOS:
            share, account, username, dialect, protection = scenario
            auth = _auth_file(work, username, passwords[account])
            measurements = [_sample(client, host, port, scenario, auth, work, mib, timeout)
                            for _ in range(samples)]
            observations.append({
                'share': share, 'dialect_requested': dialect,
                'protection_requested': protection, 'measurements': measurements,
                'write_ms_p95': round(p95([x['write_ms'] for x in measurements]), 3),
                'read_ms_p95': round(p95([x['read_ms'] for x in measurements]), 3),
                'write_mib_s_median': round(_median([x['write_mib_s'] for x in measurements]), 3),
                'read_mib_s_median': round(_median([x['read_mib_s'] for x in measurements]), 3),
            })
    report = {'schema': 'omega.smb.e22a-measurement.v1', 'status': 'OBSERVED_NOT_CERTIFIED',
              'address': host, 'port': port, 'payload_mib': mib, 'samples_per_share': samples,
              'measurement_scope': 'client process end-to-end transfer including SMB session setup',
              'client_dialect_attestation': 'NOT_INDEPENDENTLY_VERIFIED',
              'external_smb_cloud_ha_e2e': 'NOT_CLAIMED', 'scenarios': observations}
    if report_path is not None:
        _write_report(Path(report_path), report)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1] / 'vps')
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=445)
    p.add_argument('--allow-network', action='store_true')
    p.add_argument('--mib', type=int, default=1)
    p.add_argument('--samples', type=int, default=3)
    p.add_argument('--timeout', type=int, default=30)
    p.add_argument('--report', type=Path)
    args = p.parse_args(argv)
    try:
        result = qualify(root=args.root, address=args.bind, port=args.port,
                         allow_network=args.allow_network, mib=args.mib,
                         samples=args.samples, timeout=args.timeout, report_path=args.report)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (QualificationError, OSError) as exc:
        print('SMB E22a FAILED: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
