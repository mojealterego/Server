"""Durable local SQLite fencing leases for *admitted* PHASESHIFT primary plans.

Local filesystem only; NOT a cross-host distributed lock or exactly-once
execution. A worker must check its epoch before publishing any side effect.
"""
from __future__ import annotations
import hashlib
import copy
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from .phaseverify import verify_workflow
from .artifacts import ArtifactStore, ArtifactError


class LeaseError(ValueError):
    pass


def _time(now):
    val = time.time() if now is None else now
    if type(val) not in (int, float) or not math.isfinite(val) or val < 0:
        raise LeaseError('Invalid clock reading')
    return float(val)


def _ttl(ttl):
    if type(ttl) is not int or not 1 <= ttl <= 3600:
        raise LeaseError('TTL must be 1..3600 seconds')
    return ttl


def _file_sha256(path: Path) -> tuple[str, int]:
    path = Path(path)
    if path.is_symlink():
        raise LeaseError('Output symlinks are forbidden')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
    except OSError as exc:
        raise LeaseError('Cannot open output file safely') from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise LeaseError('Output must be a regular file')
        h = hashlib.sha256()
        size = 0
        with os.fdopen(fd, 'rb', closefd=False) as file:
            while chunk := file.read(1024 * 1024):
                size += len(chunk)
                h.update(chunk)
        after = os.fstat(fd)
        if (before.st_size != size or after.st_size != size or
                before.st_mtime_ns != after.st_mtime_ns or
                before.st_ino != after.st_ino or before.st_dev != after.st_dev):
            raise LeaseError('Output changed during verification')
        return h.hexdigest(), size
    finally:
        os.close(fd)


class LeaseStore:
    def __init__(self, db_path: Path, document: dict, tasks: list[dict],
                 nodes: list[dict], catalog: dict, *, artifacts: ArtifactStore | None = None):
        result = verify_workflow(document, tasks, nodes, catalog)
        if not result['primary_feasible'] or not document['admitted']:
            raise LeaseError('Workflow not admitted; cannot lease')
        self.document = copy.deepcopy(document)
        self.task_list = copy.deepcopy(tasks)
        self.node_list = copy.deepcopy(nodes)
        self.catalog = copy.deepcopy(catalog)
        self.plan_hash = document['certificate_sha256']
        self.tasks = {j['id']: j for j in self.task_list}
        self.assignments = {j['id']: j for j in document['primary']['assignments']}
        self.artifacts = artifacts
        self.nodes = {n["id"]: n for n in self.node_list}
        self.path = Path(db_path)
        if not self.path.parent.is_dir() or self.path.parent.is_symlink() or self.path.is_symlink():
            raise LeaseError('Unsafe SQLite database path')
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                pass  # concurrent creator; check the file below
        if not self.path.is_file() or self.path.is_symlink() or self.path.stat().st_mode & 0o077:
            raise LeaseError('Lease database must be regular and private (0600)')
        self.conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            self.conn.execute('PRAGMA busy_timeout=10000')
            # Concurrent worker startups may race on the initial WAL transition.
            # Retrying is safe; we do not retry user-visible claim operations.
            for attempt in range(8):
                try:
                    mode = self.conn.execute('PRAGMA journal_mode=WAL').fetchone()[0]
                    if mode.lower() != 'wal':
                        raise LeaseError('SQLite WAL mode unavailable')
                    break
                except sqlite3.OperationalError as exc:
                    if 'locked' not in str(exc).lower() or attempt == 7:
                        raise
                    time.sleep(min(0.02 * (2 ** attempt), 0.5))
            self.conn.execute('PRAGMA synchronous=FULL')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS leases (
            plan_hash TEXT NOT NULL, task_id TEXT NOT NULL,
            node_id TEXT NOT NULL, epoch INTEGER NOT NULL,
            token_hash TEXT NOT NULL, expires_at REAL NOT NULL,
            state TEXT NOT NULL, output_sha256 TEXT,
            reserved_ram_mb INTEGER, last_error TEXT,
            PRIMARY KEY (plan_hash, task_id)
        )''')
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                columns = {row[1] for row in self.conn.execute('PRAGMA table_info(leases)')}
                if 'reserved_ram_mb' not in columns:
                    self.conn.execute('ALTER TABLE leases ADD COLUMN reserved_ram_mb INTEGER')
                if 'last_error' not in columns:
                    self.conn.execute('ALTER TABLE leases ADD COLUMN last_error TEXT')
                self.conn.execute('''CREATE TABLE IF NOT EXISTS node_registry (
                    node_id TEXT PRIMARY KEY, ram_capacity_mb INTEGER NOT NULL,
                    disk_free_bytes INTEGER NOT NULL, trust TEXT NOT NULL
                )''')
                for node in self.nodes.values():
                    cap = node['ram_available_mb'] - node['ram_headroom_mb']
                    observed = self.conn.execute(
                        'SELECT ram_capacity_mb,disk_free_bytes,trust FROM node_registry WHERE node_id=?',
                        (node['id'],)).fetchone()
                    signature = (cap, node['disk_free_bytes'], node['trust'])
                    if observed is not None and tuple(observed) != signature:
                        raise LeaseError('Conflicting registered node capacity or trust: '+node['id'])
                    self.conn.execute('''INSERT OR IGNORE INTO node_registry
                        (node_id,ram_capacity_mb,disk_free_bytes,trust) VALUES (?,?,?,?)''',
                        (node['id'],*signature))
                self.conn.execute('COMMIT')
            except BaseException:
                self.conn.execute('ROLLBACK')
                raise
        except BaseException:
            self.conn.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.conn.close()

    def _get(self, task_id):
        if task_id not in self.tasks:
            raise LeaseError('Unknown task')
        return self.conn.execute('''SELECT node_id,epoch,token_hash,expires_at,state,output_sha256
                ,reserved_ram_mb,last_error FROM leases WHERE plan_hash=? AND task_id=?''',
                (self.plan_hash, task_id)).fetchone()

    def _transaction(self, func):
        self.conn.execute('BEGIN IMMEDIATE')
        try:
            result = func()
            self.conn.execute('COMMIT')
            return result
        except BaseException:
            self.conn.execute('ROLLBACK')
            raise

    def claim(self, task_id: str, node_id: str, *, now=None, ttl: int = 60) -> dict:
        clock, ttl = _time(now), _ttl(ttl)
        if task_id not in self.assignments or node_id != self.assignments[task_id]['node']:
            raise LeaseError('Task not assigned to this node')

        def op():
            for dep in self.tasks[task_id].get('depends_on', []):
                upstream = self._get(dep)
                if upstream is None or upstream[4] != 'COMPLETED':
                    raise LeaseError('Dependency not completed: '+dep)
                if self.artifacts is not None:
                    try:
                        self.artifacts.verify(upstream[5])
                    except ArtifactError as exc:
                        raise LeaseError('Dependency artifact unavailable or invalid: '+dep) from exc
            old = self._get(task_id)
            if old is not None:
                if old[4] == 'COMPLETED':
                    raise LeaseError('Task already completed')
                if old[4] == 'LEASED' and old[3] > clock:
                    raise LeaseError('Task currently leased')
            # SQLite BEGIN IMMEDIATE serializes admission across all workflows
            # sharing this database; scheduling slots are not runtime locks.
            node_cap = self.conn.execute(
                'SELECT ram_capacity_mb FROM node_registry WHERE node_id=?',
                (node_id,)).fetchone()
            if node_cap is None:
                raise LeaseError('Node has no registered RAM capacity')
            rows = self.conn.execute('''SELECT reserved_ram_mb FROM leases
                WHERE node_id=? AND state='LEASED' AND expires_at>?''',
                (node_id,clock)).fetchall()
            if any(row[0] is None for row in rows):
                raise LeaseError('Unaccounted active legacy lease; runtime RAM admission blocked')
            reservation = self.tasks[task_id]['ram_mb']
            if sum(row[0] for row in rows) + reservation > node_cap[0]:
                raise LeaseError('Runtime RAM reservation exceeds registered node capacity')
            epoch = 1 if old is None else old[1] + 1
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode('ascii')).hexdigest()
            until = clock + ttl
            self.conn.execute('''INSERT INTO leases
                (plan_hash,task_id,node_id,epoch,token_hash,expires_at,state,output_sha256,reserved_ram_mb,last_error)
                VALUES (?,?,?,?,?,?,?,NULL,?,NULL)
                ON CONFLICT(plan_hash,task_id) DO UPDATE SET
                node_id=excluded.node_id,epoch=excluded.epoch,
                token_hash=excluded.token_hash,expires_at=excluded.expires_at,
                state=excluded.state,output_sha256=NULL,
                reserved_ram_mb=excluded.reserved_ram_mb,last_error=NULL''',
                (self.plan_hash, task_id, node_id, epoch, token_hash, until, 'LEASED', reservation))
            return {'task': task_id, 'node': node_id, 'epoch': epoch,
                    'token': token, 'expires_at': until, 'state': 'LEASED',
                    'plan_sha256': self.plan_hash}
        return self._transaction(op)

    def _check_owner(self, task_id, node_id, token, epoch, clock, *, completed=False):
        if not isinstance(token, str) or len(token) > 512 or type(epoch) is not int:
            raise LeaseError('Invalid lease credential')
        row = self._get(task_id)
        if (row is None or row[0] != node_id or row[1] != epoch or
                not secrets.compare_digest(row[2], hashlib.sha256(token.encode('utf-8')).hexdigest())):
            raise LeaseError('Stale or invalid fencing token')
        if completed and row[4] == 'COMPLETED':
            return row
        if row[4] != 'LEASED' or row[3] <= clock:
            raise LeaseError('Lease expired or not active')
        return row

    def renew(self, task_id, node_id, token, epoch, *, now=None, ttl=60):
        clock, ttl = _time(now), _ttl(ttl)
        def op():
            self._check_owner(task_id, node_id, token, epoch, clock)
            until = clock + ttl
            self.conn.execute('''UPDATE leases SET expires_at=?
                WHERE plan_hash=? AND task_id=?''', (until, self.plan_hash, task_id))
            return {'task': task_id, 'epoch': epoch, 'expires_at': until}
        return self._transaction(op)

    def fail(self, task_id, node_id, token, epoch, reason, *, now=None):
        if reason not in {'PROCESS_FAILED', 'PROCESS_TIMEOUT', 'PROCESS_INTERRUPTED',
                          'OUTPUT_MISSING', 'OUTPUT_INVALID', 'LEASE_LOST'}:
            raise LeaseError('Unsupported failure reason')
        clock = _time(now)
        def op():
            self._check_owner(task_id, node_id, token, epoch, clock)
            self.conn.execute('''UPDATE leases SET state='FAILED',last_error=?,output_sha256=NULL
                WHERE plan_hash=? AND task_id=?''', (reason,self.plan_hash,task_id))
            return {'task':task_id,'epoch':epoch,'state':'FAILED','reason':reason}
        return self._transaction(op)

    def complete(self, task_id, node_id, token, epoch, output: Path, *, now=None):
        # Reject stale owners before potentially expensive CAS publication.
        clock = _time(now)
        self._transaction(lambda: self._check_owner(task_id,node_id,token,epoch,clock,completed=True))
        if self.artifacts is not None:
            receipt = self.artifacts.put(Path(output), max_bytes=self.assignments[task_id]['disk_bytes'])
            output_hash, output_size = receipt['sha256'], receipt['size_bytes']
        else:
            output_hash, output_size = _file_sha256(Path(output))
        if output_size > self.assignments[task_id]['disk_bytes']:
            raise LeaseError('Output exceeds planned disk reservation')
        clock = _time(now)  # caller-supplied deterministic clock or post-hash wall time
        def op():
            row = self._check_owner(task_id, node_id, token, epoch, clock, completed=True)
            if row[4] == 'COMPLETED':
                if row[5] != output_hash:
                    raise LeaseError('Idempotent completion hash mismatch')
            else:
                self.conn.execute('''UPDATE leases SET state='COMPLETED',output_sha256=?
                    WHERE plan_hash=? AND task_id=?''',
                    (output_hash, self.plan_hash, task_id))
            return {'task': task_id, 'node': node_id, 'epoch': epoch,
                    'output_sha256': output_hash, 'state': 'COMPLETED',
                    'plan_sha256': self.plan_hash}
        return self._transaction(op)

    def status(self, task_id):
        row = self._get(task_id)
        if row is None:
            return {'task': task_id, 'state': 'PENDING', 'epoch': 0}
        return {'task': task_id, 'node': row[0], 'epoch': row[1],
                'expires_at': row[3], 'state': row[4], 'output_sha256': row[5],
                'reserved_ram_mb': row[6], 'last_error': row[7]}
