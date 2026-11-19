"""Narrow single-host subprocess supervisor with fenced leases and durable CAS.

No shell invocation; command vectors must come from the trusted local operator.
A filesystem lease is NOT a GPU resource reservation, a sandbox, or a global
exactly-once guarantee. Command side effects beyond {output} cannot be fenced.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import threading
import time
from .artifacts import ArtifactStore, ArtifactError, _private_dir
from .phaselease import LeaseStore, LeaseError
from .runtime_gate import RuntimeGate, GateError

SUFFIX = re.compile(r'^\.[a-z0-9]{1,8}$')


class ExecutionError(RuntimeError):
    """The public error carries a stable machine-readable category."""
    def __init__(self, code: str, message: str = ''):
        self.code = code
        super().__init__(f'{code}: {message}' if message else code)


def _terminate_group(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


class SupervisedExecutor:
    def __init__(self, lease: LeaseStore, artifacts: ArtifactStore, root: Path):
        if lease.artifacts is None or lease.artifacts.root != artifacts.root:
            raise ExecutionError('INVALID_CONFIG', 'LeaseStore must use the same durable CAS')
        self.lease = lease
        self.artifacts = artifacts
        self.root = Path(root)
        if self.root.is_symlink() or (self.root.exists() and not self.root.is_dir()):
            raise ExecutionError('INVALID_CONFIG', 'Unsafe working directory')
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=False)
        try:
            _private_dir(self.root)
        except ArtifactError as exc:
            raise ExecutionError('INVALID_CONFIG', str(exc)) from exc

    @staticmethod
    def _check_args(argv: list[str], suffix: str, timeout_seconds: float,
                    ttl: int, max_log_bytes: int) -> None:
        if not isinstance(argv, list) or not 2 <= len(argv) <= 64:
            raise ExecutionError('INVALID_COMMAND', 'Expected argument vector, not a shell string')
        if any(not isinstance(x,str) or not x or '\x00' in x or len(x)>65536 for x in argv):
            raise ExecutionError('INVALID_COMMAND', 'Invalid argument')
        if sum(arg.count('{output}') for arg in argv) != 1:
            raise ExecutionError('INVALID_COMMAND', 'Exactly one {output} placeholder required')
        if not isinstance(suffix,str) or SUFFIX.fullmatch(suffix) is None:
            raise ExecutionError('INVALID_COMMAND', 'Invalid output suffix')
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ExecutionError('INVALID_COMMAND', 'TTL must be 1..3600 seconds')
        if type(timeout_seconds) not in (int,float) or not 0.1 <= timeout_seconds <= 86400:
            raise ExecutionError('INVALID_COMMAND', 'Timeout must be between 0.1 and 86400 seconds')
        if type(max_log_bytes) is not int or not 0 <= max_log_bytes <= 16*1024*1024:
            raise ExecutionError('INVALID_COMMAND', 'Invalid output log cap')

    def _heartbeat(self, task_id: str, node_id: str, token: str, epoch: int,
                   ttl: int, stop: threading.Event, lost: threading.Event) -> None:
        interval = max(0.2, min(ttl / 3, 2.0))
        while not stop.wait(interval):
            try:
                # A distinct SQLite connection is required across Python threads.
                with LeaseStore(self.lease.path, self.lease.document, self.lease.task_list,
                                self.lease.node_list, self.lease.catalog,
                                artifacts=self.artifacts) as other:
                    other.renew(task_id, node_id, token, epoch, ttl=ttl)
            except Exception:
                if not stop.is_set():
                    lost.set()
                return

    def run(self, task_id: str, node_id: str, argv: list[str], *,
            ttl: int = 30, timeout_seconds: float = 600,
            suffix: str = '.bin', max_log_bytes: int = 262144,
            runtime_gate: RuntimeGate | None = None) -> dict:
        self._check_args(argv,suffix,timeout_seconds,ttl,max_log_bytes)
        def check_runtime(starting=False):
            if runtime_gate is not None:
                try:
                    if runtime_gate.node['id']!=node_id or runtime_gate.task['id']!=task_id:
                        raise GateError('GATE_BINDING_MISMATCH')
                    runtime_gate.check(starting=starting)
                except GateError as exc:
                    raise ExecutionError('RUNTIME_GUARD',str(exc)) from exc
        check_runtime(starting=True)
        claim = self.lease.claim(task_id, node_id, ttl=ttl)
        epoch = claim['epoch']
        nonce = secrets.token_hex(12)
        base = f'{task_id}-e{epoch}-{nonce}'
        output = self.root / (base + suffix)
        log_path = self.root / (base + '.log')
        command = [x.replace('{output}', str(output)) for x in argv]
        env = {key: value for key, value in os.environ.items()
               if key in ('PATH','LANG','LC_ALL','LD_LIBRARY_PATH','TERMUX_PREFIX','PREFIX')}
        env['HOME'] = str(self.root)
        env['OMEGA_OUTPUT_PATH'] = str(output)
        stop, lost = threading.Event(), threading.Event()
        heartbeat = threading.Thread(target=self._heartbeat,
                    args=(task_id,node_id,claim['token'],epoch,ttl,stop,lost),
                    name='omega-lease-heartbeat',daemon=True)
        proc = None
        reader = None
        log_fd = None
        error_code = None
        started = time.monotonic()
        try:
            log_fd = os.open(log_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(log_fd,'wb') as log:
                log_fd = None
                check_runtime(starting=True)
                try:
                    proc = subprocess.Popen(command, shell=False, cwd=self.root, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True,close_fds=True)
                except OSError as exc:
                    raise ExecutionError('PROCESS_FAILED','Cannot start subprocess') from exc
                assert proc.stdout is not None
                def drain():
                    kept = 0
                    while True:
                        try:
                            data = os.read(proc.stdout.fileno(), 65536)
                        except (OSError, ValueError):
                            break
                        if not data:
                            break
                        if kept < max_log_bytes:
                            fragment = data[:max_log_bytes-kept]
                            log.write(fragment)
                            kept += len(fragment)
                reader = threading.Thread(target=drain,name='omega-bounded-log',daemon=True)
                reader.start()
                heartbeat.start()
                next_check = time.monotonic()
                while proc.poll() is None:
                    if time.monotonic() >= next_check:
                        check_runtime()
                        next_check = time.monotonic() + 1.0
                    if lost.is_set():
                        raise ExecutionError('LEASE_LOST','Heartbeat could not renew lease')
                    if time.monotonic() - started >= timeout_seconds:
                        raise ExecutionError('PROCESS_TIMEOUT','Deadline exceeded')
                    try:
                        proc.wait(timeout=min(0.15, max(0.01,timeout_seconds-(time.monotonic()-started))))
                    except subprocess.TimeoutExpired:
                        pass
                if lost.is_set():
                    raise ExecutionError('LEASE_LOST','Lease lost before result publication')
                if proc.returncode != 0:
                    raise ExecutionError('PROCESS_FAILED',f'Subprocess exit status {proc.returncode}')
                if not output.is_file() or output.is_symlink():
                    raise ExecutionError('OUTPUT_MISSING','Subprocess did not create a regular output file')
                check_runtime()
                try:
                    receipt = self.lease.complete(task_id,node_id,claim['token'],epoch,output)
                except (ArtifactError, LeaseError, OSError) as exc:
                    raise ExecutionError('OUTPUT_INVALID',str(exc)) from exc
                return {'task':task_id,'node':node_id,'epoch':epoch,
                        'status':'COMPLETED','sha256':receipt['output_sha256'],
                        'output_path':str(output),'log_path':str(log_path),
                        'duration_seconds':round(time.monotonic()-started,3)}
        except ExecutionError as exc:
            error_code = exc.code
            raise
        except (KeyboardInterrupt, SystemExit):
            error_code='PROCESS_INTERRUPTED'
            raise
        except (OSError, RuntimeError) as exc:
            error_code = 'PROCESS_FAILED'
            raise ExecutionError(error_code,str(exc)) from exc
        finally:
            stop.set()
            if proc is not None:
                _terminate_group(proc)
                if reader is not None:
                    reader.join(timeout=2)
                if proc.stdout:
                    proc.stdout.close()
            if heartbeat.is_alive():
                heartbeat.join(timeout=3)
            if log_fd is not None:
                os.close(log_fd)
            if error_code:
                try:
                    self.lease.fail(task_id,node_id,claim['token'],epoch,error_code)
                except LeaseError:
                    pass  # stale epoch or already expired; never mask primary error
            try:
                if output.is_file() or output.is_symlink():
                    output.unlink()
            except OSError:
                pass
