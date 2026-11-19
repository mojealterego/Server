"""Local crash recovery: per-node flock and guardian bound to supervisor lifetime.

Trusted foreground commands only. Not a sandbox or distributed lock.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys


class RecoveryBusy(RuntimeError):
    pass


class NodeLock:
    def __init__(self, db: Path, node: str):
        db = Path(db)
        st = db.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o077:
            raise ValueError('Recovery requires a private, non-aliased lease DB')
        db = db.resolve(strict=True)
        parent = db.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ValueError('Recovery requires an operator-controlled DB directory')
        if not isinstance(node, str) or not 1 <= len(node) <= 128:
            raise ValueError('Invalid node identifier')
        root = db.parent / ('.' + db.name + '.execution-locks')
        root.mkdir(mode=0o700, exist_ok=True)
        st = root.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise ValueError('Unsafe recovery lock directory')
        self.path = root / (hashlib.sha256(node.encode()).hexdigest() + '.lock')
        self.fd = None

    def __enter__(self):
        if self.fd is not None:
            raise RuntimeError('Lock already entered')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o077:
                raise ValueError('Unsafe recovery lock file')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RecoveryBusy('Node has an active or recovering execution') from exc
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            # Do not LOCK_UN: the guardian and command may still share this OFD.
            os.close(self.fd)
            self.fd = None


def node_status(db: Path, node: str) -> str:
    try:
        with NodeLock(db, node):
            return 'IDLE'
    except RecoveryBusy:
        return 'BUSY'


def spawn_guarded(lock: NodeLock, command: list[str], cwd: Path, env: dict):
    if lock.fd is None:
        raise ValueError('Node lock required before spawn')
    read_end, write_end = os.pipe()
    try:
        argv = [sys.executable, '-I', str(Path(__file__).resolve()), '_guard',
                str(read_end), str(lock.fd), *command]
        proc = subprocess.Popen(argv, shell=False, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, pass_fds=(read_end, lock.fd))
    except BaseException:
        os.close(write_end)
        raise
    finally:
        os.close(read_end)
    return proc, write_end


def _guard(read_end: int, lock_fd: int, command: list[str]) -> int:
    # The guardian is its own session/group leader. Never signal a recorded PID.
    if os.getpgrp() != os.getpid():
        return 125
    def abort(*_):
        os.killpg(os.getpgrp(), signal.SIGKILL)
        os._exit(125)
    signal.signal(signal.SIGTERM, abort)
    signal.signal(signal.SIGINT, abort)
    def parent_gone(timeout):
        return bool(select.select([read_end], [], [], timeout)[0])
    if parent_gone(0):
        return 125
    try:
        child = subprocess.Popen(command, shell=False, close_fds=True, pass_fds=(lock_fd,))
    except OSError:
        return 127
    while True:
        if parent_gone(.1):
            abort()
        rc = child.poll()
        if rc is not None:
            return rc if rc >= 0 else 128 - rc


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == '_guard':
        return _guard(int(args[1]), int(args[2]), args[3:])
    p = argparse.ArgumentParser(description='Inspect local execution exclusion lock (not lease status)')
    p.add_argument('--db', required=True, type=Path)
    p.add_argument('--node', required=True)
    a = p.parse_args(args)
    try:
        print(node_status(a.db, a.node)); return 0
    except (OSError, ValueError) as exc:
        print('RECOVERY ERROR: '+str(exc), file=sys.stderr); return 1


if __name__ == '__main__':
    sys.exit(main())
