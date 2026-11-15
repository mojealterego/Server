#!/usr/bin/env python3
"""OMEGA mobile node: supervised, key-only SFTP, loopback WebDAV, optional local LLM."""
from __future__ import annotations

import argparse
from collections import deque
import getpass
import ipaddress
import logging
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

PORTS = {"sftp": 2022, "webdav": 8081, "llm": 8082}
LOGGER = logging.getLogger("omega")


def check_bind(value: str) -> str:
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("SFTP bind must be an IPv4 address") from exc
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified and value != '0.0.0.0':
        raise ValueError("Unsafe bind address")
    return value


def validate_sftp_exposure(bind: str, allow_lan: bool) -> str:
    check_bind(bind)
    address=ipaddress.IPv4Address(bind)
    if str(address)=='0.0.0.0':
        raise ValueError('Wildcard SFTP bind prohibited; select exact LAN/VPN IP')
    if address.is_loopback:
        return bind
    if not allow_lan or not address.is_private or address.is_link_local:
        raise ValueError('Non-loopback SFTP requires --allow-lan and a private LAN/VPN IPv4')
    return bind


def sftp_command(binary: str, data: Path, bind: str, port: int,
                 authorized: Path, hostkey: Path) -> list[str]:
    check_bind(bind)
    if not 1024 <= port <= 65535:
        raise ValueError("Unprivileged SFTP port required")
    return [binary, 'serve', 'sftp', str(data), '--addr', f'{bind}:{port}',
            '--authorized-keys', str(authorized), '--key', str(hostkey),
            '--dir-perms', '0750', '--file-perms', '0640']


def webdav_command(binary: str, data: Path, htpasswd: Path) -> list[str]:
    if not htpasswd.is_file() or htpasswd.is_symlink() or not htpasswd.stat().st_size:
        raise ValueError("Nonempty bcrypt htpasswd file required")
    return [binary, 'serve', 'webdav', str(data), '--addr', '127.0.0.1:8081',
            '--htpasswd', str(htpasswd), '--dir-perms', '0750',
            '--file-perms', '0640']


def llm_command(binary: str, model: Path, threads: int,
                context: int, mmproj: Path | None = None) -> list[str]:
    if not (1 <= threads <= 8 and 512 <= context <= 8192):
        raise ValueError("Invalid LLM resource bounds")
    if not model.is_file() or model.is_symlink() or model.suffix.lower() != '.gguf' or model.stat().st_size < 64:
        raise ValueError("Invalid GGUF model file")
    if any(x in model.name.lower() for x in ('ltx-', 'ltx_', 'mmproj', 'wan_')):
        raise ValueError('This GGUF is a video/projector component, not a supported text LLM')
    from model_inventory import inspect_binary_header
    header = inspect_binary_header(model)
    arch = header.get('architecture','unknown')
    if arch in ('clip','unknown','ltx','ltxv','ltx2','wan'):
        raise ValueError(f'Model architecture not supported by text server: {arch}')
    argv = [binary, '--model', str(model), '--host', '127.0.0.1', '--port', '8082',
            '--threads', str(threads), '--ctx-size', str(context), '--parallel', '1']
    if mmproj is not None:
        if not mmproj.is_file() or mmproj.is_symlink():
            raise ValueError('Missing/unsafe mmproj')
        proj = inspect_binary_header(mmproj)
        if proj.get('architecture') != 'clip':
            raise ValueError('Explicit mmproj must be a CLIP/vision GGUF')
        # Same dimension is NOT proof of lineage compatibility. Explicit opt-in only.
        argv.extend(['--mmproj', str(mmproj)])
    return argv


class RestartBudget:
    def __init__(self, limit: int = 5, window: float = 300.0):
        self.limit, self.window = limit, window
        self.events: deque[float] = deque()

    def allow(self, now: float) -> bool:
        while self.events and self.events[0] <= now - self.window:
            self.events.popleft()
        if len(self.events) >= self.limit:
            return False
        self.events.append(now)
        return True


def state_paths(root: Path) -> dict[str, Path]:
    return {
        'root': root, 'data': root / 'data', 'auth': root / 'authorized_keys',
        'hostkey': root / 'host_ed25519', 'client': root / 'client_ed25519',
        'htpasswd': root / 'webdav.htpasswd', 'logs': root / 'logs',
        'lock': root / '.node.lock',
    }


def create_identity(target: Path) -> None:
    if target.exists():
        return
    if shutil.which('ssh-keygen'):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(target)], check=True)
    else:
        # Portable offline fallback; Termux's default uses openssh/ssh-keygen.
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, PublicFormat, NoEncryption)
        except ImportError as exc:
            raise RuntimeError('Install openssh or Python cryptography for Ed25519 keys') from exc
        key = ed25519.Ed25519PrivateKey.generate()
        with target.open('xb') as stream:
            stream.write(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
        target.with_suffix('.pub').write_bytes(
            key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH) + b' omega-node\n')
    target.chmod(0o600)


def initialize(root: Path, without_webdav: bool = False) -> None:
    paths = state_paths(root)
    for key in ('root', 'data', 'logs'):
        paths[key].mkdir(mode=0o700, parents=True, exist_ok=True)
        paths[key].chmod(0o700)
    create_identity(paths['hostkey'])
    create_identity(paths['client'])
    client_pub = paths['client'].with_suffix('.pub').read_text().strip()
    authorized = paths['auth']
    if not authorized.exists():
        authorized.write_text(client_pub + '\n')
        authorized.chmod(0o600)
    if not without_webdav and not paths['htpasswd'].exists():
        if not shutil.which('htpasswd'):
            raise RuntimeError('Install htpasswd (apache2 package) or use --without-webdav')
        password = getpass.getpass('New WebDAV password (loopback only): ')
        confirm = getpass.getpass('Repeat WebDAV password: ')
        if len(password) < 16 or password != confirm:
            raise ValueError('WebDAV passwords must match and contain at least 16 characters')
        subprocess.run(['htpasswd', '-B', '-i', '-c', str(paths['htpasswd']), 'omega'],
                       input=password + '\n', text=True, check=True,
                       stdout=subprocess.DEVNULL)
        paths['htpasswd'].chmod(0o600)
    LOGGER.info('Initialized %s', root)
    LOGGER.info('Client public key: %s', paths['client'].with_suffix('.pub'))
    LOGGER.info('Client private key: %s (keep private; securely transfer only when needed)', paths['client'])
    LOGGER.info('SSH host key fingerprint:')
    pub_path = paths['hostkey'].with_suffix('.pub')
    if shutil.which('ssh-keygen'):
        subprocess.run(['ssh-keygen', '-lf', str(pub_path)], check=True)
    else:
        import base64
        import hashlib
        key_blob = base64.b64decode(pub_path.read_text().split()[1])
        digest = base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip('=')
        LOGGER.info('SHA256:%s', digest)


def valid_authorized_keys(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    lines = [x.strip() for x in path.read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
    return bool(lines) and all(x.startswith(('ssh-ed25519 ', 'ssh-rsa ', 'ecdsa-sha2-')) for x in lines)


def rotate_once(path: Path) -> None:
    if path.exists() and path.stat().st_size > 5 * 1024 * 1024:
        for i in (2, 1):
            src = path.with_suffix(path.suffix + f'.{i}')
            dst = path.with_suffix(path.suffix + f'.{i+1}')
            if src.exists():
                src.replace(dst)
        path.replace(path.with_suffix(path.suffix + '.1'))


def supervise(root: Path, *, bind: str, model: Path | None, threads: int,
              context: int, without_webdav: bool, mmproj: Path | None = None, allow_lan: bool = False) -> int:
    import fcntl
    from contextlib import ExitStack
    from resource_arbiter import OmegaResourceArbiter, AndroidProbe, Job
    arbiter = OmegaResourceArbiter(AndroidProbe())
    paths = state_paths(root)
    validate_sftp_exposure(bind, allow_lan)
    if bind != '127.0.0.1':
        LOGGER.warning('SFTP exposed on %s:2022: restrict to private LAN or VPN firewall!', bind)
    if not paths['data'].is_dir() or not valid_authorized_keys(paths['auth']) or not paths['hostkey'].is_file():
        raise RuntimeError('Run init first and check authorized_keys / host key')
    rclone = shutil.which('rclone')
    if not rclone:
        raise RuntimeError('rclone not found; pkg install rclone')
    specs: dict[str, list[str]] = {
        'sftp': sftp_command(rclone, paths['data'], bind, PORTS['sftp'], paths['auth'], paths['hostkey'])
    }
    if not without_webdav:
        specs['webdav'] = webdav_command(rclone, paths['data'], paths['htpasswd'])
    if model is not None:
        binary = os.environ.get('LLAMA_SERVER_BIN') or str(Path.home() / 'llama.cpp/build/bin/llama-server')
        if not Path(binary).is_file() and not shutil.which(binary):
            raise RuntimeError(f'llama-server binary missing: {binary}')
        specs['llm'] = llm_command(binary, model.expanduser(), threads, context, mmproj)
        required_mb = (model.stat().st_size // (1024*1024)) + 512
        admitted, reason = arbiter.try_start(Job('local-llm','LLM',required_mb))
        if not admitted:
            raise RuntimeError(f'LLM admission blocked: {reason}; inspect free RAM / temperature')
    paths['logs'].mkdir(mode=0o700, parents=True, exist_ok=True)
    with paths['lock'].open('a+') as lock, ExitStack() as resources:
        if model is not None:
            # Shared cross-process lock: cloud/backup.sh uses the same path.
            lock_dir = Path.home()/'.omega-x'
            lock_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
            heavy_lock = resources.enter_context((lock_dir/'compute-io.lock').open('a+'))
            try:
                fcntl.flock(heavy_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError('Bulk backup is active; local LLM waits for idle I/O') from exc
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('An OMEGA node is already active') from exc
        children: dict[str, subprocess.Popen] = {}
        logs = {}
        budgets = {name: RestartBudget() for name in specs}
        stopped = False
        thermal_paused = False

        def signal_handler(_signum, _frame):
            nonlocal stopped
            stopped = True

        old_handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        for s in old_handlers:
            signal.signal(s, signal_handler)
        try:
            def launch(name: str):
                if not budgets[name].allow(time.monotonic()):
                    raise RuntimeError(f'Restart budget exhausted for {name}')
                logfile = paths['logs'] / f'{name}.log'
                rotate_once(logfile)
                log = logfile.open('ab', buffering=0)
                logs[name] = log
                children[name] = subprocess.Popen(specs[name], stdout=log, stderr=subprocess.STDOUT,
                                                   stdin=subprocess.DEVNULL, start_new_session=True)
                LOGGER.info('Started %s pid=%d', name, children[name].pid)

            for name in specs:
                launch(name)
            while not stopped:
                time.sleep(1)
                if model is not None:
                    reading = arbiter.probe.sample().get('thermal_celsius')
                    if reading is not None and reading >= arbiter.high_c and not thermal_paused:
                        LOGGER.warning('Thermal policy trip %.1f C: stopping LLM until recovery',reading)
                        thermal_paused = True
                        proc = children.get('llm')
                        if proc is not None and proc.poll() is None:
                            try:
                                os.killpg(proc.pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                    elif thermal_paused and reading is not None and reading <= arbiter.low_c:
                        thermal_paused=False
                        LOGGER.info('Thermal policy recovered %.1f C',reading)
                for name, proc in list(children.items()):
                    ret = proc.poll()
                    if ret is None:
                        continue
                    LOGGER.error('%s exited with status %s', name, ret)
                    logs[name].close()
                    if name == 'llm' and thermal_paused:
                        continue
                    time.sleep(2)
                    launch(name)
                if model is not None and not thermal_paused and 'llm' in children and children['llm'].poll() is not None:
                    launch('llm')
            return 0
        finally:
            for child in children.values():
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            for child in children.values():
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
            for log in logs.values():
                if not log.closed:
                    log.close()
            for s, handler in old_handlers.items():
                signal.signal(s, handler)


def status() -> None:
    for name, port in PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(.5)
            ok = sock.connect_ex(('127.0.0.1', port)) == 0
            print(f'{name}:{port} {"LISTENING" if ok else "NOT LISTENING"} (port only)')


def main() -> int:
    ap = argparse.ArgumentParser(description='OMEGA Mobile Node')
    ap.add_argument('command', choices=['init', 'run', 'status'])
    ap.add_argument('--root', type=Path, default=Path.home() / 'omega-node')
    ap.add_argument('--without-webdav', action='store_true')
    ap.add_argument('--sftp-bind', default='127.0.0.1')
    ap.add_argument('--allow-lan', action='store_true', help='Explicitly permit SFTP on an exact private IP')
    ap.add_argument('--model', type=Path)
    ap.add_argument('--mmproj',type=Path,help='Only when confirmed matching model lineage; dimensions alone are insufficient')
    ap.add_argument('--threads', type=int, default=4)
    ap.add_argument('--context', type=int, default=2048)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        if args.command == 'init':
            initialize(args.root, without_webdav=args.without_webdav)
        elif args.command == 'run':
            return supervise(args.root, bind=args.sftp_bind, model=args.model,
                             threads=args.threads, context=args.context,
                             without_webdav=args.without_webdav, mmproj=args.mmproj, allow_lan=args.allow_lan)
        else:
            status()
        return 0
    except (ValueError, RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        LOGGER.error('%s', exc)
        return 1


if __name__ == '__main__':
    sys.exit(main())
