"""Single-purpose, loopback-only llama-server job adapter.

No third-party network, proxy, redirects, retries of a POST or arbitrary shell.
The server-reported model id is NOT a cryptographic proof of model weights.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time
import urllib.error
import urllib.request

from .runner import NoRedirect, RunnerError, _base, _json_request

MAX_PROMPT_BYTES = 32768
MAX_ANSWER_BYTES = 2 * 1024 * 1024


class LlamaJobError(RuntimeError):
    pass


def _positive_int(value: int, low: int, high: int, name: str) -> None:
    if type(value) is not int or not low <= value <= high:
        raise LlamaJobError(f'Invalid {name}')


def validate_chat(endpoint: str, model: str, prompt_file: Path, *,
                  max_tokens: int = 256, ready_timeout: int = 15,
                  request_timeout: int = 90) -> str:
    try:
        base = _base(endpoint)
    except RunnerError as exc:
        raise LlamaJobError('Endpoint must be a literal IPv4 loopback address') from exc
    if not isinstance(model, str) or not 1 <= len(model) <= 256 or any(ord(ch) < 32 for ch in model):
        raise LlamaJobError('Invalid model identifier')
    _positive_int(max_tokens, 1, 2048, 'max_tokens')
    _positive_int(ready_timeout, 1, 300, 'ready_timeout')
    _positive_int(request_timeout, 1, 3600, 'request_timeout')
    _read_prompt(prompt_file)
    return base


def _read_prompt(prompt_file: Path) -> str:
    if not isinstance(prompt_file, Path) or prompt_file.is_symlink():
        raise LlamaJobError('Prompt must be a nonsymlink path')
    try:
        fd = os.open(prompt_file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0))
    except OSError as exc:
        raise LlamaJobError('Cannot open prompt file') from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_PROMPT_BYTES:
            raise LlamaJobError('Prompt must be a bounded regular file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_PROMPT_BYTES + 1)
        after = os.fstat(fd)
        if (len(raw) > MAX_PROMPT_BYTES or before.st_size != len(raw) or
                before.st_ino != after.st_ino or before.st_size != after.st_size or
                before.st_mtime_ns != after.st_mtime_ns):
            raise LlamaJobError('Prompt is oversized or changed during read')
    finally:
        os.close(fd)
    try:
        prompt = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise LlamaJobError('Prompt must be UTF-8') from exc
    if not 1 <= len(prompt) <= 8192:
        raise LlamaJobError('Prompt must be 1..8192 characters')
    return prompt


def _wait_until_healthy(opener, base: str, *, deadline: float, request_timeout: int) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LlamaJobError('MODEL_NOT_READY: health deadline exceeded')
        req = urllib.request.Request(base + '/health')
        try:
            with opener.open(req, timeout=min(request_timeout, remaining)) as response:
                if response.status != 200:
                    raise LlamaJobError('HEALTH_FAILED: unexpected status')
                data = response.read(4097)
                if len(data) > 4096:
                    raise LlamaJobError('HEALTH_FAILED: oversized response')
                health = json.loads(data)
                if not isinstance(health, dict) or health.get('status') != 'ok':
                    raise LlamaJobError('HEALTH_FAILED: unexpected health content')
                return
        except urllib.error.HTTPError as exc:
            if exc.code != 503:
                raise LlamaJobError(f'HEALTH_FAILED: HTTP {exc.code}') from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise LlamaJobError(f'HEALTH_FAILED: {type(exc).__name__}') from exc
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def perform_chat(endpoint: str, model: str, prompt_file: Path, *,
                 max_tokens: int = 256, ready_timeout: int = 15,
                 request_timeout: int = 90) -> bytes:
    base = validate_chat(endpoint, model, prompt_file, max_tokens=max_tokens,
                         ready_timeout=ready_timeout, request_timeout=request_timeout)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    _wait_until_healthy(opener, base, deadline=time.monotonic() + ready_timeout,
                        request_timeout=request_timeout)
    models = _json_request(opener, urllib.request.Request(base + '/v1/models'), request_timeout)
    catalog = models.get('data')
    if not isinstance(catalog, list) or model not in [m.get('id') for m in catalog if isinstance(m, dict)]:
        raise LlamaJobError('MODEL_MISMATCH: model ID not reported by server')
    prompt = _read_prompt(prompt_file)
    payload = json.dumps({'model': model, 'messages': [{'role': 'user', 'content': prompt}],
                          'max_tokens': max_tokens, 'stream': False}, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(base + '/v1/chat/completions',
                                 data=payload, headers={'Content-Type': 'application/json'},
                                 method='POST')
    # No retry on POST: a server may already have computed the response.
    response = _json_request(opener, req, request_timeout)
    try:
        answer = response['choices'][0]['message']['content']
    except (KeyError, TypeError, IndexError) as exc:
        raise LlamaJobError('INVALID_REPLY: no chat answer') from exc
    if not isinstance(answer, str) or not answer:
        raise LlamaJobError('INVALID_REPLY: text answer required')
    data = answer.encode('utf-8')
    if len(data) > MAX_ANSWER_BYTES:
        raise LlamaJobError('INVALID_REPLY: answer too large')
    return data


def write_response_new(output: Path, content: bytes) -> None:
    output = Path(output)
    parent = output.parent
    if parent.is_symlink() or not parent.is_dir() or output.is_symlink():
        raise LlamaJobError('Unsafe output destination')
    if output.exists():
        raise LlamaJobError('Refusing to overwrite existing output')
    # One open(2) with O_EXCL prevents replacing an existing path, including
    # when another actor races the preflight check above.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as dest:
            dest.write(content)
            dest.flush()
            os.fsync(dest.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
