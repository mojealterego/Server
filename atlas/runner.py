"""Loopback-only llama-server client with no proxy/redirect and authenticated audit.

A returned model ID is server-reported, not independent verification of weights.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from . import audit

MAX_JSON = 2 * 1024 * 1024

class RunnerError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RunnerError('HTTP redirect forbidden')


def _base(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise RunnerError('Invalid local endpoint') from exc
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not port or \
       parsed.username is not None or parsed.password is not None or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise RunnerError('Only http://127.0.0.1:PORT loopback endpoint is permitted')
    return f'http://127.0.0.1:{port}'


def _json_request(opener, req: urllib.request.Request, timeout: int) -> dict[str, Any]:
    try:
        with opener.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise RunnerError(f'Unexpected HTTP status {response.status}')
            raw = response.read(MAX_JSON + 1)
            if len(raw) > MAX_JSON:
                raise RunnerError('Model API response exceeds 2 MiB')
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise RunnerError('Expected JSON object')
            return result
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RunnerError(f'Local model API failed: {type(exc).__name__}') from exc


def run_local_chat(prompt: str, output: Path, model_id: str, url: str,
                   audit_log: Path, key: bytes, *, max_tokens: int = 256,
                   timeout: int = 90) -> dict[str, Any]:
    endpoint = _base(url)
    if not isinstance(prompt, str) or not 1 <= len(prompt) <= 8192:
        raise RunnerError('Prompt must contain 1..8192 characters')
    if not isinstance(model_id, str) or not 1 <= len(model_id) <= 256:
        raise RunnerError('Invalid model identifier')
    if type(max_tokens) is not int or not 1 <= max_tokens <= 2048:
        raise RunnerError('Invalid max_tokens')
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise RunnerError('Invalid timeout')
    audit._check_key(key)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Output already exists')
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise RunnerError('Unsafe output directory')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    models = _json_request(opener, urllib.request.Request(endpoint + '/v1/models'), timeout)
    available = models.get('data')
    if not isinstance(available, list) or model_id not in [x.get('id') for x in available if isinstance(x, dict)]:
        raise RunnerError('Expected model id not reported by local server')
    body = json.dumps({'model': model_id, 'messages': [{'role': 'user', 'content': prompt}],
                       'max_tokens': max_tokens, 'stream': False}, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(endpoint + '/v1/chat/completions', data=body,
                                 headers={'Content-Type': 'application/json'}, method='POST')
    result = _json_request(opener, req, timeout)
    try:
        text = result['choices'][0]['message']['content']
    except (KeyError, IndexError, TypeError) as exc:
        raise RunnerError('Unexpected chat completion response') from exc
    if not isinstance(text, str) or not text:
        raise RunnerError('No textual answer returned')
    fd, tmp = tempfile.mkstemp(prefix='.atlas-response-', dir=output.parent)
    published = False
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(text.encode('utf-8'))
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp, output, follow_symlinks=False)
        published = True
        audit.append_record(audit_log, key, {'stage': 'local_llm', 'status': 'completed',
                                             'model_reported_id': model_id, 'prompt': prompt,
                                             'max_tokens': max_tokens, 'endpoint': endpoint}, output=output)
        return {'status': 'COMPLETED', 'model_reported_id': model_id,
                'output': str(output), 'output_bytes': output.stat().st_size,
                'audit_log': str(audit_log),
                'warning': 'Model identity is server-reported; no independent hardware/model attestation.'}
    except BaseException:
        if published:
            output.unlink(missing_ok=True)
        raise
    finally:
        Path(tmp).unlink(missing_ok=True)
