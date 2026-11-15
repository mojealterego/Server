"""Deterministic fail-closed model placement. No fictitious throughput estimates."""
from __future__ import annotations
import re
from typing import Any

SAFE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
ENGINES = {'llama', 'sd-cli', 'comfyui', 'onnxruntime', 'mediapipe'}
PRIVACY = {'local_only', 'trusted_only', 'any'}
TRUST = {'local', 'trusted', 'untrusted'}


def validate_catalog(catalog: dict[str, Any]) -> None:
    if not isinstance(catalog, dict):
        raise ValueError('Catalog must be an object')
    for key, val in catalog.items():
        if not isinstance(key, str) or not SAFE.fullmatch(key) or key in ('.', '..'):
            raise ValueError('Unsafe model identifier')
        if not isinstance(val, dict) or type(val.get('bytes')) is not int or val['bytes'] < 0:
            raise ValueError('Invalid catalog model size')
        if not isinstance(val.get('format'), str) or not isinstance(val.get('role'), str):
            raise ValueError('Missing model format/role')


def _check_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(tasks, list) or len(tasks) > 256:
        raise ValueError('Invalid task count')
    by_id = {}
    for job in tasks:
        if not isinstance(job, dict) or not isinstance(job.get('id'), str) or not SAFE.fullmatch(job['id']):
            raise ValueError('Invalid task identifier')
        if job['id'] in by_id:
            raise ValueError('Duplicate task identifier')
        if job.get('engine') not in ENGINES:
            raise ValueError('Unknown execution engine')
        if not isinstance(job.get('models'), list) or any(not isinstance(m, str) or not SAFE.fullmatch(m) for m in job['models']):
            raise ValueError('Invalid model references')
        if type(job.get('ram_mb')) is not int or job['ram_mb'] <= 0:
            raise ValueError('ram_mb must be a positive integer')
        if job.get('privacy', 'trusted_only') not in PRIVACY:
            raise ValueError('Unknown privacy class')
        if type(job.get('output_bytes', 0)) is not int or job.get('output_bytes', 0) < 0:
            raise ValueError('Invalid output reservation')
        deps = job.get('depends_on', [])
        if not isinstance(deps, list) or any(not isinstance(x, str) for x in deps):
            raise ValueError('Invalid dependencies')
        by_id[job['id']] = job
    for job in tasks:
        if any(dep not in by_id for dep in job.get('depends_on', [])):
            raise ValueError('Unknown dependency')
    visited: set[str] = set()
    visiting: set[str] = set()
    ordered: list[dict[str, Any]] = []
    def visit(jobid: str) -> None:
        if jobid in visiting:
            raise ValueError('Dependency cycle detected')
        if jobid in visited:
            return
        visiting.add(jobid)
        job = by_id[jobid]
        for dep in job.get('depends_on', []):
            visit(dep)
        visiting.remove(jobid)
        visited.add(jobid)
        ordered.append(job)
    for job in tasks:
        visit(job['id'])
    return ordered


def _node_eligible(job: dict, node: dict) -> bool:
    if node.get('trust') not in TRUST:
        return False
    privacy = job.get('privacy', 'trusted_only')
    if privacy == 'local_only' and node['trust'] != 'local':
        return False
    if privacy == 'trusted_only' and node['trust'] == 'untrusted':
        return False
    if job['engine'] not in node.get('capabilities', []):
        return False
    if any(m not in node.get('models', []) for m in job['models']):
        return False
    for field in ('ram_available_mb', 'ram_headroom_mb', 'disk_free_bytes'):
        if type(node.get(field)) is not int or node[field] < 0:
            return False
    if node['ram_available_mb'] < job['ram_mb'] + node['ram_headroom_mb']:
        return False
    if node['disk_free_bytes'] < job.get('output_bytes', 0):
        return False
    temp = node.get('thermal_c')
    if not isinstance(temp, (float, int)) or isinstance(temp, bool) or not 0 <= temp < 43:
        return False
    return True


def plan(tasks: list[dict[str, Any]], nodes: list[dict[str, Any]], catalog: dict[str, Any]) -> dict[str, Any]:
    validate_catalog(catalog)
    ordered = _check_tasks(tasks)
    if not isinstance(nodes, list) or len(nodes) > 128:
        raise ValueError('Invalid nodes')
    if len({n.get('id') for n in nodes if isinstance(n, dict)}) != len(nodes):
        raise ValueError('Duplicate or invalid node IDs')
    outcomes: dict[str, dict] = {}
    for job in ordered:
        reasons: list[str] = []
        if any(outcomes[d]['status'] != 'READY' for d in job.get('depends_on', [])):
            outcomes[job['id']] = {'id': job['id'], 'status': 'BLOCKED_DEPENDENCY', 'node': None,
                                    'reasons': ['UPSTREAM_NOT_READY']}
            continue
        for model in job['models']:
            if model not in catalog:
                reasons.append('UNKNOWN_MODEL')
            elif job.get('requires_verified_lineage', False) and not catalog[model].get('lineage_verified', False):
                reasons.append(f'UNVERIFIED_LINEAGE:{model}')
        if reasons:
            outcomes[job['id']] = {'id': job['id'], 'status': 'BLOCKED', 'node': None, 'reasons': reasons}
            continue
        eligible = [n for n in nodes if _node_eligible(job, n)]
        if eligible:
            chosen = sorted(eligible, key=lambda n: (n.get('priority', 100), n['id']))[0]
            outcomes[job['id']] = {'id': job['id'], 'status': 'READY', 'node': chosen['id'],
                                    'reasons': [], 'estimated_ram_mb': job['ram_mb'],
                                    'privacy': job.get('privacy', 'trusted_only')}
        else:
            absent = [m for m in job['models'] if not any(m in n.get('models', []) for n in nodes)]
            reasons = [f'MODEL_NOT_STAGED:{m}' for m in absent]
            reasons.append('NO_ELIGIBLE_NODE')
            outcomes[job['id']] = {'id': job['id'], 'status': 'BLOCKED', 'node': None, 'reasons': reasons}
    return {'schema': 'omega.atlas.plan.v1', 'stages': list(outcomes.values()),
            'ready': sum(x['status'] == 'READY' for x in outcomes.values()),
            'blocked': sum(x['status'] != 'READY' for x in outcomes.values()),
            'note': 'Resource estimates and node capability declarations require device verification; this is a plan, not execution.'}
