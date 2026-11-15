"""PHASESHIFT: bounded counterfactual workflow scheduling with checkable plans.

A slot is a *declared* unit of work, not a measured second. RAM and disk
budgets are declared; no resource is actually reserved by this module.
"""
from __future__ import annotations
import hashlib
import json
import math
import re
from typing import Any
from .planner import _check_tasks, validate_catalog

SCHEMA = 'omega.phaseshift.plan.v1'
SAFE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
PRIVACY_RANK = {'any': 0, 'trusted_only': 1, 'local_only': 2}


def canonical(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(data: Any) -> str:
    return hashlib.sha256(canonical(data)).hexdigest()


def _check_inputs(tasks: list[dict], nodes: list[dict], catalog: dict,
                  horizon: int, max_states: int) -> list[dict]:
    validate_catalog(catalog)
    ordered = _check_tasks(tasks)
    if not ordered or len(ordered) > 24:
        raise ValueError('PHASESHIFT requires 1..24 tasks')
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 8:
        raise ValueError('PHASESHIFT requires 1..8 nodes')
    if type(horizon) is not int or not 1 <= horizon <= 64:
        raise ValueError('horizon must be 1..64 slots')
    if type(max_states) is not int or not 1 <= max_states <= 2_000_000:
        raise ValueError('max_states must be 1..2000000')
    seen = set()
    for n in nodes:
        if not isinstance(n, dict) or not isinstance(n.get('id'), str) or not SAFE.fullmatch(n['id']):
            raise ValueError('Invalid node identifier')
        if n['id'] in seen:
            raise ValueError('Duplicate node identifier')
        seen.add(n['id'])
        if n.get('trust') not in ('local', 'trusted', 'untrusted'):
            raise ValueError('Invalid node trust')
        for key in ('ram_available_mb', 'ram_headroom_mb', 'disk_free_bytes'):
            if type(n.get(key)) is not int or n[key] < 0:
                raise ValueError('Invalid node capacity: '+key)
        for key in ('capabilities', 'models'):
            if not isinstance(n.get(key), list) or any(not isinstance(x, str) for x in n[key]):
                raise ValueError('Invalid node '+key)
        if type(n.get('priority', 100)) is not int:
            raise ValueError('Invalid node priority')
        t = n.get('thermal_c')
        if type(t) not in (int, float) or not math.isfinite(t):
            raise ValueError('Invalid node thermal reading')
    for job in ordered:
        d = job.get('duration_slots', 1)
        if type(d) is not int or not 1 <= d <= horizon:
            raise ValueError('Invalid duration_slots for '+job['id'])
        if type(job.get('requires_verified_lineage', False)) is not bool:
            raise ValueError('requires_verified_lineage must be boolean')
    return ordered


def _effective_privacy(ordered: list[dict]) -> dict[str, str]:
    effective: dict[str, str] = {}
    for job in ordered:
        classes = [job.get('privacy', 'trusted_only')]
        classes.extend(effective[d] for d in job.get('depends_on', []))
        effective[job['id']] = max(classes, key=PRIVACY_RANK.__getitem__)
    return effective


def _eligible(job: dict, node: dict, privacy: str, catalog: dict) -> bool:
    if privacy == 'local_only' and node['trust'] != 'local':
        return False
    if privacy == 'trusted_only' and node['trust'] == 'untrusted':
        return False
    if job['engine'] not in node['capabilities'] or any(m not in node['models'] for m in job['models']):
        return False
    if any(m not in catalog for m in job['models']):
        return False
    if job.get('requires_verified_lineage', False) and any(
        catalog[m].get('lineage_verified') is not True for m in job['models']):
        return False
    if not 0 <= node['thermal_c'] < 43:
        return False
    if node['ram_available_mb'] - node['ram_headroom_mb'] < job['ram_mb']:
        return False
    if node['disk_free_bytes'] < job.get('output_bytes', 0):
        return False
    return True


class _BudgetExhausted(Exception):
    pass


def _schedule(ordered: list[dict], nodes: list[dict], catalog: dict,
              privacy: dict[str, str], horizon: int, max_states: int,
              failed_node: str | None = None) -> dict:
    usable = sorted((n for n in nodes if n['id'] != failed_node),
                    key=lambda n: (n.get('priority', 100), n['id']))
    candidate = {j['id']: [n for n in usable if _eligible(j, n, privacy[j['id']], catalog)]
                 for j in ordered}
    missing = [j['id'] for j in ordered if not candidate[j['id']]]
    if missing:
        return {'status': 'BLOCKED', 'reason': 'NO_ELIGIBLE_NODE',
                'unschedulable_tasks': missing, 'assignments': []}
    min_end = max(j.get('duration_slots', 1) for j in ordered)  # longest task
    # Stronger lower bound: critical path length (dependency precedence).
    finish_lb: dict[str, int] = {}
    for j in ordered:
        finish_lb[j['id']] = j.get('duration_slots', 1) + max(
            (finish_lb[d] for d in j.get('depends_on', [])), default=0)
    min_end = max(min_end, max(finish_lb.values()))
    if min_end > horizon:
        return {'status': 'BLOCKED', 'reason': 'CRITICAL_PATH_EXCEEDS_HORIZON', 'assignments': []}
    ram = {n['id']: [0] * horizon for n in usable}
    disk = {n['id']: 0 for n in usable}
    assigned: dict[str, dict] = {}
    steps = 0

    def visit(index: int, end_limit: int) -> bool:
        nonlocal steps
        steps += 1
        if steps > max_states:
            raise _BudgetExhausted
        if index == len(ordered):
            return True
        job = ordered[index]
        ident = job['id']
        duration = job.get('duration_slots', 1)
        earliest = max((assigned[d]['end_slot'] for d in job.get('depends_on', [])), default=0)
        for start in range(earliest, end_limit - duration + 1):
            end = start + duration
            for n in candidate[ident]:
                nid = n['id']
                if disk[nid] + job.get('output_bytes', 0) > n['disk_free_bytes']:
                    continue
                cap = n['ram_available_mb'] - n['ram_headroom_mb']
                if any(ram[nid][s] + job['ram_mb'] > cap for s in range(start, end)):
                    continue
                for s in range(start, end):
                    ram[nid][s] += job['ram_mb']
                disk[nid] += job.get('output_bytes', 0)
                assigned[ident] = {'id': ident, 'node': nid, 'start_slot': start,
                                   'end_slot': end, 'ram_mb': job['ram_mb'],
                                   'disk_bytes': job.get('output_bytes', 0),
                                   'effective_privacy': privacy[ident]}
                if visit(index + 1, end_limit):
                    return True
                del assigned[ident]
                disk[nid] -= job.get('output_bytes', 0)
                for s in range(start, end):
                    ram[nid][s] -= job['ram_mb']
        return False

    try:
        for makespan in range(min_end, horizon + 1):
            if visit(0, makespan):
                return {'status': 'READY', 'makespan_slots': makespan,
                        'assignments': [assigned[j['id']] for j in ordered],
                        'explored_states': steps}
    except _BudgetExhausted:
        return {'status': 'INDETERMINATE', 'reason': 'SEARCH_BUDGET_EXCEEDED',
                'assignments': [], 'explored_states': steps}
    return {'status': 'BLOCKED', 'reason': 'NO_FEASIBLE_SCHEDULE_WITHIN_HORIZON',
            'assignments': [], 'explored_states': steps}


def compile_workflow(tasks: list[dict], nodes: list[dict], catalog: dict,
                     *, horizon: int = 8, max_states: int = 20000,
                     require_n_minus_one: bool = False) -> dict:
    if type(require_n_minus_one) is not bool:
        raise ValueError('require_n_minus_one must be boolean')
    ordered = _check_inputs(tasks, nodes, catalog, horizon, max_states)
    privacy = _effective_privacy(ordered)
    primary = _schedule(ordered, nodes, catalog, privacy, horizon, max_states)
    failures = {}
    if primary['status'] == 'READY':
        for n in sorted(nodes, key=lambda x: x['id']):
            failures[n['id']] = _schedule(ordered, nodes, catalog, privacy,
                                          horizon, max_states, failed_node=n['id'])
    if primary['status'] != 'READY':
        status = primary['status']
    elif all(v['status'] == 'READY' for v in failures.values()):
        status = 'RESILIENT'
    elif any(v['status'] == 'INDETERMINATE' for v in failures.values()):
        status = 'INDETERMINATE'
    else:
        status = 'BLOCKED_RESILIENCE' if require_n_minus_one else 'DEGRADED'
    admitted = primary['status'] == 'READY' and (
        not require_n_minus_one or status == 'RESILIENT')
    inputs = {'tasks': tasks, 'nodes': nodes, 'catalog': catalog,
              'horizon': horizon, 'max_states': max_states,
              'require_n_minus_one': require_n_minus_one}
    result = {'schema': SCHEMA, 'status': status, 'admitted': admitted,
              'input_sha256': digest(inputs), 'settings': {
                  'horizon': horizon, 'max_states': max_states,
                  'require_n_minus_one': require_n_minus_one},
              'primary': primary, 'failures': failures,
              'evidence_scope': 'Declared resources only; simulated full restart, not live failover; no runtime lease or attestation.'}
    result['certificate_sha256'] = digest(result)
    return result
