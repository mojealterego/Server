"""Independent schedule validator; deliberately does not call PHASESHIFT scheduler.

Rehashing a forged certificate does not bypass resource or privacy checks.
A SHA-256 certificate is NOT an authenticity signature or hardware attestation.
"""
from __future__ import annotations
import math
from typing import Any
from .phaseshift import SCHEMA, digest, _check_inputs


def _check_scenario(scenario: dict, ordered: list[dict], nodes: list[dict],
                    catalog: dict, horizon: int, failed: str | None) -> bool:
    if not isinstance(scenario, dict) or scenario.get('status') not in ('READY', 'BLOCKED', 'INDETERMINATE'):
        raise ValueError('Invalid scenario status')
    if scenario['status'] != 'READY':
        if scenario.get('assignments') != []:
            raise ValueError('Non-ready scenario cannot contain executable assignments')
        return False  # infeasibility is not proven by the certificate
    tasks_by_id = {t['id']: t for t in ordered}
    nodes_by_id = {n['id']: n for n in nodes}
    stages = scenario.get('assignments')
    if not isinstance(stages, list) or len(stages) != len(ordered):
        raise ValueError('Incomplete scenario')
    observed: dict[str, dict] = {}
    ram = {n['id']: [0] * horizon for n in nodes}
    disk = {n['id']: 0 for n in nodes}
    for item in stages:
        if not isinstance(item, dict) or set(item) != {
                'id', 'node', 'start_slot', 'end_slot', 'ram_mb', 'disk_bytes', 'effective_privacy'}:
            raise ValueError('Malformed stage assignment')
        tid, nid = item['id'], item['node']
        if tid not in tasks_by_id or tid in observed or nid not in nodes_by_id or nid == failed:
            raise ValueError('Invalid stage/node assignment')
        t, n = tasks_by_id[tid], nodes_by_id[nid]
        a, b = item['start_slot'], item['end_slot']
        if type(a) is not int or type(b) is not int or not 0 <= a < b <= horizon:
            raise ValueError('Invalid slot range')
        if b - a != t.get('duration_slots', 1):
            raise ValueError('Duration mismatch')
        if item['ram_mb'] != t['ram_mb'] or item['disk_bytes'] != t.get('output_bytes', 0):
            raise ValueError('Reservation mismatch')
        privacy_rank = {'any': 0, 'trusted_only': 1, 'local_only': 2}
        restrictions = [t.get('privacy', 'trusted_only')]
        for dep in t.get('depends_on', []):
            if dep not in observed:
                raise ValueError('Out-of-order dependency')
            if observed[dep]['end_slot'] > a:
                raise ValueError('Dependency overlaps')
            restrictions.append(observed[dep]['effective_privacy'])
        privacy = max(restrictions, key=privacy_rank.__getitem__)
        if item['effective_privacy'] != privacy:
            raise ValueError('Effective privacy mismatch')
        if privacy == 'local_only' and n['trust'] != 'local':
            raise ValueError('Local-only privacy violation')
        if privacy == 'trusted_only' and n['trust'] == 'untrusted':
            raise ValueError('Trust violation')
        if t['engine'] not in n['capabilities'] or any(m not in n['models'] for m in t['models']):
            raise ValueError('Engine or model not staged')
        if any(m not in catalog for m in t['models']):
            raise ValueError('Unknown model')
        if t.get('requires_verified_lineage', False) and any(
                catalog[m].get('lineage_verified') is not True for m in t['models']):
            raise ValueError('Unverified model lineage')
        if not 0 <= n['thermal_c'] < 43:
            raise ValueError('Thermal violation')
        cap = n['ram_available_mb'] - n['ram_headroom_mb']
        for s in range(a, b):
            ram[nid][s] += t['ram_mb']
            if ram[nid][s] > cap:
                raise ValueError('RAM overcommit')
        disk[nid] += t.get('output_bytes', 0)
        if disk[nid] > n['disk_free_bytes']:
            raise ValueError('Disk overcommit')
        observed[tid] = item
    if set(observed) != set(tasks_by_id):
        raise ValueError('Missing tasks')
    if type(scenario.get('makespan_slots')) is not int or scenario['makespan_slots'] != max(
            x['end_slot'] for x in observed.values()):
        raise ValueError('Makespan mismatch')
    return True


def verify_workflow(document: dict, tasks: list[dict], nodes: list[dict],
                    catalog: dict) -> dict:
    if not isinstance(document, dict) or document.get('schema') != SCHEMA:
        raise ValueError('Wrong certificate schema')
    settings = document.get('settings')
    if not isinstance(settings, dict) or set(settings) != {
            'horizon', 'max_states', 'require_n_minus_one'}:
        raise ValueError('Invalid certificate settings')
    if type(settings['require_n_minus_one']) is not bool:
        raise ValueError('Invalid resilience requirement')
    ordered = _check_inputs(tasks, nodes, catalog, settings['horizon'], settings['max_states'])
    if document.get('input_sha256') != digest({
        'tasks': tasks, 'nodes': nodes, 'catalog': catalog, **settings}):
        raise ValueError('Input fingerprint mismatch')
    if document.get('certificate_sha256') != digest({
        k: v for k, v in document.items() if k != 'certificate_sha256'}):
        raise ValueError('Certificate digest mismatch')
    primary = _check_scenario(document.get('primary'), ordered, nodes, catalog,
                              settings['horizon'], None)
    failures = document.get('failures')
    if not isinstance(failures, dict):
        raise ValueError('Invalid failure scenarios')
    if primary and set(failures) != {n['id'] for n in nodes}:
        raise ValueError('Incomplete N-1 failure coverage')
    if not primary and failures:
        raise ValueError('No failover scenarios allowed without primary')
    verified = []
    for failed, scenario in failures.items():
        if _check_scenario(scenario, ordered, nodes, catalog,
                           settings['horizon'], failed):
            verified.append(failed)
    if not primary:
        expected_status = document['primary']['status']
    elif len(verified) == len(nodes):
        expected_status = 'RESILIENT'
    elif any(v['status'] == 'INDETERMINATE' for v in failures.values()):
        expected_status = 'INDETERMINATE'
    else:
        expected_status = 'BLOCKED_RESILIENCE' if settings['require_n_minus_one'] else 'DEGRADED'
    expected_admitted = primary and (not settings['require_n_minus_one'] or expected_status == 'RESILIENT')
    if document.get('status') != expected_status or document.get('admitted') is not expected_admitted:
        raise ValueError('Invalid admission/status claim')
    return {'valid': True, 'primary_feasible': primary,
            'verified_failure_scenarios': sorted(verified),
            'unproven_failure_scenarios': sorted(set(failures) - set(verified)),
            'authenticity_verified': False, 'runtime_verified': False,
            'note': 'Checks feasibility only. BLOCKED/INDETERMINATE claims are not infeasibility proofs.'}
