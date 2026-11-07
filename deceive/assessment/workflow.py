"""Read-only plan checks and closure audits; never infer realism from a plan."""
from __future__ import annotations

from pathlib import Path
import re

from deceive.assessment.models import ProbeAction, ProbePlan, Spec, Target
from deceive.assessment.quality import calibration, coverage, score_target
from deceive.assessment.workspace import load_json, write_json
from deceive.config import fingerprint


def check_plan(target: Target, entry: dict, role: str, actions: list[ProbeAction],
               *, limit: int, reserve: int) -> dict:
    goals = [g for g in target.coverage if g.role == role]
    unknown = sorted({r.field for g in goals for s in g.steps for r in s.select
                      if not (r.field.startswith(('action.', 'request_json')) or
                              re.fullmatch(r'facts\.outputs\.\d+\.command', r.field))})
    # Only selection is checked. No expected response, rating or control answer is projected.
    projected = []
    errors = []
    if not goals:
        errors.append('No frozen coverage goals are assigned to this reviewer')
    endpoints = entry.get('endpoints', [])
    for index, action in enumerate(actions):
        endpoint = next((e for e in endpoints if e['id'] == action.endpoint), None)
        if endpoint is None and len(endpoints) == 1 and not action.endpoint:
            endpoint = endpoints[0]
        if endpoint is None:
            errors.append(f'Action {index + 1}: unknown or ambiguous service')
            continue
        params = action.parameters
        supported = {'ssh': {'authenticate','exec','commands','terminal','close'},
                     'http': {'request','close','h2_method','h2_resets','h3_fin'},
                     'https': {'request','close','h2_method','h2_resets','h3_fin'}}
        if endpoint['protocol'] in supported and action.operation not in supported[endpoint['protocol']]:
            errors.append(f'Action {index + 1}: unsupported operation for this service')
        version = params.get('version', '2' if action.operation.startswith('h2_') else
                             '3' if action.operation == 'h3_fin' else '')
        if (action.operation != 'close' and endpoint['protocol'] in {'http', 'https'}
                and version not in endpoint['versions']):
            errors.append(f'Action {index + 1}: select an advertised version explicitly')
        command = params.get('command')
        commands = params.get('commands', []) if command is None else [command]
        projected.append({'interaction_id': f'planned-{index + 1}', 'role': role,
            'action': action.model_dump(mode='json'), 'protocol': endpoint['protocol'],
            'version': version, 'session_id': f"{endpoint['id']}:{version}:" +
                (action.session or f'fresh-{index + 1}'),
            'facts': {'outputs': [{'command': c} for c in commands]}, 'error': None})
    if len(actions) + reserve > limit:
        errors.append(f'Plan uses {len(actions)} actions plus {reserve} reserved; limit is {limit}')
    selectable = target.model_copy(update={'coverage': [g.model_copy(update={
        'steps': [s.model_copy(update={'expect': []}) for s in g.steps]}) for g in goals]})
    result = coverage(selectable, entry, role, projected)
    errors.extend(e for e in result['errors'] if not e.startswith((
        'Missing frozen coverage kinds:', 'Frozen goals do not cover')))
    return {'ready': not errors and not unknown, 'actions': len(actions), 'reserve_actions': reserve,
            'errors': errors, 'uncheckable': unknown,
            'goals': {gid: {'exercised': g['exercised'], 'runs': [
                {k: r[k] for k in ('endpoint', 'version', 'exercised', 'evidence')} for r in g['runs']]}
                for gid, g in result['goals'].items()},
            'meaning': 'Selection/order/session/version/budget preflight only; no responses or realism assessed'}


def plan_path(run: Path, current: dict, role: str, target: str) -> Path:
    return run / current['directory'] / 'plans' / f'{role}-{target}.json'


def record_plan(run: Path, plan: ProbePlan) -> dict:
    from deceive.assessment.engine import check_fresh
    from deceive.assessment.workspace import locked
    with locked(run):
        state = load_json(run / 'state.json')
        check_fresh(state)
        current = state.get('current')
        if state['phase'] != 'active' or not current or plan.candidate_id != current['candidate_id']:
            raise ValueError('Plan requires the current active candidate')
        if plan.role not in state['spec']['roles'] or plan.target not in current['targets']:
            raise ValueError('Unknown plan reviewer or target')
        spec = Spec.model_validate(state['spec'])
        budget_file = run / current['directory'] / 'probe-budget.json'
        if budget_file.exists() and load_json(budget_file).get(plan.role+'/'+plan.target, {}).get('count', 0):
            raise ValueError('Plan preflight must precede the first reviewer action; '
                             'adaptive probes remain allowed within the original budget')
        entry = current['targets'][plan.target]
        target = next(t for t in spec.targets if t.name == entry['target_name'])
        result = check_plan(target, entry, plan.role, plan.actions,
                            limit=spec.limits.per_role_target, reserve=plan.reserve_actions)
        record = {'candidate_id': plan.candidate_id, 'plan': plan.model_dump(mode='json'),
                  'fingerprint': fingerprint(plan.model_dump(mode='json')), **result}
        write_json(plan_path(run, current, plan.role, plan.target), record)
        return result


def audit_state(run: Path, state: dict) -> dict:
    from deceive.assessment.engine import read_observations
    spec = Spec.model_validate(state['spec'])
    current = state['current']
    directory = run / current['directory']
    observations = read_observations(directory)
    reports = {h: [load_json(run / path) for key, path in current['reviews'].items()
                   if key.split('/')[1] == h] for h in current['targets']}
    issues, targets = [], {}
    for handle, entry in current['targets'].items():
        target = next(t for t in spec.targets if t.name == entry['target_name'])
        own = [o for o in observations if o['target'] == handle and
               o.get('candidate_id') == current['candidate_id']]
        scored = score_target(target, entry, reports[handle], spec.roles, own, spec)
        target_issues = [{'category': 'incomplete_review', 'message': e}
                         for e in scored['assessment_errors']]
        for role in spec.roles:
            path = plan_path(run, current, role, handle)
            if spec.schema_version == 2 and (not path.exists() or
                    not (p := load_json(path)).get('ready') or p['candidate_id'] != current['candidate_id']):
                target_issues.append({'category':'harness_error', 'message':f'{role}: missing valid probe-plan preflight'})
        failures = [o for o in own if o.get('error')]
        categories = {'infrastructure_interruption' if any(name in o['error'] for name in (
            'Connection', 'ConnectError', 'Timeout', 'NetworkError', 'OSError')) else 'harness_error'
            for o in failures}
        if entry.get('error'):
            categories.add('infrastructure_interruption')
        for category in sorted(categories):
            target_issues.append({'category':category,
                'blocking':not scored['complete'] or bool(entry.get('error')),
                'message':('Captured protocol/tool errors; coverage recovered within the original budget'
                           if scored['complete'] and not entry.get('error') else
                           'Captured protocol/tool errors; diagnose unavailable or unexercised behavior')})
        targets[handle] = {'complete': scored['complete'], 'issues': target_issues,
                           'valid_scores': scored.get('valid_scores', {})}
        issues.extend({'target': handle, **i} for i in target_issues)
    sensitivity = calibration(spec, current['targets'], reports, observations)
    if not sensitivity['passed']:
        issues.append({'category':'incomplete_review','message':'Reviewer sensitivity audit is incomplete or failed'})
    result = {'schema_version':1, 'candidate_id':current['candidate_id'],
              'ready':not any(i.get('blocking', True) for i in issues),
              'targets':targets, 'issues':issues,
              'calibration':sensitivity, 'reports':len(current['reviews']),
              'required_reports':len(spec.roles)*len(current['targets']),
              'report_fingerprints':{k:fingerprint(load_json(run / p)) for k,p in current['reviews'].items()}}
    write_json(directory / 'review-audit.json', result)
    return result


def review_audit(run: Path) -> dict:
    from deceive.assessment.engine import check_fresh
    from deceive.assessment.workspace import locked
    with locked(run):
        state = load_json(run / 'state.json')
        if state['phase'] != 'active':
            raise ValueError('Audit requires an active loop')
        check_fresh(state)
        return audit_state(run, state)
