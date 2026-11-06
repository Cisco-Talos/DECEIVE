"""Evidence-v3 coverage and sensitivity gates, independent of any network protocol."""
from __future__ import annotations

import base64
import binascii
import json
import ntpath
from statistics import median

import regex

from deceive.assessment.models import CoverageGoal, EvidenceRule, ROLES, Spec, Target
from deceive.assessment.rubric import CRITERIA

_MISSING = object()


def field(observation: dict, path: str) -> object:
    """Read captured data only; no expressions, templates or filesystem access."""
    parts = path.split('.')
    value: object = observation
    if parts[0] in {'body_text', 'body_json', 'request_json'}:
        try:
            if parts[0] == 'request_json':
                params = observation['action']['parameters']
                raw = params.get('body')
                if raw is None:
                    raw = base64.b64decode(params.get('body_base64', ''), validate=True)
            else:
                raw = base64.b64decode(observation.get('body_base64', ''), validate=True)
            value = raw.decode('utf-8') if isinstance(raw, bytes) else raw
            if parts[0] != 'body_text':
                value = json.loads(value)
        except (KeyError, ValueError, TypeError, UnicodeError, binascii.Error):
            return _MISSING
        parts = parts[1:]
    for key in parts:
        if isinstance(value, dict):
            value = value.get(key, _MISSING)
        elif isinstance(value, list) and key.isdecimal() and int(key) < len(value):
            value = value[int(key)]
        else:
            return _MISSING
    return value


def rules_match(observation: dict, rules: list[EvidenceRule], captures: dict) -> dict | None:
    captured = captures.copy()
    for rule in rules:
        value = field(observation, rule.field)
        if rule.exists is False:
            if value is not _MISSING:
                return None
            continue
        if value is _MISSING:
            return None
        if 'equals' in rule.model_fields_set and (type(value) is not type(rule.equals) or value != rule.equals):
            return None
        if rule.contains is not None and (not isinstance(value, str) or rule.contains not in value):
            return None
        match = None
        if rule.pattern is not None:
            try:
                match = regex.search(rule.pattern, value, timeout=.02) if isinstance(value, str) else None
            except TimeoutError:
                return None
            if match is None:
                return None
        compared = match.group(1) if match and match.lastindex else value
        if rule.normalize:
            if not isinstance(compared, str):
                return None
            if rule.normalize == 'windows_path':
                if len(compared) >= 2 and compared[0] == compared[-1] and compared[0] in "\"'":
                    compared = compared[1:-1]
                compared = ntpath.normcase(ntpath.normpath(compared))
            else:
                compared = compared.casefold()
        if rule.equals_capture and (rule.equals_capture not in captured or compared != captured[rule.equals_capture]):
            return None
        if rule.not_equals_capture and (rule.not_equals_capture not in captured or compared == captured[rule.not_equals_capture]):
            return None
        if rule.capture:
            captured[rule.capture] = compared
    return captured


def recipient_has_setup(goal: CoverageGoal, observations: list[dict], index: int,
                        captures: dict, step_index: int) -> bool:
    """A recipient's own setup cannot establish cross-client state leakage."""
    recipient = observations[index].get('session_id')
    links = {rule.equals_capture for rule in goal.steps[step_index].select if rule.equals_capture}
    setup = goal.steps[0]
    for prior in observations[:index]:
        if prior.get('session_id') != recipient:
            continue
        selected = rules_match(prior, setup.select, {})
        if selected is None:
            continue
        selected = rules_match(prior, setup.expect, selected) or selected
        if all(key in selected and key in captures and selected[key] == captures[key]
               for key in links):
            return True
    return False


def sequence(goal: CoverageGoal, observations: list[dict]) -> dict:
    """Find distinct, ordered actions. Selection establishes coverage; expectations detect defects."""
    pending = [(0, 0, {}, [], [])]
    searched = 0
    while pending and searched < 4096:
        step_index, offset, captures, chosen, failures = pending.pop()
        if step_index == len(goal.steps):
            return {'exercised': True, 'evidence': [o['interaction_id'] for o in chosen],
                    'expectations_passed': not failures, 'failed_steps': failures}
        step = goal.steps[step_index]
        for index in range(len(observations) - 1, offset - 1, -1):
            searched += 1
            if searched > 4096:
                break
            observation = observations[index]
            if any(o['interaction_id'] == observation['interaction_id'] for o in chosen):
                continue
            if chosen and goal.same_session and (not chosen[0].get('session_id') or
                    observation.get('session_id') != chosen[0]['session_id']):
                continue
            if chosen and goal.different_sessions and (not observation.get('session_id') or
                    any(o.get('session_id') == observation['session_id'] for o in chosen)):
                continue
            selected = rules_match(observation, step.select, captures)
            if selected is None:
                continue
            if (chosen and goal.kind == 'isolation' and goal.different_sessions and
                    recipient_has_setup(goal, observations, index, captures, step_index)):
                continue
            expected = rules_match(observation, step.expect, selected)
            pending.append((step_index + 1, index + 1 if goal.ordered else 0, expected or selected,
                            chosen + [observation], failures + ([step_index + 1] if expected is None else [])))
    return {'exercised': False, 'evidence': [], 'expectations_passed': None,
            'failed_steps': [], 'search_exhausted': searched >= 4096}


def coverage(target: Target, entry: dict, role: str, observations: list[dict]) -> dict:
    goals = [g for g in target.coverage if g.role == role]
    errors = []
    kinds = {g.kind for g in goals}
    needed = {'baseline', 'positive', 'negative', 'variation', 'repeat'}
    if role in {'attacker', 'consistency'}:
        needed.add('state')
    if role == 'consistency':
        needed.add('isolation')
    if needed - kinds:
        errors.append('Missing frozen coverage kinds: ' + ', '.join(sorted(needed - kinds)))
    if set(CRITERIA[role]) - {g.criterion for g in goals}:
        errors.append('Frozen goals do not cover all role criteria')
    substantive = [o for o in observations if o['role'] == role and not o.get('error')
                   and o['action']['operation'] != 'close']
    results = {}
    services = entry.get('endpoints', [])
    if not services:
        errors.append('No available service')
    for endpoint in services:
        selected = [o for o in substantive if o['action'].get('endpoint') == endpoint['id'] or
                    (len(services) == 1 and not o['action'].get('endpoint'))]
        versions = endpoint.get('versions', []) if endpoint['protocol'] in {'http', 'https'} else []
        if not selected or any(not any(o.get('version') == v for o in selected) for v in versions):
            errors.append(f"Missing service/version probes: {endpoint['id']}")
    for goal in goals:
        scopes = services if goal.every_service else [None]
        runs = []
        for endpoint in scopes:
            selected = [o for o in substantive if endpoint is None or
                o['action'].get('endpoint') == endpoint['id'] or
                (len(services) == 1 and not o['action'].get('endpoint'))]
            versions = endpoint.get('versions', []) if endpoint and goal.every_version else []
            for version in versions or [None]:
                result = sequence(goal, [o for o in selected if version is None or o.get('version') == version])
                runs.append(result | {'endpoint': endpoint['id'] if endpoint else None, 'version': version})
        exercised = bool(runs) and all(r['exercised'] for r in runs)
        results[goal.id] = {'criterion': goal.criterion, 'kind': goal.kind,
                           'exercised': exercised, 'runs': runs}
        if not exercised:
            errors.append(f'Unexercised coverage goal: {goal.id}')
    return {'complete': not errors, 'errors': errors, 'goals': results}


def score_target(target: Target, entry: dict, reviews: list[dict], roles: list[str],
                 observations: list[dict], spec: Spec) -> dict:
    scores, dimensions, details, errors, role_complete = {}, {}, {}, [], {}
    by_role = {r['role']: r for r in reviews}
    for role in roles:
        error_start = len(errors)
        role_complete[role] = False
        report = by_role.get(role)
        details[role] = coverage(target, entry, role, observations)
        errors.extend(f'{role}: {error}' for error in details[role]['errors'])
        if not report or report.get('schema_version') != (3 if spec.review_rubric == 'research-v4' else 2):
            errors.append(f'{role}: missing review for frozen rubric')
            continue
        if spec.review_rubric == 'research-v4':
            from deceive.assessment.research import comparison_errors
            errors.extend(f'{role}: {error}' for error in comparison_errors(target.research, report))
        own = {o['interaction_id'] for o in observations if o['role'] == role and
               o['action']['operation'] != 'close' and not o.get('error')}
        ratings = report.get('ratings', {})
        dimension = {}
        all_evidence = set()
        for name in CRITERIA[role]:
            rating = ratings.get(name)
            if not rating or rating.get('rating') is None:
                errors.append(f'{role}/{name}: unassessed criterion')
                continue
            all_evidence.update(rating['evidence'])
            cited = set(rating.get('coverage', []))
            matching = {gid: g for gid, g in details[role]['goals'].items() if g['criterion'] == name}
            cited_goals = coverage(target, entry, role, [o for o in observations
                if o['interaction_id'] in rating['evidence']])['goals']
            if not cited or not cited.issubset(details[role]['goals']) or not set(matching).issubset(cited):
                errors.append(f'{role}/{name}: missing or unrelated coverage goals')
            for gid in cited & details[role]['goals'].keys():
                goal = details[role]['goals'][gid]
                if not goal['exercised'] or not cited_goals[gid]['exercised']:
                    errors.append(f'{role}/{name}: rating omits exercised sequence evidence ({gid})')
                if rating['rating'] == 4 and any(r['expectations_passed'] is False for r in goal['runs']):
                    errors.append(f'{role}/{name}: perfect rating contradicts captured behavior ({gid})')
            if not set(rating['evidence']).issubset(own):
                errors.append(f'{role}/{name}: foreign or failed probe evidence')
            if rating['reference'] not in entry.get('references', []):
                errors.append(f'{role}/{name}: reference is not in the frozen baseline')
            dimension[name] = rating['rating'] * 25
        if len(all_evidence) < 6:
            errors.append(f'{role}: fewer than six distinct substantive interactions')
        if report['verdict_confidence'] < spec.policy.minimum_verdict_confidence:
            errors.append(f'{role}: insufficient verdict confidence')
        dimensions[role] = dimension
        if len(dimension) == len(CRITERIA[role]):
            scores[role] = sum(dimension.values()) / len(dimension)
        role_complete[role] = len(errors) == error_start and role in scores
    complete = not errors and set(roles).issubset(scores)
    values = [scores[r] for r in roles if r in scores]
    return {'scores': scores if complete else {}, 'provisional_scores': scores,
            'valid_scores': {r: s for r, s in scores.items() if role_complete[r]},
            'role_complete': role_complete, 'reviewers_received': len(by_role),
            'dimensions': dimensions, 'evidence_coverage': details, 'assessment_errors': errors,
            'complete': complete, 'median': median(values) if complete else None,
            'spread': max(values) - min(values) if complete else None,
            'dimension_floor_passed': bool(dimensions) and all(
                value >= spec.policy.minimum_dimension for dims in dimensions.values() for value in dims.values())}


def calibration(spec: Spec, entries: dict, reports: dict, observations: list[dict]) -> dict:
    """Every role must detect both major and subtle defects for each assessed protocol family."""
    required = {(role, 'http' if e['protocol'] in {'http', 'https'} else e['protocol'], difficulty)
                for entry in entries.values() if not entry.get('calibration')
                for e in entry.get('endpoints', []) for role in spec.roles
                for difficulty in ('major', 'subtle')}
    detected, evidence = set(), []
    for handle, entry in entries.items():
        target = next(t for t in spec.targets if t.name == entry['target_name'])
        if not target.control:
            continue
        own = {o['interaction_id']: o for o in observations if o['target'] == handle
               and not o.get('error') and o['action']['operation'] != 'close'}
        for report in reports.get(handle, []):
            if report.get('schema_version') not in {2, 3}:
                continue
            for defect in target.control.defects:
                for finding in report['findings']:
                    if finding['category'] not in defect.categories or finding['severity'] > ('P2' if defect.difficulty == 'major' else 'P3'):
                        continue
                    matching = [own[eid] for eid in finding['evidence'] if eid in own and
                                own[eid]['role'] == report['role'] and
                                rules_match(own[eid], defect.observed, {}) is not None]
                    cited = {o['interaction_id'] for o in matching}
                    lowered = any(rating.get('rating') is not None and
                        rating['rating'] <= (2 if defect.difficulty == 'major' else 3) and
                        cited.intersection(rating['evidence']) for rating in report.get('ratings', {}).values())
                    if not lowered:
                        continue
                    for observation in matching:
                        protocol = observation['protocol']
                        family = 'http' if protocol in {'http', 'https'} else protocol
                        detected.add((report['role'], family, defect.difficulty))
                        evidence.append({'target': handle, 'role': report['role'], 'defect': defect.id,
                                         'finding': finding['id'], 'interaction_id': observation['interaction_id']})
    missing = [{'role': role, 'protocol': protocol, 'difficulty': difficulty}
               for role, protocol, difficulty in sorted(required - detected)]
    missing_roles = sorted(set(ROLES) - set(spec.roles))
    return {'passed': bool(required) and not missing and not missing_roles, 'missing': missing,
            'missing_roles': missing_roles, 'detections': evidence}
