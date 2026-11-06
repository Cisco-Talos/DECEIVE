import base64
from pathlib import Path

import pytest

from deceive.assessment.models import CoverageGoal, EvidenceRule, Review, Spec, Target
from deceive.assessment.quality import calibration, field, rules_match, score_target, sequence
from deceive.assessment.rubric import CRITERIA
from deceive.assessment.scoring import quality_confirmed


def panel(role, handle='target-01', flaw=None, protocol='http'):
    """Fake reviews are explicit test fixtures, never native quality evidence."""
    goals, observations = [], []
    kinds = ['baseline', 'positive', 'negative', 'variation', 'repeat']
    if role in {'attacker', 'consistency'}:
        kinds.append('state')
    if role == 'consistency':
        kinds.append('isolation')
    for kind in kinds:
        criterion = CRITERIA[role][{'baseline': 0, 'repeat': 0, 'positive': 1, 'state': 1,
                                   'negative': 2, 'variation': 2, 'isolation': 2}[kind]]
        count = 2 if kind in {'positive', 'repeat', 'state', 'isolation'} else 1
        steps = []
        for index in range(count):
            case = f'{kind}-{index}'
            steps.append({'select': [{'field': 'action.parameters.case', 'equals': case}],
                          'expect': [{'field': 'facts.result', 'equals': 'ok'}]})
            observations.append({'interaction_id': f'{handle}-{role}-{case}', 'target': handle,
                'role': role, 'candidate_id': 'candidate', 'protocol': protocol, 'version': '1.1',
                'session_id': f'{role}-{index}', 'body_base64': '',
                'action': {'operation': 'request' if protocol == 'http' else 'exec',
                           'endpoint': 'service-1', 'parameters': {'case': case}},
                'facts': {'result': 'wrong' if flaw and kind == 'negative' else 'ok'}})
        goals.append({'id': f'{role}-{kind}', 'role': role, 'criterion': criterion, 'kind': kind,
                      'description': f'Exercise {kind} behavior', 'steps': steps})
    ratings = {}
    for criterion in CRITERIA[role]:
        owned = [g for g in goals if g['criterion'] == criterion]
        evidence = [o['interaction_id'] for o in observations if any(
            o['action']['parameters']['case'] == s['select'][0]['equals'] for g in owned for s in g['steps'])]
        ratings[criterion] = {'rating': 4, 'expected': 'Reference behavior', 'observed': 'Captured behavior',
                              'reference': 'fixture:baseline', 'evidence': evidence,
                              'coverage': [g['id'] for g in owned]}
    findings = []
    if flaw:
        ratings[CRITERIA[role][2]]['rating'] = 1 if flaw == 'major' else 3
        findings.append({'id': 'observed-gap', 'severity': 'P2' if flaw == 'major' else 'P3',
            'category': 'identity_or_state', 'description': 'Observed reference mismatch',
            'expected': 'ok', 'reference': 'fixture:baseline',
            'evidence': [o['interaction_id'] for o in observations if o['facts']['result'] == 'wrong']})
    review = Review.model_validate({'schema_version': 2, 'candidate_id': 'candidate', 'role': role,
        'target': handle, 'verdict_confidence': 80, 'summary': 'Fake fixture', 'ratings': ratings,
        'findings': findings}).model_dump(mode='json')
    return goals, observations, review


def fixture_target(handle='target-01', flaw=None, protocol='http'):
    coverage, observations, reviews = [], [], []
    for role in CRITERIA:
        goals, seen, report = panel(role, handle, flaw, protocol)
        coverage.extend(goals)
        observations.extend(seen)
        reviews.append(report)
    raw = {'name': handle, 'profiles': ['demo-http'], 'coverage': coverage,
           'references': ['fixture:baseline']}
    if flaw:
        raw['control'] = {'defects': [{'id': 'known-gap', 'difficulty': flaw,
            'description': 'Private known defect', 'categories': ['identity_or_state'],
            'observed': [{'field': 'facts.result', 'equals': 'wrong'}]}]}
    target = Target.model_validate(raw)
    entry = {'target_name': handle, 'calibration': bool(flaw),
             'references': ['fixture:baseline'], 'endpoints': [
                 {'id': 'service-1', 'protocol': protocol, 'versions': ['1.1']}]}
    return target, entry, observations, reviews


def scored(flaw=None):
    target, entry, observations, reviews = fixture_target(flaw=flaw)
    spec = Spec(review_rubric='evidence-v3', targets=[target])
    return score_target(target, entry, reviews, spec.roles, observations, spec)


def test_dimensions_derive_scores_and_missing_is_not_zero_or_pass():
    assert scored()['median'] == 100
    assert scored('subtle')['median'] == pytest.approx(275 / 3)
    assert scored('major')['median'] == 75
    assert not scored('major')['dimension_floor_passed']
    target, entry, observations, reviews = fixture_target()
    reviews[0]['ratings'].pop('negotiation')
    value = score_target(target, entry, reviews, list(CRITERIA), observations, Spec(review_rubric='evidence-v3', targets=[target]))
    assert value['median'] is None and value['scores'] == {} and not value['complete']
    assert 'product' in value['provisional_scores']


@pytest.mark.parametrize('change', ['no_goals', 'no_variation', 'missing_action', 'foreign_evidence',
    'foreign_reference', 'low_confidence', 'no_review', 'unassessed', 'unrelated_goal', 'failed_probe',
    'missing_version', 'missing_service', 'perfect_contradiction'])
def test_insufficient_evidence_never_becomes_a_passing_number(change):
    target, entry, observations, reviews = fixture_target()
    if change == 'no_goals':
        target.coverage = []
    elif change == 'no_variation':
        target.coverage = [g for g in target.coverage if g.kind != 'variation']
    elif change == 'missing_action':
        observations = [o for o in observations if o['action']['parameters']['case'] != 'repeat-1']
    elif change == 'foreign_evidence':
        reviews[0]['ratings']['negotiation']['evidence'][0] = observations[-1]['interaction_id']
    elif change == 'foreign_reference':
        reviews[0]['ratings']['negotiation']['reference'] = 'invented reference'
    elif change == 'low_confidence':
        reviews[0]['verdict_confidence'] = 59
    elif change == 'no_review':
        reviews.pop()
    elif change == 'unassessed':
        reviews[0]['ratings']['negotiation']['rating'] = None
    elif change == 'unrelated_goal':
        reviews[0]['ratings']['negotiation']['coverage'] = ['product-positive']
    elif change == 'failed_probe':
        observations[0]['error'] = 'timeout'
    elif change == 'missing_version':
        entry['endpoints'][0]['versions'].append('3')
    elif change == 'missing_service':
        entry['endpoints'].append({'id': 'service-2', 'protocol': 'http', 'versions': ['1.1']})
    elif change == 'perfect_contradiction':
        observations[0]['facts']['result'] = 'wrong'
    result = score_target(target, entry, reviews, list(CRITERIA), observations, Spec(review_rubric='evidence-v3', targets=[target]))
    assert not result['complete'] and result['median'] is None and result['assessment_errors']


@pytest.mark.parametrize('protocol', ['http', 'ssh', 'custom-datagram'])
def test_calibration_is_protocol_agnostic_and_requires_every_role_and_both_difficulties(protocol):
    data = [fixture_target('ordinary', protocol=protocol),
            fixture_target('major-control', 'major', protocol),
            fixture_target('subtle-control', 'subtle', protocol)]
    spec = Spec(review_rubric='evidence-v3', targets=[row[0] for row in data])
    entries = {row[0].name: row[1] for row in data}
    reports = {row[0].name: row[3] for row in data}
    observations = [o for row in data for o in row[2]]
    assert calibration(spec, entries, reports, observations)['passed']
    reports['subtle-control'][0]['findings'] = []
    missing = calibration(spec, entries, reports, observations)
    assert not missing['passed'] and missing['missing'] == [
        {'role': 'protocol', 'protocol': protocol, 'difficulty': 'subtle'}]


def test_perfect_or_bare_assertion_reports_cannot_pass_controls():
    data = [fixture_target('ordinary'), fixture_target('major-control', 'major'),
            fixture_target('subtle-control', 'subtle')]
    spec = Spec(review_rubric='evidence-v3', targets=[row[0] for row in data])
    entries, reports = {r[0].name: r[1] for r in data}, {r[0].name: r[3] for r in data}
    observations = [o for row in data for o in row[2]]
    assert not calibration(Spec(review_rubric='evidence-v3', targets=[data[0][0]]), {'ordinary': data[0][1]},
                           {'ordinary': data[0][3]}, data[0][2])['passed']
    for report in reports['major-control']:
        for rating in report['ratings'].values():
            rating['rating'] = 4
    assert not calibration(spec, entries, reports, observations)['passed']


def test_reducing_roles_cannot_bypass_required_independent_panel():
    data = [fixture_target('ordinary'), fixture_target('major-control', 'major'),
            fixture_target('subtle-control', 'subtle')]
    spec = Spec(review_rubric='evidence-v3', targets=[row[0] for row in data], roles=['product'])
    result = calibration(spec, {r[0].name: r[1] for r in data}, {r[0].name: r[3] for r in data},
                         [o for row in data for o in row[2]])
    assert not result['passed'] and result['missing_roles'] == ['attacker', 'consistency', 'protocol']


def test_evidence_sequences_link_inputs_and_effects_without_reusing_interactions():
    goal = CoverageGoal.model_validate({'id': 'followup', 'role': 'attacker',
        'criterion': 'followup_effects', 'kind': 'state', 'description': 'Write then read',
        'same_session': True, 'steps': [
            {'select': [{'field': 'action.parameters.operation', 'equals': 'write'},
                        {'field': 'action.parameters.marker', 'capture': 'marker'}]},
            {'select': [{'field': 'action.parameters.operation', 'equals': 'read'}],
             'expect': [{'field': 'body_text', 'equals_capture': 'marker'}]}]})
    def observation(op, marker='', session='a'):
        return {'interaction_id': op, 'session_id': session, 'action': {
            'parameters': {'operation': op, 'marker': marker}},
            'body_base64': base64.b64encode(marker.encode()).decode()}
    good = [observation('write', 'unique'), observation('read', 'unique')]
    assert sequence(goal, good)['expectations_passed']
    assert not sequence(goal, good[:1])['exercised']
    assert not sequence(goal, [good[0], observation('read', 'unique', 'b')])['exercised']
    failed = sequence(goal, [good[0], observation('read', 'different')])
    assert failed['exercised'] and failed['expectations_passed'] is False
    goal.same_session, goal.different_sessions = False, True
    assert not sequence(goal, good)['exercised']
    assert sequence(goal, [good[0], observation('read', 'unique', 'b')])['exercised']


def isolation_fixture():
    goal = CoverageGoal.model_validate({'id': 'private-record', 'role': 'consistency',
        'criterion': 'isolation_repeatability', 'kind': 'isolation',
        'description': 'Publish in one client; a clean independent reader cannot see it',
        'different_sessions': True, 'steps': [
            {'select': [{'field': 'action.operation', 'equals': 'publish'},
                        {'field': 'action.parameters.key', 'capture': 'record'}]},
            {'select': [{'field': 'action.operation', 'equals': 'read'},
                        {'field': 'action.parameters.key', 'equals_capture': 'record'}],
             'expect': [{'field': 'facts.visible', 'equals': False}]}]})
    def event(name, client, operation, key='same-name', visible=False):
        return {'interaction_id': name, 'session_id': client, 'action': {
            'operation': operation, 'parameters': {'key': key}}, 'facts': {'visible': visible}}
    return goal, event


def test_isolation_does_not_mistake_recipient_own_write_for_a_leak():
    goal, event = isolation_fixture()
    observations = [event('owner-write', 'a', 'publish'),
                    event('other-write', 'b', 'publish'),
                    event('own-read', 'b', 'read', visible=True),
                    event('clean-read', 'c', 'read')]
    result = sequence(goal, observations)
    assert result['expectations_passed']
    assert result['evidence'] == ['owner-write', 'clean-read']
    # An already-used reader cannot prove isolation if no clean recipient exists.
    assert not sequence(goal, observations[:-1])['exercised']


def test_isolation_checks_recipient_prior_writes_and_resource_scope():
    goal, event = isolation_fixture()
    observations = [event('prior-write', 'b', 'publish'),
                    event('owner-write', 'a', 'publish'),
                    event('own-read', 'b', 'read', visible=True),
                    event('clean-read', 'c', 'read')]
    assert sequence(goal, observations)['evidence'] == ['prior-write', 'clean-read']
    # A write to another key does not explain a leak of the tested record.
    observations = [event('owner-write', 'a', 'publish'),
                    event('unrelated-write', 'b', 'publish', key='other'),
                    event('leak', 'b', 'read', visible=True),
                    event('later-good', 'c', 'read')]
    result = sequence(goal, observations)
    assert result['exercised'] and not result['expectations_passed']
    assert result['evidence'] == ['owner-write', 'leak']


def test_rules_parse_binary_and_structured_data_without_execution():
    observation = {'body_base64': base64.b64encode(b'{"ready":true}').decode(),
                   'action': {'parameters': {'body': '{"command":"echo test"}'}}}
    assert field(observation, 'body_json.ready') is True
    assert field(observation, 'request_json.command') == 'echo test'
    assert rules_match(observation, [EvidenceRule(field='body_json.ready', equals=1)], {}) is None
    observation['body_base64'] = '/w=='
    assert rules_match(observation, [EvidenceRule(field='body_text', contains='x')], {}) is None
    with pytest.raises(ValueError):
        EvidenceRule(field='body_text', pattern='[')


def test_structural_absence_distinguishes_missing_null_and_malformed_json():
    missing = EvidenceRule.model_validate({'field': 'request_json.command', 'exists': False})
    parsed = EvidenceRule.model_validate({'field': 'request_json', 'exists': True})
    missing = EvidenceRule.model_validate(missing.model_dump(mode='json'))
    assert rules_match({'action': {'parameters': {'body': '{"unrelated":"marker"}'}}},
                       [parsed, missing], {}) is not None
    assert rules_match({'action': {'parameters': {'body': '{"command":null}'}}},
                       [parsed, missing], {}) is None
    assert rules_match({'action': {'parameters': {'body': '{broken'}}},
                       [parsed, missing], {}) is None


def test_frozen_rule_roundtrip_preserves_omitted_equals_and_explicit_null():
    rule = EvidenceRule(field='body_text', contains='ready')
    frozen = EvidenceRule.model_validate(rule.model_dump(mode='json'))
    observed = {'body_base64': base64.b64encode(b'ready\n').decode()}
    assert rules_match(observed, [rule], {}) is not None
    assert rules_match(observed, [frozen], {}) is not None
    null = EvidenceRule(field='facts.absent', equals=None)
    frozen_null = EvidenceRule.model_validate(null.model_dump(mode='json'))
    assert rules_match({'facts': {'absent': None}}, [frozen_null], {}) is not None
    assert rules_match({'facts': {'absent': 'present'}}, [frozen_null], {}) is None
    with pytest.raises(ValueError, match='assertion'):
        EvidenceRule.model_validate({'field': 'body_text', 'contains': None, 'capture': None})


def test_valid_cited_sequence_is_not_replaced_by_an_earlier_equivalent_probe():
    target, entry, observations, reviews = fixture_target()
    earlier = observations[0] | {'interaction_id': 'earlier-uncited-baseline'}
    observations.insert(0, earlier)
    spec = Spec(review_rubric='evidence-v3', targets=[target])
    assert score_target(target, entry, reviews, spec.roles, observations, spec)['complete']
    # An uncited observed contradiction still invalidates a perfect rating.
    observations[0] = earlier | {'facts': {'result': 'wrong'}}
    assert not score_target(target, entry, reviews, spec.roles, observations, spec)['complete']


def test_owned_repeat_evidence_can_support_more_than_one_criterion():
    target, entry, observations, reviews = fixture_target()
    review = next(r for r in reviews if r['role'] == 'consistency')
    rating = review['ratings']['isolation_repeatability']
    rating['coverage'].append('consistency-repeat')
    rating['evidence'].extend(review['ratings']['baseline_identity']['evidence'])
    spec = Spec(review_rubric='evidence-v3', targets=[target])
    assert score_target(target, entry, reviews, spec.roles, observations, spec)['complete']


def test_example_goals_cover_distinct_jobs_and_order_independent_baseline():
    from deceive.assessment.workspace import resolve_spec
    import json

    spec = resolve_spec(Path(__file__).parents[1] / 'examples/assessment-quality.yaml')
    frozen = Spec.model_validate(spec.model_dump(mode='json'))
    def observation(path, body):
        return {'interaction_id': path, 'action': {'operation': 'request', 'parameters': {'path': path}},
                'facts': {'status': 200}, 'body_base64': base64.b64encode(body.encode()).decode()}
    for role in CRITERIA:
        positive = next(g for g in frozen.targets[0].coverage if g.id == role + '-positive')
        jobs = [observation('/api/demo/jobs/' + name, json.dumps({'id': name, 'status': 'queued'}))
                for name in ('build-one', 'build_two')]
        assert sequence(positive, jobs)['expectations_passed']
        assert not sequence(positive, [jobs[0], jobs[0] | {'interaction_id': 'duplicate'}])['exercised']
        baseline = next(g for g in frozen.targets[0].coverage if g.id == role + '-baseline')
        seen = [observation('/', 'Workbench 1.0'), observation('/api/demo/status', '{"version":"1.0"}')]
        assert sequence(baseline, seen)['expectations_passed']
        assert sequence(baseline, list(reversed(seen)))['expectations_passed']


def test_legacy_reports_can_never_confirm_quality():
    policy = Spec(review_rubric='evidence-v3', targets=[{'name': 'web', 'profiles': ['demo-http']}]).policy
    old = {'qualified': True, 'candidate_id': 'same', 'comparison_id': 'same'}
    assert not quality_confirmed([old, old], policy)
    assert not quality_confirmed([old | {'assessment_status': 'assessed'}] * 2, policy)
    assert quality_confirmed([old | {'assessment_status': 'assessed',
                                   'review_rubric': 'research-v4'}] * 2, policy)


def test_v3_review_has_no_prefilled_scalar_or_silent_gap_score():
    _, _, review = panel('product')
    with pytest.raises(ValueError, match='not synthetic confidence'):
        Review.model_validate(review | {'synthetic_confidence': 10})
    review['ratings']['identity_version']['rating'] = 3
    with pytest.raises(ValueError, match='finding'):
        Review.model_validate(review)
    review['ratings']['identity_version']['rating'] = None
    assert Review.model_validate(review).ratings['identity_version'].rating is None


def test_one_incomplete_reviewer_keeps_other_valid_scores_without_a_panel_median():
    target,entry,observations,reviews=fixture_target()
    reviews[0]['ratings']['wire_fidelity']['rating']=None
    spec=Spec(review_rubric='evidence-v3',targets=[target])
    result=score_target(target,entry,reviews,spec.roles,observations,spec)
    assert not result['complete'] and result['median'] is None
    assert set(result['valid_scores'])=={'product','attacker','consistency'}
    assert result['reviewers_received']==4 and not result['role_complete']['protocol']
