"""Research provenance gates use synthetic fixtures, never live model judgments."""
import copy

import pytest

from deceive.assessment.models import Review, Spec
from deceive.assessment.research import Dossier, comparison_errors
from test_assessment_quality import fixture_target


def dossier():
    return {'schema_version': 1, 'profile_id': 'demo-http', 'version': '1',
        'subject': 'Fictional portal; protocol plausibility only', 'kind': 'fictional',
        'sources': [{'id': 'http', 'kind': 'standard', 'url': 'https://example.org/rfc',
                     'title': 'Fixture standard', 'retrieved': '2026-11-04',
                     'facts': ['HEAD preserves representation metadata without response content.']},
                    {'id': 'design', 'kind': 'design', 'title': 'Authored fixture',
                     'retrieved': '2026-11-04', 'facts': ['Portal status is ready.']}],
        'criteria': [{'id': 'wire', 'roles': ['protocol'], 'sources': ['http'],
                      'expectation': 'Compare HEAD and GET bytes, lengths and completion.',
                      'comparisons': ['Ordinary binary GET, HEAD and a nearby error path.']}],
        'unknowns': ['No genuine server captures.'], 'search_notes': ['No CVE claim.']}


def report():
    _, _, _, reviews = fixture_target()
    r = copy.deepcopy(reviews[0])
    r.update(schema_version=3, confidence_reason='Independent documentation supports this bounded scope; no reference captures.')
    for rating in r['ratings'].values():
        rating.update(rating=3, comparison={'source_ids': ['http'],
            'criterion_ids': ['wire'],
            'rationale': 'Observed representation and challenge behavior follows the documented semantics, with limited comparative depth.',
            'limitations': 'No genuine counterpart captures; assessment is limited to sampled protocol semantics.'})
    return r


def test_research_requires_valid_independent_provenance_and_unique_ids():
    assert Dossier.model_validate(dossier()).kind == 'fictional'
    for change in ('missing_source', 'duplicate', 'no_url'):
        d = dossier()
        if change == 'missing_source':
            d['criteria'][0]['sources'] = ['absent']
        elif change == 'duplicate':
            d['sources'].append(d['sources'][0])
        else:
            d['sources'][0].pop('url')
        with pytest.raises(ValueError):
            Dossier.model_validate(d)


def test_research_review_cannot_reuse_a_contract_as_its_only_comparator():
    r = Review.model_validate(report())
    d = Dossier.model_validate(dossier())
    assert not comparison_errors(d, r.model_dump(mode='json'))
    r.ratings['negotiation'].comparison.source_ids = ['design']
    assert any('independent' in e for e in comparison_errors(d, r.model_dump(mode='json')))


def test_research_review_requires_individual_reasons_and_allows_limited_depth_without_inventing_defect():
    r = report()
    assert Review.model_validate(r).ratings['negotiation'].rating == 3
    r.pop('confidence_reason')
    with pytest.raises(ValueError, match='confidence'):
        Review.model_validate(r)
    r = report()
    r['ratings']['negotiation'].pop('comparison')
    with pytest.raises(ValueError, match='comparison'):
        Review.model_validate(r)
    r = report()
    r['ratings']['negotiation']['rating'] = 2
    with pytest.raises(ValueError, match='finding'):
        Review.model_validate(r)


def test_unknown_sources_roles_and_dossier_missing_never_qualify():
    r = report()
    d = Dossier.model_validate(dossier())
    r['ratings']['negotiation']['comparison']['source_ids'] = ['unknown']
    assert comparison_errors(d, r)
    r = report()
    d.criteria[0].roles = ['product']
    assert comparison_errors(d, r)
    assert comparison_errors(None, r)


def test_research_contents_are_frozen_in_the_assessment_spec():
    spec = Spec.model_validate({'review_rubric': 'research-v4', 'targets': [
        {'name': 'portal', 'profiles': ['demo-http'], 'research': dossier()}]})
    restored = Spec.model_validate(spec.model_dump(mode='json'))
    assert restored.targets[0].research.sources[0].facts == dossier()['sources'][0]['facts']


def test_every_bundled_profile_has_a_portable_typed_dossier():
    from importlib.resources import files
    import yaml
    root = files('deceive')
    for profile in root.joinpath('profiles').iterdir():
        if profile.name.endswith('.yaml'):
            researched = Dossier.model_validate(yaml.safe_load(
                root.joinpath('research', profile.name).read_text()))
            assert researched.profile_id == profile.name.removesuffix('.yaml')
            assert any(s.kind != 'design' for s in researched.sources)


def test_research_example_selects_declared_http_methods():
    import base64
    import json
    from pathlib import Path
    from deceive.assessment.quality import sequence
    from deceive.assessment.workspace import resolve_spec
    spec = resolve_spec(Path(__file__).parents[1] / 'examples/assessment-research.yaml')
    goal = next(g for g in spec.targets[0].coverage if g.id == 'protocol-positive')
    def observation(name, method):
        return {'interaction_id': name, 'action': {'operation': 'request',
            'parameters': {'method': method, 'path': '/api/demo/jobs/' + name}},
            'facts': {'status': 200}, 'body_base64': base64.b64encode(
                json.dumps({'id': name, 'status': 'queued'}).encode()).decode()}
    assert not sequence(goal, [observation('one', 'POST'), observation('two', 'POST')])['exercised']
    assert sequence(goal, [observation('one', 'GET'), observation('two', 'GET')])['expectations_passed']
