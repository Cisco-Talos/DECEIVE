import json

import pytest
import yaml

from deceive.composition import resolve
from deceive.config import load_deployment, load_profile
from deceive.models import Deployment


def profile(tmp_path, **extra):
    raw = {'schema_version': 2, 'id': 'custom', 'protocol': 'http',
           'parameters': {'tenant': {'type': 'string', 'default': 'demo'},
                          'count': {'type': 'integer', 'default': 3, 'minimum': 1}},
           'identity': {'banner': 'Welcome ${tenant}'},
           'behaviors': [{'id': 'status', 'match': {'path': '/${tenant}'},
                          'reply': {'body_json': {'tenant': '${tenant}', 'count': '${count}'}}}]}
    raw.update(extra)
    path = tmp_path / 'profile.yaml'
    path.write_text(yaml.safe_dump(raw))
    return path


def test_defaults_org_override_and_types(tmp_path):
    path = profile(tmp_path)
    org = tmp_path / 'org.yaml'
    org.write_text('id: acme\nvalues: {tenant: acme, count: 8, unrelated: true}\n')
    default = load_profile(str(path))
    assert default.behaviors[0].match.path == '/demo'
    assert default.behaviors[0].reply.body_json['count'] == 3
    bound = load_profile(str(path), organization=org, parameters={'count': 9}, instance_id='first')
    assert bound.identity.banner == 'Welcome acme'
    assert bound.resolved_parameters == {'tenant': 'acme', 'count': 9}
    assert bound.parameter_origins['count'] == 'instance override'
    assert bound.instance_id == 'first'
    with pytest.raises(ValueError, match='count'):
        load_profile(str(path), parameters={'count': True})
    with pytest.raises(ValueError, match='Unknown parameter'):
        load_profile(str(path), parameters={'typo': 4})


def test_one_pass_regex_literal_escape_and_no_environment(tmp_path):
    path = profile(tmp_path, prompt='$${tenant} ${tenant}', behaviors=[
        {'id': 'pattern', 'match': {'command_regex': '${tenant}'}}])
    result = load_profile(str(path), parameters={'tenant': '${HOME}.*'})
    assert result.prompt == '${tenant} ${HOME}.*'
    assert result.behaviors[0].match.command_regex == r'\$\{HOME\}\.\*'
    path = profile(tmp_path, prompt='${unknown}')
    with pytest.raises(ValueError, match='Unresolved placeholder'):
        load_profile(str(path))


def test_instance_binding_and_readonly_resolution(tmp_path):
    path = profile(tmp_path)
    config = tmp_path / 'deploy.yaml'
    config.write_text(yaml.safe_dump({'schema_version': 2, 'listeners': [
        {'name': 'a', 'protocol': 'http', 'port': 8081, 'profile':
         {'profile': path.name, 'id': 'one', 'parameters': {'tenant': 'first'}}},
        {'name': 'b', 'protocol': 'http', 'port': 8082, 'profile':
         {'profile': path.name, 'id': 'two', 'parameters': {'tenant': 'second'}}}]}))
    plan = resolve(load_deployment(config))
    assert plan.profiles['a'].instance_id == 'one'
    assert plan.profiles['b'].behaviors[0].match.path == '/second'
    assert not (tmp_path / '.deceive').exists()


def test_defaults_required_and_v1_unchanged(tmp_path):
    with pytest.raises(ValueError):
        load_profile(str(profile(tmp_path, parameters={'x': {'type': 'string'}})))
    assert load_profile('demo-http').schema_version == 1


def test_inherited_values_and_base_constraint_validation(tmp_path):
    base = profile(tmp_path)
    child = tmp_path / 'child.yaml'
    child.write_text(yaml.safe_dump({'schema_version': 2, 'id': 'child',
        'requirements': {'protocol': 'http', 'base_profile': base.name, 'base_version': '1'},
        'behaviors': [{'id': 'child', 'match': {'path': '/extra/${tenant}'}, 'reply': {'body': 'ok'}}]}))
    plan = resolve(Deployment(deceptions=[{'profile': str(child), 'parameters': {'tenant': 'bound'}}]))
    effective = next(iter(plan.profiles.values()))
    assert effective.identity.banner == 'Welcome bound'
    assert {b.match.path for b in effective.behaviors} == {'/bound', '/extra/bound'}


def test_parameter_content_cannot_become_a_runtime_template(tmp_path):
    from deceive.binding import render
    path = profile(tmp_path, prompt='${tenant}')
    bound = load_profile(str(path), parameters={'tenant': '${request.path.secret}'})
    assert render(bound.prompt, {'request.path.secret': 'wrong'}, runtime=True) == '${request.path.secret}'
