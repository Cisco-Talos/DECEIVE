"""Shared operational settings and private credential sources."""
import json
from pathlib import Path

import pytest
import yaml

from deceive.config import load_deployment
from deceive.cli import deployment_from_args, parser
from deceive.composition import resolve
from deceive.providers import _secret
from deceive.credentials import literal_name, read_env_file, selected_environment
from deceive.models import ProviderConfig


def files(tmp_path):
    (tmp_path / '.env').write_text('PRIVATE_KEY=dotenv-secret\nUNRELATED=must-not-forward\n')
    (tmp_path / 'providers.local.yaml').write_text(yaml.safe_dump({
        'schema_version':1, 'env_file':'.env', 'default_provider':'primary',
        'providers':{'primary':{'kind':'openai','model':'model-a','api_key_env':'PRIVATE_KEY'},
                     'other':{'kind':'ollama','model':'model-b'}}}))
    path=tmp_path / 'deployment.yaml'
    path.write_text(yaml.safe_dump({'provider_config':'providers.local.yaml',
        'listeners':[{'name':'inherited','protocol':'ssh','profile':'linux-device','port':0},
                     {'name':'disabled','protocol':'ssh','profile':'linux-device','port':0,'provider':None},
                     {'name':'override','protocol':'ssh','profile':'linux-device','port':0,'provider':'other'}]}))
    return path


def test_shared_default_explicit_override_and_disable(tmp_path):
    config=load_deployment(files(tmp_path))
    assert [l.provider for l in config.listeners]==['primary',None,'other']
    assert config.providers['primary'].env_file==tmp_path / '.env'
    assert _secret(config.providers['primary'])=='dotenv-secret'
    assert 'dotenv-secret' not in json.dumps(config.model_dump(mode='json'))
    assert len(resolve(config).listeners)==3


def test_cli_profile_selection_can_use_shared_provider_catalog(tmp_path):
    files(tmp_path)
    catalog = tmp_path / 'providers.local.yaml'
    args = parser().parse_args(['serve', '--profile', 'sudo-2019-14287',
                                '--provider-config', str(catalog), '--port', '8022'])
    config = deployment_from_args(args)
    assert config.default_provider == 'primary'
    assert config.listeners[0].provider == 'primary'
    assert config.listeners[0].profiles == []
    assert config.listeners[0].profile == 'sudo-2019-14287'
    assert config.providers['primary'].env_file == tmp_path / '.env'
    assert _secret(config.providers['primary']) == 'dotenv-secret'
    managed = parser().parse_args(['deployment', 'start', 'sudo-retest', '--profile',
                                   'sudo-2019-14287', '--provider-config', str(catalog)])
    assert deployment_from_args(managed).listeners[0].provider == 'primary'


def test_cli_provider_catalog_and_deployment_yaml_are_unambiguous(tmp_path):
    path = files(tmp_path)
    args = parser().parse_args(['serve', '--config', str(path),
                                '--provider-config', str(tmp_path / 'providers.local.yaml')])
    with pytest.raises(ValueError, match='provider-config'):
        deployment_from_args(args)


def test_environment_takes_precedence_without_mutating_process(tmp_path,monkeypatch):
    import os
    path=files(tmp_path)
    monkeypatch.setenv('PRIVATE_KEY','process-secret')
    config=load_deployment(path)
    assert _secret(config.providers['primary'])=='process-secret'
    assert os.environ.get('UNRELATED') is None


def test_references_are_resolved_after_yaml_and_relative_to_their_owner(tmp_path):
    catalog = tmp_path / 'catalog'
    catalog.mkdir()
    (catalog / '.env').write_text('MODEL="model: with punctuation"\nTOKEN=secret\n')
    (catalog / 'providers.yaml').write_text(yaml.safe_dump({
        'env_file': '.env', 'default_provider': 'remote', 'providers': {
            'remote': {'kind': 'openai', 'model': '${env:MODEL}',
                       'api_key': '${env:TOKEN}'},
            'file': {'kind': 'openai', 'model': 'other', 'api_key_file': 'key'}}}))
    path = tmp_path / 'deployment.yaml'
    path.write_text(yaml.safe_dump({'provider_config': 'catalog/providers.yaml',
        'default_provider': None, 'deceptions': [{'profile': 'linux-device'}]}))
    config = load_deployment(path)
    assert config.providers['remote'].model == 'model: with punctuation'
    assert _secret(config.providers['remote']) == 'secret'
    assert config.providers['file'].api_key_file == catalog / 'key'
    assert config.deception_defaults.provider is None


def test_local_alias_replaces_shared_alias_and_local_env_overrides_source(tmp_path):
    path = files(tmp_path)
    (tmp_path / 'override.env').write_text('OTHER=local-key\n')
    raw = yaml.safe_load(path.read_text())
    raw.update(env_file='override.env', providers={
        'primary': {'kind': 'openai', 'model': 'replacement', 'api_key_env': 'OTHER'}})
    path.write_text(yaml.safe_dump(raw))
    config = load_deployment(path)
    assert config.providers['primary'].api_key_env == 'OTHER'
    assert _secret(config.providers['primary']) == 'local-key'
    assert config.providers['other'].env_file == tmp_path / 'override.env'


def test_dotenv_is_data_and_errors_do_not_include_values(tmp_path):
    path = tmp_path / '.env'
    path.write_text('export TOKEN="$(touch sentinel) ${OTHER} # literal"\nEMPTY=\n')
    assert read_env_file(path) == {'TOKEN': '$(touch sentinel) ${OTHER} # literal', 'EMPTY': ''}
    assert not (tmp_path / 'sentinel').exists()
    path.write_text('TOKEN="private-value\n')
    with pytest.raises(ValueError, match='line 1') as error:
        read_env_file(path)
    assert 'private-value' not in str(error.value)


def test_missing_credentials_can_be_checked_offline(tmp_path):
    path = files(tmp_path)
    (tmp_path / '.env').unlink()
    config = load_deployment(path)
    assert len(resolve(config).listeners) == 3
    with pytest.raises(ValueError, match='PRIVATE_KEY'):
        _secret(config.providers['primary'])


def test_literal_key_is_private_and_selected_secrets_are_filtered(tmp_path):
    path = files(tmp_path)
    raw = yaml.safe_load(path.read_text())
    raw['providers'] = {'literal': {'kind': 'openai', 'model': 'model', 'api_key': 'literal-secret'}}
    path.write_text(yaml.safe_dump(raw))
    config = load_deployment(path)
    provider = config.providers['literal']
    assert _secret(provider) == 'literal-secret'
    assert 'literal-secret' not in repr(provider) + json.dumps(config.model_dump(mode='json'))
    assert selected_environment(config.providers, {'literal'}) == {
        literal_name('literal'): 'literal-secret'}
    assert selected_environment(config.providers, {'primary'}) == {'PRIVATE_KEY': 'dotenv-secret'}


def test_conflicting_selected_sources_fail_without_disclosing_values(tmp_path):
    first, second = tmp_path / 'first.env', tmp_path / 'second.env'
    first.write_text('KEY=first-secret\n')
    second.write_text('KEY=second-secret\n')
    providers = {name: ProviderConfig(kind='openai', model='model', api_key_env='KEY', env_file=path)
                 for name, path in [('first', first), ('second', second)]}
    with pytest.raises(ValueError, match='Conflicting') as error:
        selected_environment(providers, {'first', 'second'})
    assert 'first-secret' not in str(error.value) and 'second-secret' not in str(error.value)


def test_named_aws_profile_does_not_forward_other_aws_keys(tmp_path, monkeypatch):
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'unrelated-key')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'unrelated-secret')
    config = ProviderConfig(kind='bedrock', model='model', aws_profile='named', region='us-east-1')
    assert selected_environment({'aws': config}, {'aws'}) == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('profile', [None, 'local-profile'])
async def test_bedrock_session_uses_selected_dotenv_source(tmp_path, monkeypatch, profile):
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from deceive.providers import SDKProvider

    for variable in ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_ACCESS_KEY_ID',
                     'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_REGION', 'AWS_DEFAULT_REGION'):
        monkeypatch.delenv(variable, raising=False)
    path = tmp_path / '.env'
    path.write_text('AWS_ACCESS_KEY_ID=test-access\nAWS_SECRET_ACCESS_KEY=test-secret\n'
                    'AWS_SESSION_TOKEN=test-session\nAWS_REGION=eu-west-1\n'
                    + (f'AWS_PROFILE={profile}\n' if profile else ''))
    session = MagicMock()
    sdk = SimpleNamespace(Session=MagicMock(return_value=session))
    monkeypatch.setitem(sys.modules, 'boto3', sdk)
    config = ProviderConfig(kind='bedrock', model='model', env_file=path)
    provider = SDKProvider(config, 1, 1)
    try:
        expected = {'profile_name': profile, 'region_name': 'eu-west-1'}
        if profile is None:
            expected.update(aws_access_key_id='test-access', aws_secret_access_key='test-secret',
                            aws_session_token='test-session')
        sdk.Session.assert_called_once_with(**expected)
    finally:
        await provider.close()


def test_assessment_can_use_same_catalog_and_explicit_target_override(tmp_path):
    from deceive.assessment.workspace import resolve_spec, target_deployment
    files(tmp_path)
    path = tmp_path / 'assessment.yaml'
    path.write_text(yaml.safe_dump({'provider_config': 'providers.local.yaml', 'targets': [
        {'name': 'default', 'profiles': ['linux-device']},
        {'name': 'disabled', 'profiles': ['linux-device'], 'provider': None}]}))
    spec = resolve_spec(path)
    assert [target.provider for target in spec.targets] == ['primary', None]
    config = target_deployment(spec, spec.targets[0])
    assert _secret(config.providers['primary']) == 'dotenv-secret'
    assert resolve(config).listeners[0].provider == 'primary'


def test_local_examples_are_excluded_from_assessment_source(tmp_path):
    from deceive.assessment.workspace import source_files
    examples = tmp_path / 'examples'
    examples.mkdir()
    (examples / 'public.yaml').write_text('{}')
    (examples / 'private.local.yaml').write_text('api_key: private-secret')
    package = tmp_path / 'deceive'
    package.mkdir()
    (package / 'private.local.yaml').write_text('api_key: private-secret')
    assert [path.name for path in source_files(tmp_path)] == ['public.yaml']


def test_assessment_serializes_literal_key_as_separate_private_material(tmp_path, monkeypatch):
    from deceive.assessment import workspace
    monkeypatch.setattr(workspace, 'checkpoint', lambda *args: {'files': {}})
    path = tmp_path / 'assessment.yaml'
    path.write_text(yaml.safe_dump({'providers': {'model': {
        'kind': 'openai', 'model': 'model', 'api_key': 'literal-private-key'}},
        'targets': [{'name': 'ssh', 'profiles': ['linux-device'], 'provider': 'model'}]}))
    run = tmp_path / 'run'
    state = workspace.prepare(path, run, tmp_path)
    assert 'literal-private-key' not in json.dumps(state) + (run / 'state.json').read_text()
    secret = Path(state['spec']['providers']['model']['api_key_file'])
    assert secret.read_text() == 'literal-private-key'
    assert secret.stat().st_mode & 0o777 == 0o600
    assert secret.parent.stat().st_mode & 0o777 == 0o700
