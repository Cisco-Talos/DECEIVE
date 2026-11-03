import json

import pytest

from deceive.assessment.models import Spec
from deceive.assessment.workspace import resolve_spec


def test_assessment_aws_directory_resolves_from_spec_without_reading_secrets(tmp_path):
    path = tmp_path / 'assessment.json'
    path.write_text(json.dumps({'targets': [{'name': 'ssh', 'profiles': ['linux-ssh']}],
                               'docker': {'aws_dir': 'private-aws'}}))
    spec = resolve_spec(path)
    assert spec.docker.aws_dir == tmp_path / 'private-aws'
    assert not spec.docker.aws_dir.exists()


def test_bedrock_credential_mounts_require_explicit_profile_source(tmp_path, monkeypatch):
    from deceive.assessment.docker import aws_credentials
    from deceive.models import ProviderConfig

    provider = ProviderConfig(kind='bedrock', model='configured-model', aws_profile='configured-profile')
    with pytest.raises(ValueError, match='aws_dir'):
        aws_credentials({'chosen': provider}, None)
    directory = tmp_path / 'aws'
    directory.mkdir()
    mounts, env = aws_credentials({'chosen': provider}, directory)
    assert mounts == [(str(directory), '/material/aws')]
    assert env == {'AWS_SHARED_CREDENTIALS_FILE': '/material/aws/credentials',
                   'AWS_CONFIG_FILE': '/material/aws/config'}
    assert provider.aws_profile == 'configured-profile'
    assert aws_credentials({}, directory) == ([], {})
    with pytest.raises(ValueError, match='directory'):
        aws_credentials({'chosen': provider}, tmp_path / 'missing')
