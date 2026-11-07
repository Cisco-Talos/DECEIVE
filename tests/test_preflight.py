"""Live-check orchestration uses only injected providers in ordinary pytest."""
import asyncio
import io
import json

import pytest
import yaml

from deceive.cli import main
from deceive.models import Deployment, Listener, ProviderConfig
from deceive.preflight import PreflightError
from deceive.providers import ModelResult, ProviderError
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def configuration(tmp_path, providers, selected):
    return Deployment(data_dir=tmp_path / 'runtime', providers=providers,
        listeners=[Listener(name=f'ssh-{i}', protocol='ssh', profile='linux-device',
                            host='127.0.0.1', port=0, provider=name)
                   for i, name in enumerate(selected)])


def runtime(config, providers=None):
    return Runtime(config, providers=providers, telemetry=Telemetry('preflight', stream=io.StringIO()))


class FakeProvider:
    def __init__(self, result='ready', delay=0):
        self.result, self.delay = result, delay
        self.calls = []
        self.closed = False

    async def complete(self, messages):
        self.calls.append(messages)
        await asyncio.sleep(self.delay)
        if isinstance(self.result, Exception):
            raise self.result
        return ModelResult(self.result)

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_preflight_deduplicates_effective_configs_and_ignores_unused_secrets(tmp_path, monkeypatch):
    common = ProviderConfig(kind='ollama', model='same-model')
    config = configuration(tmp_path, {'a': common, 'b': common.model_copy(),
        'other-model': common.model_copy(update={'model':'other'}),
        'unused': ProviderConfig(kind='openai', model='unused', api_key_env='ABSENT_SECRET')},
        ['a', 'b', 'other-model'])
    created = []
    def factory(*args):
        provider = FakeProvider()
        created.append(provider)
        return provider
    monkeypatch.setattr('deceive.runtime.SDKProvider', factory)
    rt = runtime(config)
    try:
        report = await rt.preflight()
        assert report['verification'] == 'live-verified'
        assert len(report['checks']) == 2
        assert report['checks'][0]['providers'] == ['a', 'b']
        assert len(created) == 2 and all(len(p.calls) == 1 for p in created)
        assert not rt.servers and not config.data_dir.exists()
        assert all(m.role in {'system', 'user'} for p in created for m in p.calls[0])
    finally:
        await rt.close()
    assert all(p.closed for p in created)


@pytest.mark.asyncio
async def test_literal_credentials_are_checked_separately_without_exposing_them(tmp_path):
    config = configuration(tmp_path, {name: ProviderConfig(kind='openai', model='same-model', api_key=key)
        for name, key in [('a', 'first-secret'), ('b', 'second-secret')]}, ['a', 'b'])
    providers = {'a': FakeProvider(), 'b': FakeProvider()}
    rt = runtime(config, providers)
    try:
        report = await rt.preflight()
        assert len(report['checks']) == 2
        assert all(len(provider.calls) == 1 for provider in providers.values())
        assert 'first-secret' not in json.dumps(report) and 'second-secret' not in json.dumps(report)
    finally:
        await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('reply', ['', '   ', 'x'*129, ProviderError('private-key secret response')])
async def test_unusable_or_failed_provider_blocks_listeners_and_sanitizes_failure(tmp_path, reply):
    config = configuration(tmp_path, {'model': ProviderConfig(kind='ollama', model='test')}, ['model'])
    config.limits.output_bytes = 128
    provider = FakeProvider(reply)
    rt = runtime(config, {'model':provider})
    with pytest.raises(PreflightError) as failure:
        await rt.start(preflight=True)
    assert not rt.ready and not rt.servers and rt.closed and provider.closed
    report = json.dumps(failure.value.report)
    assert 'private-key' not in report and 'secret response' not in report
    assert failure.value.report['verification'] == 'failed'
    assert not (config.data_dir / 'status.json').exists()


@pytest.mark.asyncio
async def test_timeout_is_bounded_and_provider_is_closed(tmp_path):
    config = configuration(tmp_path, {'model': ProviderConfig(kind='ollama',model='test')}, ['model'])
    config.limits.llm_seconds = .01
    provider = FakeProvider(delay=1)
    rt = runtime(config, {'model':provider})
    with pytest.raises(PreflightError) as failure:
        await rt.start(preflight=True)
    assert failure.value.report['checks'][0]['error']['type'] == 'TimeoutError'
    assert provider.closed and not rt.servers


@pytest.mark.asyncio
async def test_model_free_preflight_does_not_initialize_sdk(tmp_path, monkeypatch):
    def forbidden(*args):
        pytest.fail('No selected provider should initialize')
    monkeypatch.setattr('deceive.runtime.SDKProvider', forbidden)
    rt = runtime(configuration(tmp_path, {}, [None]))
    try:
        report = await rt.preflight()
        assert report == {'mode':'live','verification':'not-required','passed':True,'checks':[]}
    finally:
        await rt.close()


@pytest.mark.asyncio
async def test_provider_check_happens_before_socket_start_and_success_starts_listener(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()
    class Controlled(FakeProvider):
        async def complete(self, messages):
            entered.set()
            await release.wait()
            return await super().complete(messages)
    config = configuration(tmp_path, {'model':ProviderConfig(kind='ollama',model='test')}, ['model'])
    provider = Controlled()
    rt = runtime(config, {'model':provider})
    work = asyncio.create_task(rt.start(preflight=True))
    try:
        await asyncio.wait_for(entered.wait(),1)
        assert not rt.servers and not rt.ready
        release.set()
        await asyncio.wait_for(work,2)
        assert rt.ready and rt.servers and len(provider.calls) == 1
    finally:
        release.set()
        await asyncio.gather(work, return_exceptions=True)
        await rt.close()


def test_default_live_failure_json_is_sanitized_and_offline_never_initializes(tmp_path, monkeypatch, capsys):
    def failing(*args):
        raise ValueError('private-key raw SDK message')
    monkeypatch.setattr('deceive.runtime.SDKProvider', failing)
    config = configuration(tmp_path, {'model':ProviderConfig(kind='ollama',model='test')}, ['model'])
    path = tmp_path / 'deployment.yaml'
    path.write_text(yaml.safe_dump(config.model_dump(mode='json')))
    assert main(['config','validate','--config',str(path),'--json']) == 2
    raw = capsys.readouterr().out
    result = json.loads(raw)
    assert result['error']['code'] == 'provider_preflight_failed'
    assert result['data']['validation']['verification'] == 'failed'
    assert 'private-key' not in raw and 'raw SDK' not in raw
    assert not config.data_dir.exists()
    assert main(['config','validate','--config',str(path),'--offline','--json']) == 0
    assert json.loads(capsys.readouterr().out)['data']['validation']['verification'] == 'offline-valid'


@pytest.mark.asyncio
async def test_actual_cli_sdk_roundtrip_against_local_mock(tmp_path):
    pytest.importorskip('openai')
    import runpy
    from pathlib import Path
    program = Path(__file__).resolve().parents[1] / 'scripts/check_provider_preflight.py'
    namespace = runpy.run_path(str(program))
    report = await namespace['exercise'](tmp_path)
    assert report['passed'] and report['live_llm_calls'] == 0
    assert report['mock_api_requests'] == 4
