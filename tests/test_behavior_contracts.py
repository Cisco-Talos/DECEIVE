import asyncio
import base64
import io
import json
from unittest.mock import AsyncMock

import pytest

from deceive.config import load_profile
from deceive.interaction import Interaction
from deceive.models import Deployment, Listener, Profile, ProviderConfig
from deceive.providers import ModelResult
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def make_runtime(tmp_path, *, protocol='http', dialect=None, contracts=(), programs=(), model=None,
                 files=None, stateful=False):
    profile = Profile.model_validate({'schema_version': 2, 'id': 'test-contract', 'protocol': protocol,
        'stateful': stateful, 'files': files or {}, 'contracts': list(contracts),
        'command_environment': {'dialect': dialect, 'programs': list(programs),
            'directories': ['/tmp'] if dialect == 'linux' else [r'C:\Temp']} if dialect else None})
    listener = Listener(name='test', protocol=protocol, profile='test', host='127.0.0.1', port=0,
                        provider='fake' if model else None)
    providers = {'fake': ProviderConfig(kind='openai', model='test')} if model else {}
    output = io.StringIO()
    provider = AsyncMock()
    if model:
        provider.complete.side_effect = [ModelResult(text) for text in model]
    runtime = Runtime(Deployment(data_dir=tmp_path, listeners=[listener], providers=providers),
                      profiles={'test': profile}, providers={'fake': provider} if model else {},
                      telemetry=Telemetry('test', stream=output))
    return runtime, runtime.new_session(listener, username='guest'), provider, output


def http(path, **changes):
    return Interaction(protocol='http', method='GET', path=path, **changes)


@pytest.mark.asyncio
async def test_path_captures_structured_types_and_prerequisites(tmp_path):
    contracts = [{'id': 'item', 'http': {'path': '/items/{item}', 'query': {'key': 'ok'}},
        'reply': {'body_json': {'item': '${request.path.item}', 'ready': True}},
        'checks': {'json_types': {'item': 'string', 'ready': 'boolean'}},
        'effects': {'state': {'seen': '${request.path.item}'}}}]
    rt, session, _, output = make_runtime(tmp_path, contracts=contracts)
    result = await rt.respond(session, http('/items/one', query=b'key=wrong'))
    assert result.status == 400 and session.state == {}
    result = await rt.respond(session, http('/items/one', query=b'key=ok'))
    assert json.loads(result.body) == {'item': 'one', 'ready': True}
    assert session.state['seen'] == 'one'
    assert (await rt.respond(session, http('/other'))).status == 404
    assert 'deception_instance_id' in output.getvalue()
    await rt.close()


@pytest.mark.asyncio
async def test_model_repair_fallback_effects_and_telemetry(tmp_path):
    contract = {'id': 'model', 'http': {'path': '/model'}, 'mode': 'model',
                'checks': {'text': 'correct'}, 'fallback': {'body': 'correct'},
                'effects': {'write_files': {'/tmp/proof': 'once'}}}
    rt, session, provider, output = make_runtime(tmp_path, dialect='linux', contracts=[contract],
        model=['{"body":"wrong"}', '{"body":"correct"}'])
    result = await rt.respond(session, http('/model'))
    assert result.body == b'correct' and provider.complete.await_count == 2
    assert session.virtual_files == {'/tmp/proof': b'once'}
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    responses = [r for r in rows if r['message'] in ('LLM response', 'Deception response')]
    assert [r['response_stage'] for r in responses] == ['attempt', 'final']
    assert len(session.history) == 2
    await rt.close()
    rt, session, provider, output = make_runtime(tmp_path, dialect='linux', contracts=[contract],
        model=['not json', 'also invalid'])
    result = await rt.respond(session, http('/model'))
    assert result.origin == 'deterministic' and result.body == b'correct'
    assert len(session.virtual_files) == 1
    await rt.close()


@pytest.mark.asyncio
async def test_exhausted_model_no_effects_and_transactional_limit(tmp_path):
    contract = {'id': 'model', 'http': {'path': '/model'}, 'mode': 'model',
                'checks': {'text': 'correct'}, 'effects': {'state': {'bad': 'no'}}}
    rt, session, provider, _ = make_runtime(tmp_path, contracts=[contract], model=['bad', 'bad'])
    assert (await rt.respond(session, http('/model'))).status == 503
    assert not session.state
    await rt.close()
    contract = {'id': 'large', 'http': {'path': '/large'},
                'reply': {'body': 'a' * 129}, 'effects': {'write_files': {'/tmp/no': 'no'}}}
    rt, session, _, _ = make_runtime(tmp_path, contracts=[contract], dialect='linux')
    rt.limits.output_bytes = 128
    with pytest.raises(ValueError, match='Response exceeds'):
        await rt.respond(session, http('/large'))
    assert not session.virtual_files
    await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['linux', 'cmd', 'powershell-5.1', 'powershell-7'])
async def test_command_discovery_cases_and_argument_failures(tmp_path, dialect):
    path = '/usr/bin/sample' if dialect == 'linux' else r'C:\Tools\sample.exe'
    contracts = [{'id': 'sample', 'command': {'program': 'sample', 'args': ['--name', '{name}']},
                  'reply': {'body': 'Hello ${command.name}\n', 'exit_status': 0},
                  'checks': {'contains': ['Hello']}}]
    rt, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect=dialect,
        programs=[{'name': 'sample', 'path': path, 'help': 'usage\n', 'version': '1.0\n'}], contracts=contracts)
    async def run(text):
        return await rt.respond(session, Interaction(protocol='ssh', command=text, interactive=True))
    discovery = 'which' if dialect == 'linux' else 'where' if dialect == 'cmd' else 'Get-Command'
    assert path.encode() in (await run(discovery + ' sample')).body
    assert (await run('sample --name user')).body == b'Hello user\n'
    assert (await run('sample --help')).body == b'usage\n'
    assert (await run('sample wrong')).exit_status == 1
    await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['linux', 'cmd', 'powershell-5.1', 'powershell-7'])
async def test_http_commands_fresh_process_private_files_and_exit(tmp_path, dialect):
    rt, session, _, _ = make_runtime(tmp_path, dialect=dialect, contracts=[
        {'id': 'exec', 'http': {'path': '/exec'}, 'endpoint': {'source': 'query'}}])
    from urllib.parse import urlencode
    async def run(command, target=session):
        return json.loads((await rt.respond(target, http('/exec', query=urlencode({'command': command}).encode()))).body)
    write = 'echo secret > /tmp/private' if dialect == 'linux' else (
        r'echo secret > C:\Temp\private' if dialect == 'cmd' else r'Set-Content C:\Temp\private secret')
    read = 'cat /tmp/private' if dialect == 'linux' else (
        r'type C:\Temp\private' if dialect == 'cmd' else r'Get-Content C:\Temp\private')
    assert (await run(write))['exit_status'] == 0
    assert 'secret' in (await run(read))['stdout']
    other = rt.new_session(rt.listeners['test'], username='-')
    assert (await run(read, other))['exit_status'] == 1
    change = 'cd /tmp' if dialect == 'linux' else r'cd C:\Temp'
    await run(change)
    location = 'pwd' if dialect == 'linux' else 'cd' if dialect == 'cmd' else 'Get-Location'
    assert ('guest' in (await run(location))['stdout'])
    await run('exit')
    assert not session.closed
    assert (await run('hostname'))['exit_status'] == 0
    await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect,expected', [('powershell-5.1', b'\xff\xfe'), ('powershell-7', b'h\xc3\xa9')])
async def test_powershell_redirection_encoding_and_casefold_paths(tmp_path, dialect, expected):
    rt, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect=dialect)
    await rt.respond(session, Interaction(protocol='ssh', command=r'Write-Output hé > C:\Temp\Test'))
    result = await rt.respond(session, Interaction(protocol='ssh', command=r'cmd /d /c type c:\temp\test'))
    assert result.body.startswith(expected)
    await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['powershell-5.1', 'powershell-7'])
async def test_powershell_type_alias_reads_text_while_cmd_type_preserves_bytes(tmp_path, dialect):
    rt, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect=dialect)
    data = 'café\r\nnaïve\r\n'.encode('utf-16')
    session.virtual_files[r'C:\Temp\Mixed Case.txt'] = data
    async def run(command):
        return await rt.respond(session, Interaction(protocol='ssh', command=command))
    result = await run(r'type "c:\temp\mixed case.txt"')
    assert result.body == 'café\r\nnaïve\r\n'.encode()
    assert result.stderr == b'' and result.exit_status == 0
    assert (await run(r'cmd /d /c "type C:\Temp\Missing"')).exit_status == 1
    # The cmd wrapper preserves the quoted inner path and exposes literal bytes.
    assert (await run(r'cmd /d /c type "C:\Temp\Mixed Case.txt"')).body == data
    await rt.close()


def test_ambiguous_contracts_and_invalid_fallback_fail_validation(tmp_path):
    with pytest.raises(ValueError, match='Routing conflict'):
        make_runtime(tmp_path, contracts=[{'id': 'a', 'http': {'path': '/{a}'}},
                                         {'id': 'b', 'http': {'path': '/literal'}}])
    with pytest.raises(ValueError, match='differs'):
        make_runtime(tmp_path, contracts=[{'id': 'a', 'http': {'path': '/'},
            'mode': 'model', 'checks': {'text': 'yes'}, 'fallback': {'body': 'no'}}], model=['unused'])


@pytest.mark.asyncio
async def test_timeout_cancellation_provider_error_never_retry_or_mutate(tmp_path):
    from deceive.providers import ProviderError
    contract = {'id': 'wait', 'http': {'path': '/wait'}, 'mode': 'model',
        'checks': {'text': 'ok'}, 'fallback': {'body': 'ok'},
        'effects': {'state': {'must_not_commit': 'yes'}}}
    for error in (ProviderError('unavailable'), TimeoutError(), asyncio.CancelledError()):
        rt, session, provider, _ = make_runtime(tmp_path, contracts=[contract], model=['unused'])
        provider.complete.side_effect = error
        with pytest.raises(type(error)):
            await rt.respond(session, http('/wait'))
        assert provider.complete.await_count == 1
        assert not session.state and not session.history
        await rt.close()


@pytest.mark.asyncio
async def test_powershell_native_status_survives_cmdlet_and_wrapper(tmp_path):
    rt, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect='powershell-7',
        programs=[{'name': 'fail', 'path': r'C:\Tools\fail.exe'}], contracts=[
            {'id': 'fail', 'command': {'program': 'fail'}, 'reply': {'exit_status': 9}}])
    async def run(command):
        return await rt.respond(session, Interaction('ssh', command=command, interactive=True))
    assert (await run('fail')).exit_status == 9
    assert (await run('Write-Output $?')).body == b'False\r\n'
    await run('Get-Location')
    assert (await run('Write-Output $LASTEXITCODE')).body == b'9\r\n'
    assert (await run('pwsh -NoProfile -Command "hostname"')).body.endswith(b'\r\n')
    await rt.close()


@pytest.mark.asyncio
async def test_captures_cannot_retemplate_or_inject_headers_or_reach_host(tmp_path):
    import urllib.parse
    host = tmp_path / 'host-secret'
    host.write_text('HOST-ONLY')
    contracts = [{'id': 'echo', 'http': {'path': '/echo'},
                  'reply': {'body': '${request.query.value}'}}]
    rt, session, _, _ = make_runtime(tmp_path, contracts=contracts)
    query = urllib.parse.urlencode({'value': '${session.secret}'}).encode()
    session.state['secret'] = 'DO-NOT-SUBSTITUTE'
    assert (await rt.respond(session, http('/echo', query=query))).body == b'${session.secret}'
    await rt.close()
    rt, session, _, _ = make_runtime(tmp_path, dialect='linux', contracts=[
        {'id': 'exec', 'http': {'path': '/exec'}, 'endpoint': {'source': 'query'}}])
    result = await rt.respond(session, http('/exec', query=urllib.parse.urlencode({'command': 'cat ' + str(host)}).encode()))
    assert b'HOST-ONLY' not in result.body and host.read_text() == 'HOST-ONLY'
    await rt.close()


@pytest.mark.asyncio
async def test_duplicate_json_command_is_rejected_without_mutating_state(tmp_path):
    rt, session, _, _ = make_runtime(tmp_path, dialect='linux', contracts=[
        {'id': 'exec', 'http': {'path': '/exec'}, 'endpoint': {'source': 'json'}}])
    result = await rt.respond(session, http('/exec', body=b'{"command":"hostname","command":"echo changed > /tmp/duplicate"}'))
    assert result.status == 400
    assert not session.virtual_files
    await rt.close()


@pytest.mark.asyncio
async def test_dynamic_effect_cannot_replace_reserved_identity_state(tmp_path):
    rt, session, _, _ = make_runtime(tmp_path, contracts=[
        {'id':'effect','http':{'path':'/effect'},'effects':{'state':{'${request.query.key}':'bad'}}}])
    try:
        with pytest.raises(ValueError, match='identity'):
            await rt.respond(session, http('/effect', query=b'key=hostname'))
        assert not session.state
    finally:
        await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('policy,status', [('reject',400), ('last',200)])
async def test_explicit_json_duplicate_policy_for_nested_requirements(tmp_path, policy, status):
    rt, session, _, _ = make_runtime(tmp_path, contracts=[
        {'id':'json','http':{'path':'/json','json_fields':{'nested.op':'go'},'json_duplicates':policy},
         'reply':{'body':'ok'}}])
    result = await rt.respond(session, http('/json', body=b'{"nested":{"op":"bad","op":"go"}}'))
    assert result.status == status
    await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['powershell-5.1','powershell-7'])
async def test_add_content_preserves_existing_bom_encoding(tmp_path,dialect):
    rt,session,_,_=make_runtime(tmp_path,protocol='ssh',dialect=dialect)
    async def run(command):
        return await rt.respond(session,Interaction('ssh',command=command,interactive=True))
    try:
        await run(r'Write-Output first > C:\Temp\mix')
        await run(r'Add-Content C:\Temp\mix second')
        result=await run(r'Get-Content C:\Temp\mix')
        assert result.body==b'first\r\nsecond\r\n'
    finally:
        await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['powershell-5.1','powershell-7'])
async def test_utf8_bom_reads_and_appends_without_midfile_bom(tmp_path,dialect):
    path=r'C:\Users\guest\note'
    rt,session,_,_=make_runtime(tmp_path,protocol='ssh',dialect=dialect,files={path:'\ufeffrésumé\n'})
    async def run(command):
        return await rt.respond(session,Interaction('ssh',command=command,interactive=True))
    try:
        assert (await run('Get-Content '+path)).body=='résumé\r\n'.encode()
        await run('Add-Content '+path+' café')
        assert (await run('Get-Content '+path)).body=='résumé\r\ncafé\r\n'.encode()
        assert session.virtual_files[path].count(b'\xef\xbb\xbf')==1
    finally:
        await rt.close()
