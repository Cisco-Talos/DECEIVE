import asyncio
import json

import asyncssh
import httpx
import pytest
import yaml

from deceive.clients import ShellClient, h3_connect
from deceive.config import load_profile
from deceive.evaluate import evaluate
from deceive.models import Profile


@pytest.mark.asyncio
@pytest.mark.parametrize('suffix', ['linux', 'cmd', 'ps51', 'ps7'])
@pytest.mark.parametrize('version', ['1.1', '2', '3'])
async def test_reference_acceptance_over_actual_protocol(tmp_path, suffix, version):
    from importlib.resources import files
    suite = yaml.safe_load(files('deceive').joinpath('acceptance', f'workbench-http-{suffix}.yaml').read_text())
    suite['http_version'] = version
    path = tmp_path / 'suite.yaml'
    path.write_text(yaml.safe_dump(suite))
    result = await evaluate('workbench-http-' + suffix, path, tmp_path / 'report')
    assert result['passed'], result


@pytest.mark.asyncio
@pytest.mark.parametrize('suffix', ['linux', 'cmd', 'ps51', 'ps7'])
async def test_real_ssh_dialect_prompts_files_and_process_exit(runtime_factory, suffix):
    raw = load_profile('workbench-http-' + suffix).model_dump(mode='json')
    raw.update(protocol='ssh', requirements=None, contracts=[c for c in raw['contracts'] if c['command']],
               ssh_response_format='json')
    profile = Profile.model_validate(raw)
    rt = await runtime_factory('ssh', profile=profile)
    port = next(iter(rt.servers.values())).endpoints[0]['port']
    async with asyncssh.connect('127.0.0.1', port=port, username='guest', known_hosts=None, encoding=None) as conn:
        shell = await ShellClient.open(conn, 3)
        assert b'Welcome to Example Industries' in shell.banner
        result = await shell.run('hostname', 3)
        assert result.body == (b'workbench-01\n' if suffix == 'linux' else b'workbench-01\r\n')
        assert b'workbench-01: ready' in (await shell.run('workbench status', 3)).body
        if suffix in ('ps51', 'ps7'):
            await shell.run(r'Write-Output first > C:\Temp\mixed', 3)
            await shell.run(r'Add-Content C:\Temp\mixed second', 3)
            assert (await shell.run(r'Get-Content C:\Temp\mixed', 3)).body == b'first\r\nsecond\r\n'
        await shell.run('exit 7', 3)


@pytest.mark.asyncio
@pytest.mark.parametrize('version', ['1.1', '2', '3'])
async def test_cookie_files_and_parallel_isolation_over_wire(runtime_factory, version):
    profile = load_profile('workbench-http-linux')
    rt = await runtime_factory('https', profile=profile, versions=[version])
    endpoints = next(iter(rt.servers.values())).endpoints
    tcp = next((e['port'] for e in endpoints if e['transport'] == 'tcp'), None)
    udp = next((e['port'] for e in endpoints if e['transport'] == 'udp'), None)
    from contextlib import AsyncExitStack
    async with AsyncExitStack() as stack:
        async def client():
            if version == '3':
                return await stack.enter_async_context(h3_connect(udp))
            return await stack.enter_async_context(httpx.AsyncClient(base_url=f'https://127.0.0.1:{tcp}',
                http2=version == '2', verify=False, trust_env=False))
        first, second = await client(), await client()
        async def run(c, text):
            body = json.dumps({'command': text}).encode()
            if version == '3':
                result = await c.request('POST', '/api/demo/command', body)
                assert result.version == '3'
                return json.loads(result.body)
            result = await c.post('/api/demo/command', content=body)
            assert result.http_version == ('HTTP/2' if version == '2' else 'HTTP/1.1')
            return result.json()
        await run(first, 'echo private > /tmp/note')
        one, two = await asyncio.gather(run(first, 'cat /tmp/note'), run(second, 'cat /tmp/note'))
        assert one['stdout'] == 'private\n' and two['exit_status'] == 1
        await run(first, 'exit')
        assert (await run(first, 'hostname'))['stdout'] == 'workbench-01\n'


@pytest.mark.asyncio
async def test_evaluation_selects_one_bound_instance_without_rewriting_suite(tmp_path):
    from deceive.config import fingerprint
    suite = {'schema_version': 1, 'id': 'bound-contract', 'cases': [{'id': 'bound', 'steps': [
        {'path': '/api/acme/status', 'expect': {'json_value': {'application': 'Workbench', 'version': '1.0',
            'organization': 'Acme', 'hostname': 'node-one', 'ready': True}}}]}]}
    suite_path = tmp_path / 'suite.yaml'
    suite_path.write_text(yaml.safe_dump(suite))
    org = tmp_path / 'org.yaml'
    org.write_text('id: acme\nvalues: {organization_name: Acme, tenant_id: acme}\n')
    deployment = tmp_path / 'deployment.yaml'
    deployment.write_text(yaml.safe_dump({'schema_version': 2, 'organization': org.name, 'listeners': [
        {'name': name, 'protocol': 'https', 'port': 0, 'versions': ['1.1'],
         'profile': {'profile': 'workbench-http-linux', 'id': name, 'parameters': {'hostname': host}}}
        for name, host in [('first', 'node-one'), ('second', 'node-two')]]}))
    with pytest.raises(ValueError, match='Instance selection'):
        await evaluate('workbench-http-linux', suite_path, tmp_path / 'ambiguous', config_path=deployment)
    report = await evaluate('workbench-http-linux', suite_path, tmp_path / 'bound', config_path=deployment, instance_id='first')
    assert report['passed'] and report['instance_id'] == 'first'
    assert report['suite_fingerprint'] == fingerprint(suite)


@pytest.mark.asyncio
@pytest.mark.parametrize('suffix', ['ps51', 'ps7'])
@pytest.mark.parametrize('version', ['1.1', '2', '3'])
async def test_powershell_encoding_followup_over_actual_http(runtime_factory, suffix, version):
    from contextlib import AsyncExitStack
    rt = await runtime_factory('https', profile=load_profile('workbench-http-'+suffix), versions=[version])
    endpoints = next(iter(rt.servers.values())).endpoints
    port = next(e['port'] for e in endpoints if e['transport'] == ('udp' if version == '3' else 'tcp'))
    async with AsyncExitStack() as stack:
        client = await stack.enter_async_context(h3_connect(port) if version == '3' else
            httpx.AsyncClient(base_url=f'https://127.0.0.1:{port}', verify=False,
                              trust_env=False, http2=version == '2'))
        async def command(text):
            body = json.dumps({'command':text}).encode()
            if version == '3':
                response = await client.request('POST','/api/demo/command',body)
                assert response.version == version
                return json.loads(response.body)
            response = await client.post('/api/demo/command',content=body)
            assert response.http_version == ('HTTP/2' if version == '2' else 'HTTP/1.1')
            return response.json()
        assert (await command(r'Write-Output first > C:\Temp\mixed'))['exit_status'] == 0
        assert (await command(r'Add-Content C:\Temp\mixed café'))['exit_status'] == 0
        assert (await command(r'Get-Content C:\Temp\mixed'))['stdout'] == 'first\r\ncafé\r\n'
        assert (await command(r'type C:\Temp\mixed'))['stdout'] == 'first\r\ncafé\r\n'


@pytest.mark.asyncio
@pytest.mark.parametrize('suffix', ['linux', 'cmd', 'ps51', 'ps7'])
@pytest.mark.parametrize('version', ['1.1', '2', '3'])
async def test_reference_read_only_head_metadata(runtime_factory, suffix, version):
    from contextlib import AsyncExitStack
    runtime = await runtime_factory('https', profile=load_profile('workbench-http-' + suffix),
                                    versions=[version])
    endpoints = next(iter(runtime.servers.values())).endpoints
    port = next(e['port'] for e in endpoints if e['transport'] == ('udp' if version == '3' else 'tcp'))
    async with AsyncExitStack() as stack:
        client = await stack.enter_async_context(h3_connect(port) if version == '3' else
            httpx.AsyncClient(base_url=f'https://127.0.0.1:{port}', verify=False,
                              trust_env=False, http2=version == '2'))
        async def request(method, path):
            response = await client.request(method, path)
            if version == '3':
                assert response.version == '3'
                return response.status, {k.decode('ascii'): v.decode('latin-1')
                                         for k, v in response.headers}, response.body
            assert response.http_version == ('HTTP/2' if version == '2' else 'HTTP/1.1')
            return response.status_code, dict(response.headers), response.content
        for path in ('/', '/api/demo/status', '/api/demo/jobs/head-probe'):
            get_status, get_headers, body = await request('GET', path)
            status, headers, head = await request('HEAD', path)
            assert status == get_status == 200
            assert head == b''
            assert headers['content-type'] == get_headers['content-type']
            assert int(headers['content-length']) == len(body)
        assert (await request('HEAD', '/api/demo/command'))[0] == 404
