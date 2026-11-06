import io
import json
import pytest
import yaml
from deceive.interaction import Interaction
from deceive.models import Deployment
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def selection_paths(tmp_path, protocol='http', versions=None):
    versions = versions or ['1.1']
    base = tmp_path / 'base.yaml'
    base.write_text(yaml.safe_dump({'schema_version': 2, 'id': 'base', 'protocol': 'http', 'http_versions': versions,
        'stateful': True, 'command_environment': {'dialect': 'linux', 'directories': ['/tmp']}}))
    def child(name, contracts, programs):
        path = tmp_path / (name + '.yaml')
        path.write_text(yaml.safe_dump({'schema_version': 2, 'id': name,
            'requirements': {'protocol': protocol, 'http_versions': versions, 'base_profile': base.name, 'base_version': '1'},
            'command_environment': {'programs': programs}, 'contracts': contracts}))
        return str(path)
    a = child('first', [
        {'id':'ready','http':{'path':'/ready'},'reply':{'body':'ok'},'effects':{'state':{'ready':'yes'}}},
        {'id':'read','http':{'path':'/read'},'requires':{'ready':'yes'},'reply':{'body':'${session.ready}'}},
        {'id':'alpha','command':{'program':'alpha','args':['{value}']},'requires':{'ready':'yes'},
         'reply':{'body':'${command.value}:${session.ready}'}}],
        [{'name':'alpha','path':'/usr/bin/alpha'}])
    b = child('second', [
        {'id':'exec','http':{'path':'/exec'},'endpoint':{'source':'json'}},
        {'id':'beta','command':{'program':'beta'},'reply':{'body':'beta'}}],
        [{'name':'beta','path':'/usr/bin/beta'}])
    return a, b


@pytest.mark.asyncio
async def test_distinct_programs_and_private_contract_state_share_one_listener(tmp_path):
    a, b = selection_paths(tmp_path)
    rt = Runtime(Deployment(listeners=[{'name':'web','protocol':'http','profiles':[a,b]}]),
                 telemetry=Telemetry('test',stream=io.StringIO()))
    try:
        session=rt.new_session(rt.listeners['web'])
        await rt.respond(session, Interaction('http',method='GET',path='/ready'))
        response=await rt.respond(session,Interaction('http',method='GET',path='/read'))
        assert response.body==b'yes'
        response=await rt.respond(session,Interaction('http',method='GET',path='/exec',body=b'{"command":"alpha test"}'))
        assert json.loads(response.body)['stdout']=='test:yes'
        response=await rt.respond(session,Interaction('http',method='GET',path='/exec',body=b'{"command":"beta"}'))
        assert json.loads(response.body)['stdout']=='beta'
    finally:
        await rt.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('version', ['1.1', '2', '3'])
async def test_contract_composition_over_actual_listener(tmp_path, version):
    import httpx
    from contextlib import AsyncExitStack
    from deceive.clients import h3_connect
    protocol = 'http' if version == '1.1' else 'https'
    a, b = selection_paths(tmp_path, protocol, [version])
    rt = Runtime(Deployment(data_dir=tmp_path/'data', listeners=[{'name':'web', 'protocol':protocol,
        'profiles':[a,b], 'host':'127.0.0.1', 'port':0, 'quic_port':0, 'versions':[version]}]),
        telemetry=Telemetry('test',stream=io.StringIO()))
    try:
        await rt.start()
        endpoints = rt.servers['web'].endpoints
        port = next(e['port'] for e in endpoints if e['transport'] == ('udp' if version == '3' else 'tcp'))
        async with AsyncExitStack() as stack:
            client = await stack.enter_async_context(h3_connect(port) if version == '3' else
                httpx.AsyncClient(base_url=f'{protocol}://127.0.0.1:{port}', verify=False,
                                  trust_env=False, http2=version == '2'))
            async def request(path, body=b''):
                if version == '3':
                    response = await client.request('GET', path, body)
                    assert response.version == version
                    return response.body
                response = await client.request('GET',path,content=body)
                assert response.http_version == ('HTTP/2' if version == '2' else 'HTTP/1.1')
                return response.content
            await request('/ready')
            assert await request('/read') == b'yes'
            assert json.loads(await request('/exec',b'{"command":"alpha wire"}'))['stdout'] == 'wire:yes'
            assert json.loads(await request('/exec',b'{"command":"beta"}'))['stdout'] == 'beta'
    finally:
        await rt.close()
