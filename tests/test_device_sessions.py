"""Whole-device behavior through actual SSH channels, without live providers."""
import asyncio
import json

import asyncssh
import pytest

from deceive.config import load_profile


@pytest.mark.asyncio
@pytest.mark.parametrize('name,system', [('linux-device',b'Linux'),('macos-device',b'Darwin'),
                                        ('freebsd-device',b'FreeBSD')])
async def test_uname_flag_sets_share_current_hostname(runtime_factory, name, system):
    profile = load_profile(name)
    runtime = await runtime_factory('ssh', profile=profile)
    async with await connect(runtime) as client:
        for flags in ['-sn', '-ns', '-s -n']:
            result = await client.run('uname ' + flags)
            assert result.exit_status == 0
            assert result.stdout == system + b' ' + profile.identity.hostname.encode() + b'\n'
        result = await client.run('hostname updated-node; uname -ns')
        assert result.stdout == system + b' updated-node\n'
        result = await client.run('uname -sz', check=False)
        assert result.exit_status != 0 and result.stderr and not result.stdout


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['linux-device','macos-device','freebsd-device'])
@pytest.mark.parametrize('operation', ['undo', 'search'])
async def test_editor_insert_undo_and_same_line_search(runtime_factory, name, operation):
    import base64
    from deceive.assessment.drivers import Drivers
    from deceive.assessment.models import ProbeAction
    runtime = await runtime_factory('ssh', profile=load_profile(name))
    address = next(iter(runtime.servers.values())).endpoints[0]
    target = {'protocol':'ssh','versions':[],'ports':{'tcp':{'host':address['port']}},
              'username':'guest','password':'','timeout':2}
    driver = Drivers()
    async def send(text):
        return await driver.execute(target, ProbeAction(operation='terminal',session='editor',
            parameters={'events':[{'send':text}]}), ('editor',))
    try:
        await send('vi /tmp/undo\r')
        await send('iSCREEN\x1b:w\r')
        if operation == 'search':
            search = await send('0/REEN\r')
            assert search['facts']['cursor']['column'] == 2
        else:
            await send('0iTEMP\x1bu:wq\r')
            result = await send('cat /tmp/undo\r')
            raw = b''.join(base64.b64decode(c['raw_base64']) for c in result['facts']['terminal'])
            assert b'SCREEN' in raw and b'TEMSCREEN' not in raw
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_monitor_delay_input_does_not_change_sort(runtime_factory):
    from deceive.assessment.drivers import Drivers
    from deceive.assessment.models import ProbeAction
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    address = next(iter(runtime.servers.values())).endpoints[0]
    target = {'protocol':'ssh','versions':[],'ports':{'tcp':{'host':address['port']}},
              'username':'guest','password':'','timeout':2}
    driver = Drivers()
    async def send(text):
        return await driver.execute(target, ProbeAction(operation='terminal',session='monitor',
            parameters={'events':[{'send':text}]}), ('monitor',))
    try:
        initial = await send('top\r')
        question = await send('s')
        assert 'delay' in question['facts']['screen'][-1].lower()
        assert initial['facts']['screen'][2:5] == question['facts']['screen'][2:5]
        changed = await send('2\r')
        assert '2' in changed['facts']['screen'][-1]
        await send('q')
        result = await send('hostname\r')
        assert any('build-node-03' in line for line in result['facts']['screen'])
    finally:
        await driver.close()


async def connect(runtime):
    endpoint = next(iter(runtime.servers.values())).endpoints[0]
    return await asyncssh.connect('127.0.0.1', port=endpoint['port'], username='guest',
                                  known_hosts=None, encoding=None)


@pytest.mark.asyncio
async def test_shell_composition(runtime_factory):
    runtime = await runtime_factory('ssh')
    async with await connect(runtime) as client:
        result = await client.run('pwd && hostname', check=False)
        assert result.stdout == b'/home/guest\nbuild-node-03\n'
        assert result.exit_status == 0


@pytest.mark.asyncio
async def test_multiple_channels_are_private(runtime_factory):
    runtime = await runtime_factory('ssh')
    async with await connect(runtime) as client:
        for _ in range(2):
            result = await client.run('hostname', check=False)
            assert result.stdout == b'build-node-03\n'
            assert result.exit_status == 0
    await asyncio.sleep(.05)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    assert len([r for r in records if r['message'] == 'Session summary']) == 1


@pytest.mark.asyncio
async def test_nested_shell_returns_to_parent(runtime_factory):
    runtime = await runtime_factory('ssh')
    async with await connect(runtime) as client:
        process = await client.create_process(term_type='xterm')
        await asyncio.wait_for(process.stdout.readuntil(b'$ '), 2)
        process.stdin.write(b'bash\n')
        await asyncio.wait_for(process.stdout.readuntil(b'$ '), 2)
        process.stdin.write(b'exit\n')
        assert await asyncio.wait_for(process.stdout.readuntil(b'$ '), 2)
        process.stdin.write(b'echo alive\n')
        assert b'alive' in await asyncio.wait_for(process.stdout.readuntil(b'$ '), 2)
        process.stdin.write(b'exit\n')
        await asyncio.wait_for(process.wait_closed(), 2)


@pytest.mark.asyncio
@pytest.mark.parametrize('profile_name,system,base', [
    ('linux-device', b'Linux', b'/home/guest'),
    ('macos-device', b'Darwin', b'/Users/guest'),
    ('freebsd-device', b'FreeBSD', b'/home/guest')])
async def test_platform_and_private_channels(runtime_factory, profile_name, system, base):
    runtime = await runtime_factory('ssh', profile=load_profile(profile_name))
    async with await connect(runtime) as client:
        result = await client.run('uname -s; pwd')
        assert result.stdout == system + b'\n' + base + b'\n'
        result = await client.run('echo secret > /tmp/private; cat /tmp/private')
        assert result.stdout == b'secret\n'
        result = await client.run('cat /tmp/private', check=False)
        assert result.exit_status == 1 and not result.stdout


@pytest.mark.asyncio
async def test_pipes_redirects_and_conditionals(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    async with await connect(runtime) as client:
        result = await client.run("echo alpha > /tmp/a; cat < /tmp/a | grep alpha | wc -c; false && echo wrong; true || echo wrong")
        assert result.stdout == b'6\n'
        result = await client.run('echo unsafe > /tmp/a &&')
        assert result.exit_status == 2


@pytest.mark.asyncio
async def test_effects_are_atomic_and_visible(runtime_factory):
    from unittest.mock import AsyncMock
    from deceive.providers import ModelResult
    from deceive.clients import ShellClient
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': 'created\n', 'exit_status': 0,
        'effects': {'write_files': {'/tmp/model-file': 'saved\n'}, 'configuration': {'hostname': 'changed-node'}}})))
    async with await connect(runtime) as client:
        shell = await ShellClient.open(client, 2)
        await shell.run('unfamiliar', 2)
        assert (await shell.run('cat /tmp/model-file', 2)).body == b'saved\n'
        assert (await shell.run('hostname', 2)).body == b'changed-node\n'
        runtime.test_provider.complete.return_value = ModelResult(json.dumps({
            'stdout':'must not appear','exit_status':0,
            'effects': {'write_files': {'/tmp/partial': 'bad', '/etc/real-config': 'forbidden'}}}))
        failed = await shell.run('unfamiliar-again', 2)
        assert b'must not appear' not in failed.body
        assert b'Session unavailable' in failed.body
    async with await connect(runtime) as client:
        assert (await client.run('cat /tmp/partial', check=False)).exit_status == 1


@pytest.mark.asyncio
async def test_fullscreen_editor_and_monitor(runtime_factory):
    import pyte
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    async with await connect(runtime) as client:
        process = await client.create_process(term_type='xterm', term_size=(80,24))
        await asyncio.wait_for(process.stdout.readuntil(b'$ '), 2)
        process.stdin.write(b'vi /tmp/note\n')
        screen = pyte.Screen(80,24)
        stream = pyte.ByteStream(screen)
        stream.feed(await asyncio.wait_for(process.stdout.readuntil(b'\x1b[?25h'),2))
        assert '/tmp/note' in '\n'.join(screen.display)
        process.stdin.write(b'ihello')
        await asyncio.sleep(.08)
        process.stdin.write(b'\x1b')
        await asyncio.sleep(.08)
        process.stdin.write(b':wq\r')
        await asyncio.wait_for(process.stdout.readuntil(b'$ '),2)
        process.stdin.write(b'cat /tmp/note\n')
        assert (await asyncio.wait_for(process.stdout.readuntil(b'$ '),2)).startswith(b'hello')
        process.stdin.write(b'top\n')
        raw = await asyncio.wait_for(process.stdout.readuntil(b'q quit | s delay'),2)
        stream.feed(raw)
        assert 'worker' in '\n'.join(screen.display)
        process.change_terminal_size(100,30)
        await asyncio.sleep(.08)
        process.stdin.write(b'q')
        await asyncio.wait_for(process.stdout.readuntil(b'$ '),2)
        process.stdin.write(b'exit\n')
        await asyncio.wait_for(process.wait_closed(),2)


@pytest.mark.asyncio
async def test_interrupt_cancels_late_effects(runtime_factory):
    from deceive.providers import ModelResult
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'), model=True)
    entered = asyncio.Event()
    async def delayed(messages):
        entered.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            await asyncio.sleep(.1)
        return ModelResult(json.dumps({'stdout':'late','exit_status':0,
                                      'effects':{'write_files':{'/tmp/late':'bad'}}}))
    runtime.test_provider.complete = delayed
    async with await connect(runtime) as client:
        process = await client.create_process(term_type='xterm')
        await asyncio.wait_for(process.stdout.readuntil(b'$ '),2)
        process.stdin.write(b'unknown\n')
        await asyncio.wait_for(entered.wait(),2)
        process.stdin.write(b'\x03')
        await asyncio.wait_for(process.stdout.readuntil(b'$ '),2)
        await asyncio.sleep(.15)
        process.stdin.write(b'cat /tmp/late\n')
        raw = await asyncio.wait_for(process.stdout.readuntil(b'$ '),2)
        assert b'No such file' in raw and b'bad' not in raw
        process.stdin.write(b'exit\n')
        await asyncio.wait_for(process.wait_closed(),2)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    inputs = [r for r in records if r['message'] == 'User input']
    finals = [r for r in records if r.get('response_stage') == 'final']
    assert all(sum(r['request_id'] == i['request_id'] for r in finals) == 1 for i in inputs)


@pytest.mark.asyncio
async def test_ios_modes_password_and_configuration(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'))
    async with await connect(runtime) as client:
        p = await client.create_process(term_type='xterm')
        async def step(command, prompt):
            p.stdin.write(command + b'\n')
            return await asyncio.wait_for(p.stdout.readuntil(prompt), 2)
        await asyncio.wait_for(p.stdout.readuntil(b'edge-router-01> '),2)
        await step(b'en',b'Password: ')
        await step(b'fixture-enable',b'edge-router-01# ')
        await step(b'conf t',b'(config)# ')
        await step(b'hostname private-edge',b'private-edge(config)# ')
        await step(b'interface GigabitEthernet0/0',b'(config-if)# ')
        await step(b'shutdown',b'(config-if)# ')
        await step(b'end',b'private-edge# ')
        assert b'administratively down' in await step(b'show interfaces',b'private-edge# ')
        await step(b'copy running-config startup-config',b'Destination filename [startup-config]? ')
        await step(b'',b'private-edge# ')
        assert b'hostname private-edge' in await step(b'show startup-config',b'private-edge# ')
        p.stdin.write(b'exit\n')
        await asyncio.wait_for(p.wait_closed(),2)


def test_terminal_fragmentation_unicode_and_paste():
    from deceive.device.terminal import Decoder, LineEditor, TerminalEvent
    decoder = Decoder()
    assert decoder.feed(b'\x1b[') == []
    assert decoder.feed(b'D') == [TerminalEvent('left')]
    assert decoder.feed('λ'.encode()[:1]) == []
    assert decoder.feed('λ'.encode()[1:]) == [TerminalEvent('text','λ')]
    events = decoder.feed(b'\x1b[200~echo one\necho two\x1b[201~')
    assert not any(e.kind == 'enter' for e in events)
    editor = LineEditor(128)
    for e in decoder.feed('λx'.encode()) + [TerminalEvent('left'), TerminalEvent('backspace')]:
        editor.handle(e)
    assert editor.text == 'x'


@pytest.mark.asyncio
@pytest.mark.parametrize('app', ['less','device-menu'])
async def test_pager_and_menu_restore_parent(runtime_factory,app):
    import pyte
    runtime = await runtime_factory('ssh',profile=load_profile('linux-device'))
    async with await connect(runtime) as client:
        p=await client.create_process(term_type='xterm')
        await asyncio.wait_for(p.stdout.readuntil(b'$ '),2)
        p.stdin.write((app + (' notes.txt' if app == 'less' else '')+'\n').encode())
        raw=await asyncio.wait_for(p.stdout.readuntil(b'\x1b[0m'),2)
        screen=pyte.Screen(80,24); stream=pyte.ByteStream(screen); stream.feed(raw)
        assert ('alpha' if app=='less' else 'Device configuration') in '\n'.join(screen.display)
        if app=='less':
            p.stdin.write(b'/gamma\r')
            await asyncio.sleep(.1)
        else:
            p.stdin.write(b'\rmenu-node\ry')
            await asyncio.sleep(.1)
        p.stdin.write(b'q')
        await asyncio.wait_for(p.stdout.readuntil(b'$ '),2)
        p.stdin.write(b'hostname\n')
        result=await asyncio.wait_for(p.stdout.readuntil(b'$ '),2)
        assert (b'menu-node' if app=='device-menu' else b'build-node-03') in result
        p.stdin.write(b'exit\n'); await asyncio.wait_for(p.wait_closed(),2)


@pytest.mark.asyncio
async def test_hidden_model_dialogue_and_recovery(runtime_factory):
    from unittest.mock import AsyncMock
    from deceive.providers import ModelResult
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'),model=True)
    runtime.test_provider.complete=AsyncMock(side_effect=[
        ModelResult(json.dumps({'stdout':'','exit_status':0,'dialogue':{'prompt':'Secret: ','echo':False}})),
        ModelResult(json.dumps({'stdout':'accepted\n','exit_status':0}))])
    async with await connect(runtime) as client:
        p=await client.create_process(term_type='xterm',term_modes={asyncssh.PTY_ECHO:1})
        await asyncio.wait_for(p.stdout.readuntil(b'$ '),2)
        p.stdin.write(b'ask-secret\n'); await asyncio.wait_for(p.stdout.readuntil(b'Secret: '),2)
        p.stdin.write(b'private-password\n')
        raw=await asyncio.wait_for(p.stdout.readuntil(b'$ '),2)
        assert b'accepted' in raw and b'private-password' not in raw
        p.stdin.write(b'exit\n'); await asyncio.wait_for(p.wait_closed(),2)


@pytest.mark.asyncio
async def test_model_rejection_leaves_same_overlay_unchanged(runtime_factory):
    from unittest.mock import AsyncMock
    from deceive.providers import ModelResult
    from deceive.interaction import Interaction
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'),model=True)
    session=runtime.new_session(next(iter(runtime.listeners.values())),username='guest')
    runtime.test_provider.complete=AsyncMock(return_value=ModelResult(json.dumps({
        'stdout':'no','exit_status':0,'effects':{
            'write_files':{'/tmp/first':'must roll back','/etc/protected':'forbidden'}}})))
    result=await runtime.respond(session,Interaction('ssh',command='unknown'))
    assert result.close and result.exit_status==1
    assert '/tmp/first' not in session.virtual_files
    assert '/etc/protected' not in session.virtual_files


def test_online_assessment_requires_explicit_configuration():
    from deceive.assessment.models import Spec
    with pytest.raises(ValueError,match='Online realism requires'):
        Spec.model_validate({'targets':[{'name':'test','profiles':['linux-device']}],
                             'require_live_model':True})


@pytest.mark.asyncio
async def test_ios_paging_and_terminal_length(runtime_factory):
    runtime=await runtime_factory('ssh',profile=load_profile('ios-device'))
    async with await connect(runtime) as client:
        p=await client.create_process(term_type='xterm',term_size=(80,5))
        async def step(command,marker):
            p.stdin.write(command+b'\r')
            return await asyncio.wait_for(p.stdout.readuntil(marker),2)
        await asyncio.wait_for(p.stdout.readuntil(b'> '),2)
        await step(b'enable',b'Password: ')
        await step(b'fixture-enable',b'# ')
        raw=await step(b'show running-config',b'--More--')
        assert b'\x1b[?1049h' not in raw and b'\r\nend\r\n' not in raw
        p.stdin.write(b'q'); await asyncio.wait_for(p.stdout.readuntil(b'# '),2)
        await step(b'terminal length 0',b'# ')
        raw=await step(b'show running-config',b'# ')
        assert b'\x1b[?1049h' not in raw and b'hostname' in raw
        p.stdin.write(b'exit\r'); await asyncio.wait_for(p.wait_closed(),2)


@pytest.mark.asyncio
async def test_pipeline_preserves_actual_model_telemetry(runtime_factory):
    from unittest.mock import AsyncMock
    from deceive.providers import ModelResult
    import base64
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'),model=True)
    raw=json.dumps({'stdout':'abc','exit_status':0})
    runtime.test_provider.complete=AsyncMock(return_value=ModelResult(raw))
    async with await connect(runtime) as client:
        result=await client.run('unfamiliar | wc -c')
        assert result.stdout==b'3\n'
    records=[json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    components=[r for r in records if r.get('response_stage')=='component']
    assert len(components)==1 and base64.b64decode(components[0]['details'])==raw.encode()
    finals=[r for r in records if r.get('response_stage')=='final']
    assert len(finals)==1 and base64.b64decode(finals[0]['ssh_stdout'])==b'3\n'


@pytest.mark.asyncio
async def test_direct_environment_effect_obeys_state_value_limit(runtime_factory):
    from deceive.interaction import Interaction
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'))
    session=runtime.new_session(next(iter(runtime.listeners.values())),username='guest')
    with pytest.raises(ValueError,match='Invalid state transition'):
        await runtime.respond(session,Interaction('ssh',command='export LARGE='+'x'*4097))
    assert 'env:LARGE' not in session.state


@pytest.mark.asyncio
async def test_cat_keeps_partial_stdout_when_an_operand_fails(runtime_factory):
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'))
    async with await connect(runtime) as client:
        result=await client.run('cat notes.txt missing README.txt',check=False)
        assert result.stdout==b'alpha\nbeta\ngamma\nDevice workspace\nUse help to discover commands.\n'
        assert b'No such file' in result.stderr and result.exit_status==1


@pytest.mark.asyncio
async def test_permission_metadata_agrees_across_views(runtime_factory):
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'))
    async with await connect(runtime) as client:
        result=await client.run('echo private > /tmp/mode; chmod 000 /tmp/mode; ls -l /tmp/mode; stat /tmp/mode; cat /tmp/mode',check=False)
        assert b'----------' in result.stdout and b'Mode: 000' in result.stdout
        assert b'Permission denied' in result.stderr and result.exit_status==1


@pytest.mark.asyncio
async def test_nested_exit_preserves_child_status(runtime_factory):
    from deceive.clients import ShellClient
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'))
    async with await connect(runtime) as client:
        shell=await ShellClient.open(client,2)
        await shell.run('bash',2)
        await shell.run('false',2)
        await shell.run('exit',2)
        assert (await shell.run('echo $?',2)).body==b'1\n'
        await shell.run('sh',2)
        await shell.run('exit 7',2)
        assert (await shell.run('echo $?',2)).body==b'7\n'
        await shell.run('exit',2)
