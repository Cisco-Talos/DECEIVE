"""Regressions derived from independent whole-device client observations."""
import asyncio
import base64
import json

import asyncssh
import pytest

from deceive.assessment.drivers import Drivers
from deceive.assessment.models import ProbeAction
from deceive.assessment.telemetry import audit
from deceive.config import load_profile


def endpoint(runtime):
    address = next(iter(runtime.servers.values())).endpoints[0]
    return {'protocol': 'ssh', 'versions': [], 'ports': {'tcp': {'host': address['port']}},
            'username': 'guest', 'password': '', 'timeout': 2}


async def terminal(driver, target, text=None, *, events=None):
    return await driver.execute(target, ProbeAction(operation='terminal', session='screen',
        parameters={'events': events if events is not None else [{'send': text}]}), ('screen',))


def raw(result):
    return b''.join(base64.b64decode(c['raw_base64']) for c in result['facts']['terminal'])


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['linux-device', 'macos-device', 'freebsd-device'])
async def test_pager_interrupt_cancels_search_without_leaving(runtime_factory, name):
    runtime = await runtime_factory('ssh', profile=load_profile(name))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        await terminal(driver, target, 'less notes.txt\r')
        await terminal(driver, target, '/missing')
        cancelled = await terminal(driver, target, '\x03')
        assert b'\x1b[?1049l' not in raw(cancelled)
        assert any('notes.txt' in line for line in cancelled['facts']['screen'])
        found = await terminal(driver, target, '/beta\r')
        assert any('/beta' in line for line in found['facts']['screen'])
        assert b'\x1b[?1049l' in raw(await terminal(driver, target, 'q'))
    finally:
        await driver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('name,cpu,memory', [('linux-device', '%Cpu(s)', 'MiB Mem'),
    ('macos-device', 'CPU usage', 'PhysMem'), ('freebsd-device', 'CPU:', 'Mem:')])
async def test_monitor_resources_and_process_removal_share_facts(runtime_factory, name, cpu, memory):
    runtime = await runtime_factory('ssh', profile=load_profile(name))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        initial = await terminal(driver, target, 'top\r')
        screen = '\n'.join(initial['facts']['screen'])
        assert cpu in screen and memory in screen and 'worker' in screen
        await terminal(driver, target, 'k240\r')
        updated = await terminal(driver, target, events=[{'resize': [100, 30]}])
        assert not any('worker' in line for line in updated['facts']['screen'])
        await terminal(driver, target, 'q')
        result = await terminal(driver, target, 'ps aux\r')
        assert b'worker' not in raw(result) and b'sshd' in raw(result) and b'%CPU' in raw(result)
        if name == 'linux-device':
            memory_view = await terminal(driver, target, 'free -m\r')
            assert b'1036' in raw(memory_view)
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_ios_interface_inventory_is_authoritative_in_commands_and_model(runtime_factory):
    from deceive.clients import ShellClient
    from deceive.providers import ModelResult
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'), model=True)
    prompts = []
    async def model(messages):
        prompts.append(messages[0].content)
        return ModelResult(json.dumps({'stdout': 'detail unavailable\n', 'exit_status': 0}))
    runtime.test_provider.complete = model
    async with await asyncssh.connect('127.0.0.1', port=endpoint(runtime)['ports']['tcp']['host'],
            username='guest', known_hosts=None, encoding=None) as client:
        shell = await ShellClient.open(client, 2, continuation_prompts=(b'Password: ',))
        await shell.run('enable', 2)
        await shell.run('fixture-enable', 2)
        for command in ['configure terminal', 'interface GigabitEthernet0/0', 'shutdown', 'end']:
            await shell.run(command, 2)
        brief = await shell.run('show ip interface brief', 2)
        assert b'GigabitEthernet0/0' in brief.body and b'administratively down' in brief.body
        assert not prompts
        interfaces = await shell.run('show interfaces', 2)
        assert b'GigabitEthernet0/0' in interfaces.body and b'administratively down' in interfaces.body
        await shell.run('show inventory', 2)
        assert 'network_interfaces' in prompts[-1] and 'GigabitEthernet0/0' in prompts[-1]
        assert 'complete' in prompts[-1] and 'administratively down' in prompts[-1]


@pytest.mark.asyncio
async def test_ios_nonzero_terminal_length_pages_and_zero_disables(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        await terminal(driver, target, 'enable\rfixture-enable\r')
        length = await terminal(driver, target, 'terminal length 3\r')
        assert b'Invalid' not in raw(length)
        page = await terminal(driver, target, 'show running-config\r')
        assert b'--More--' in raw(page)
        assert b'\x1b[?1049h' not in raw(page)
        assert b'\r\nend\r\n' not in raw(page)
        continued = await terminal(driver, target, ' ')
        assert b'end\r\nedge-router-01# ' in raw(continued)
        await terminal(driver, target, 'show running-config\r')
        await terminal(driver, target, '\x03')
        disabled = await terminal(driver, target, 'terminal length 0\rshow running-config\r')
        assert b'--More--' not in raw(disabled) and b'hostname' in raw(disabled)
    finally:
        await driver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('interaction', ['terminal', 'context-help'])
async def test_delivered_ssh_bytes_audit_across_nat(runtime_factory, interaction):
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'))
    driver = Drivers()
    target = endpoint(runtime)
    if interaction == 'terminal':
        action = ProbeAction(operation='terminal', session='audit',
            parameters={'events': [{'send': 'show version\r'}]})
    else:
        action = ProbeAction(operation='commands', session='audit', parameters={'commands': ['?']})
    try:
        result = await driver.execute(target, action, ('audit',))
        observation = result | {'interaction_id': 'observed', 'target': 'target-01', 'role': 'protocol',
                               'protocol': 'ssh', 'action': action.model_dump()}
        assert result['facts'].get('client_version')
    finally:
        await driver.close()
    await asyncio.sleep(.05)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    for record in records:
        if str(record['src_port']).isdigit():
            record['src_port'] = str(int(record['src_port']) + 1)  # Docker can translate ports.
    assert audit(records, [observation], {'ios-device'})['status'] == 'passed'
    if interaction == 'terminal':
        empty = observation | {'facts': observation['facts'] | {'terminal': []},
                               'action': action.model_dump() | {'parameters': {'events': []}}}
        assert audit(records, [observation, empty], {'ios-device'})['status'] == 'passed'
        replay = observation | {'facts': observation['facts'] | {'client_version': 'other-client'}}
        assert audit(records, [replay], {'ios-device'})['status'] == 'failed'
        assert audit(records, [observation, observation], {'ios-device'})['status'] == 'failed'


@pytest.mark.asyncio
async def test_invalid_terminal_events_do_not_open_or_consume_a_channel(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'))
    driver = Drivers()
    try:
        with pytest.raises(ValueError, match='bounds'):
            await terminal(driver, endpoint(runtime), events=[{'resize': [80, 3]}])
        assert not driver.registry['ssh'].sessions
    finally:
        await driver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['linux-device', 'macos-device', 'freebsd-device'])
async def test_long_pager_viewport_moves_with_navigation(runtime_factory, name):
    runtime = await runtime_factory('ssh', profile=load_profile(name))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        commands = '; '.join(f'echo line{i:02} {">" if i == 1 else ">>"} /tmp/pages'
                             for i in range(1, 10))
        await terminal(driver, target, commands + '; less /tmp/pages\r')
        initial = await terminal(driver, target, events=[{'resize': [40, 5]}])
        assert initial['facts']['screen'][:4] == [f'line{i:02}'.ljust(40) for i in range(1, 5)]
        moved = await terminal(driver, target, 'j')
        assert moved['facts']['screen'][:4] == [f'line{i:02}'.ljust(40) for i in range(2, 6)]
        last = await terminal(driver, target, 'G')
        assert last['facts']['screen'][:4] == [f'line{i:02}'.ljust(40) for i in range(6, 10)]
        await terminal(driver, target, 'q')
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_monitor_cpu_totals_never_decrease(runtime_factory):
    import re
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    driver = Drivers()
    target = endpoint(runtime)
    samples = []
    try:
        await terminal(driver, target, 'top\r')
        await terminal(driver, target, 's0.1\r')
        for _ in range(32):
            result = await terminal(driver, target, events=[])
            line = next(line for line in result['facts']['screen'] if line.rstrip().endswith(' worker'))
            value = re.search(r'([\d:]+\.\d+)\s+worker\s*$', line).group(1)
            parts = value.split(':')
            samples.append(float(parts[-1]) + (60 * int(parts[-2]) if len(parts) > 1 else 0))
        assert samples[-1] > samples[0]
        assert samples == sorted(samples)
        await terminal(driver, target, 'q')
    finally:
        await driver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['linux-device', 'macos-device', 'freebsd-device'])
async def test_editor_logical_lines_and_text_file_termination(runtime_factory, name):
    runtime = await runtime_factory('ssh', profile=load_profile(name))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        await terminal(driver, target, 'vi /tmp/eol\r')
        await terminal(driver, target, 'iSCREEN\x1b:wq\r')
        saved = await terminal(driver, target, 'wc -c /tmp/eol\r')
        assert b'7 /tmp/eol\r\n' in raw(saved)
        opened = await terminal(driver, target, 'vi notes.txt\r')
        assert '1/3' in opened['facts']['screen'][-1]
        await terminal(driver, target, ':w\r:wq\r')
        unchanged = await terminal(driver, target, 'wc -c notes.txt\r')
        assert b'17 notes.txt\r\n' in raw(unchanged)
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_editor_interrupt_preserves_unsaved_buffer(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        await terminal(driver, target, 'vi /tmp/draft\r')
        await terminal(driver, target, 'iDRAFT')
        interrupted = await terminal(driver, target, '\x03')
        assert b'\x1b[?1049l' not in raw(interrupted)
        warning = await terminal(driver, target, ':q\r')
        assert any('No write since last change' in line for line in warning['facts']['screen'])
        await terminal(driver, target, ':wq\r')
        saved = await terminal(driver, target, 'wc -c /tmp/draft\r')
        assert b'6 /tmp/draft\r\n' in raw(saved)
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_ios_error_marker_and_control_z_match_input(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        invalid = await terminal(driver, target, 'nonsense\r')
        assert b'\r\n' + b' ' * len('edge-router-01> ') + b'^\r\n' in raw(invalid)
        await terminal(driver, target, 'enable\rfixture-enable\rconfigure terminal\rinterface GigabitEthernet0/0\r')
        ended = await terminal(driver, target, '\x1a')
        assert b'^Z' in raw(ended) and b'^C' not in raw(ended)
        assert raw(ended).endswith(b'edge-router-01# ')
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_gnu_uname_aliases_use_the_same_effective_facts(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    async with await asyncssh.connect('127.0.0.1', port=endpoint(runtime)['ports']['tcp']['host'],
            username='guest', known_hosts=None, encoding=None) as client:
        result = await client.run('hostname changed-node; uname --nodename; uname -n; uname --kernel-name')
        assert result.stdout == b'changed-node\nchanged-node\nLinux\n'
        failed = await client.run('uname --nodename -z', check=False)
        assert failed.exit_status != 0 and not failed.stdout


@pytest.mark.asyncio
@pytest.mark.parametrize('term', ['xterm', 'xterm-256color'])
async def test_client_emulator_restores_primary_screen_and_cursor(runtime_factory, term):
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'))
    driver = Drivers()
    target = endpoint(runtime)
    try:
        await driver.execute(target, ProbeAction(operation='terminal', session='screen',
            parameters={'term': term, 'events': []}), ('screen',))
        await terminal(driver, target, 'vi notes.txt\r')
        restored = await terminal(driver, target, ':q\r')
        screen = '\n'.join(restored['facts']['screen'])
        assert 'Authorized access only.' in screen
        assert not any(line.startswith('~') for line in restored['facts']['screen'])
        assert restored['facts']['cursor']['column'] == len('guest@build-node-03:~$ ')
    finally:
        await driver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('body,expected', [(b'', b''), (b'\n', b'\n'), (b'\n\n', b'\n\n'),
    (b'a\n\n', b'a\n\n'), (b'a', b'a\n'), (b'a\n', b'a\n')])
async def test_editor_repeated_save_preserves_empty_and_blank_lines(runtime_factory, body, expected):
    from deceive.device.apps import Application
    profile = load_profile('linux-device')
    runtime = await runtime_factory('ssh', profile=profile)
    session = runtime.new_session(next(iter(runtime.listeners.values())), username='guest')
    session.virtual_files['/tmp/lines'] = body
    editor = Application.open('vi', ['/tmp/lines'], profile, session)
    editor.save(profile, session)
    editor.save(profile, session)
    assert session.virtual_files['/tmp/lines'] == expected


def test_client_emulator_resizes_both_buffers_without_losing_primary_cursor():
    import pyte
    from deceive.terminal_client import Screen
    screen = Screen(80, 24)
    stream = pyte.ByteStream(screen)
    stream.feed(b'parent\x1b[?1049hchild')
    screen.resize(30, 100)
    stream.feed(b'\x1b[?1049l')
    assert screen.columns == 100 and screen.lines == 30
    assert screen.display[0].startswith('parent')
    assert 'child' not in '\n'.join(screen.display)
    assert screen.cursor.x == 6 and screen.cursor.y == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['linux-device', 'ios-device'])
@pytest.mark.parametrize('failure', ['provider', 'timeout'])
async def test_provider_request_failure_preserves_channel_state_and_telemetry(runtime_factory, name, failure):
    from unittest.mock import AsyncMock
    from deceive.providers import ModelResult, ProviderError
    profile = load_profile(name)
    runtime = await runtime_factory('ssh', profile=profile, model=True)
    error = ProviderError('private-provider-detail-do-not-log') if failure == 'provider' else TimeoutError()
    runtime.test_provider.complete = AsyncMock(side_effect=[error,
        ModelResult(json.dumps({'stdout': 'recovered\n', 'exit_status': 0}))])
    driver = Drivers()
    target = endpoint(runtime)
    observations = []
    async def commands(values):
        action = ProbeAction(operation='commands', session='recovery', parameters={
            'commands': values, 'continuation_prompts': ['Password: ']})
        result = await driver.execute(target, action, ('recovery',))
        observations.append(result | {'protocol': 'ssh', 'action': action.model_dump()})
        return result
    try:
        if name == 'ios-device':
            before = await commands(['enable', 'fixture-enable', 'configure terminal',
                                     'hostname retained-edge', 'end'])
            request = 'show inventory'
        else:
            before = await commands(['echo retained > /tmp/before', 'hostname retained-node'])
            request = 'uptime'
        unavailable = await commands([request])
        output = unavailable['facts']['outputs'][0]
        assert output['exit_status'] is None
        assert unavailable['session_id'] == before['session_id']
        assert b'temporarily unavailable' in base64.b64decode(output['body_base64'])
        if name == 'ios-device':
            state = await commands(['show version'])
            assert b'retained-edge' in base64.b64decode(state['facts']['outputs'][0]['body_base64'])
        else:
            state = await commands(['echo $?', 'cat /tmp/before', 'hostname'])
            assert base64.b64decode(state['facts']['outputs'][0]['body_base64']) == b'1\n'
            assert base64.b64decode(state['facts']['outputs'][1]['body_base64']) == b'retained\n'
            assert base64.b64decode(state['facts']['outputs'][2]['body_base64']) == b'retained-node\n'
        recovered = await commands([request])
        assert b'recovered' in base64.b64decode(recovered['facts']['outputs'][0]['body_base64'])
        assert recovered['session_id'] == before['session_id']
    finally:
        await driver.close()
    await asyncio.sleep(.05)
    text = runtime.test_stream.getvalue()
    assert 'private-provider-detail-do-not-log' not in text
    records = [json.loads(line) for line in text.splitlines()]
    failures = [r for r in records if r['message'] == 'Model attempt failed']
    assert len(failures) == 1 and failures[0]['request_id']
    assert audit(records, observations, {profile.id})['status'] == 'passed'


@pytest.mark.asyncio
async def test_ios_connected_routes_follow_interface_state(runtime_factory):
    import re
    from unittest.mock import AsyncMock
    from deceive.clients import ShellClient
    from deceive.providers import ModelResult
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': 'detail unavailable\n', 'exit_status': 0})))
    async with await asyncssh.connect('127.0.0.1', port=endpoint(runtime)['ports']['tcp']['host'],
            username='guest', known_hosts=None, encoding=None) as client:
        shell = await ShellClient.open(client, 2, continuation_prompts=(b'Password: ',))
        await shell.run('enable', 2)
        await shell.run('fixture-enable', 2)
        up = await shell.run('show ip route', 2)
        assert re.search(rb'^C\s+192\.0\.2\.0/24', up.body, re.M)
        assert not runtime.test_provider.complete.called
        for command in ['configure terminal', 'interface GigabitEthernet0/0', 'shutdown', 'end']:
            await shell.run(command, 2)
        down = await shell.run('show ip route', 2)
        assert not re.search(rb'^[CL]\s', down.body, re.M)
        for command in ['configure terminal', 'interface GigabitEthernet0/0', 'no shutdown', 'end']:
            await shell.run(command, 2)
        restored = await shell.run('show ip route', 2)
        assert restored.body == up.body


@pytest.mark.asyncio
async def test_freebsd_reports_native_machine_spelling(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('freebsd-device'))
    async with await asyncssh.connect('127.0.0.1', port=endpoint(runtime)['ports']['tcp']['host'],
            username='guest', known_hosts=None, encoding=None) as client:
        assert (await client.run('uname -m')).stdout == b'amd64\n'
