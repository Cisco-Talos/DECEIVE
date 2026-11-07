"""Ordinary sudo-profile exploration must remain coherent and entirely virtual."""

import asyncio
import json
import asyncssh
import pytest
from unittest.mock import AsyncMock

from deceive.clients import ShellClient
from deceive.config import load_profile
from deceive.providers import ModelResult


async def connect(runtime):
    port = next(iter(runtime.servers.values())).endpoints[0]['port']
    return await asyncssh.connect('127.0.0.1', port=port, username='guest',
                                  known_hosts=None, encoding=None)


@pytest.mark.asyncio
async def test_sudo_profile_has_browseable_virtual_executables(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'))
    async with await connect(runtime) as client:
        for directory, expected in ((b'/bin', {b'bash', b'cat', b'ls', b'sh'}),
                                    (b'/usr/bin', {b'id', b'python', b'python3', b'sudo'})):
            result = await client.run(b'ls ' + directory, check=False)
            assert result.exit_status == 0 and result.stderr == b''
            assert expected <= set(result.stdout.splitlines())
            result = await client.run(b'cd ' + directory + b' && pwd', check=False)
            assert result.exit_status == 0 and result.stdout == directory + b'\n'
        result = await client.run('which python', check=False)
        assert result.exit_status == 0 and result.stdout == b'/usr/bin/python\n'
        result = await client.run('ls -l /usr/bin/python', check=False)
        assert result.exit_status == 0 and b'-rwxr-xr-x' in result.stdout
        result = await client.run('python --version', check=False)
        assert result.exit_status == 0 and b'Python 3.7.' in result.stdout
        result = await client.run('python -c "print(1 + 2)"', check=False)
        assert result.exit_status == 0 and result.stdout == b'3\n'
        result = await client.run('python -c "import subprocess"', check=False)
        assert result.exit_status == 1 and b'ImportError' in result.stderr
        result = await client.run('touch /usr/bin/injected', check=False)
        assert result.exit_status == 1 and b'Permission denied' in result.stderr
        result = await client.run('ls /usr/bin', check=False)
        assert b'injected' not in result.stdout


@pytest.mark.asyncio
async def test_python_prompt_is_virtual_and_returns_to_parent(runtime_factory, tmp_path):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'))
    marker = tmp_path / 'host-only-marker'
    marker.write_text('HOST_SECRET')
    async with await connect(runtime) as client:
        process = await client.create_process(term_type='xterm', encoding=None)
        async def until(marker: bytes) -> bytes:
            return await asyncio.wait_for(process.stdout.readuntil(marker), 2)

        await until(b'guest@build-node-03:~$ ')
        process.stdin.write(b'python\n')
        entered = await until(b'>>> ')
        assert b'Python 3.7.' in entered
        process.stdin.write(b'print("hello")\n')
        assert b'hello' in await until(b'>>> ')
        process.stdin.write(b'import os\n')
        await until(b'>>> ')
        process.stdin.write(b'os.getcwd()\n')
        assert b"'/home/guest'" in await until(b'>>> ')
        process.stdin.write(b'os.listdir("/usr/bin")\n')
        assert b'python' in await until(b'>>> ')
        process.stdin.write(b'open("/etc/hostname").read()\n')
        assert b'build-node-03' in await until(b'>>> ')
        process.stdin.write(f'open("{marker}").read()\n'.encode())
        denied = await until(b'>>> ')
        assert b'No such file or directory' in denied and b'HOST_SECRET' not in denied
        process.stdin.write(b'exit()\n')
        assert (await until(b'guest@build-node-03:~$ ')).endswith(
            b'guest@build-node-03:~$ ')
        process.stdin.write(b'exit\n')
        await process.wait_closed()
    assert marker.read_text() == 'HOST_SECRET'


@pytest.mark.asyncio
async def test_model_can_extend_private_executable_inventory(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': 'ripgrep 13.0.0\n', 'exit_status': 0,
        'effects': {'add_executables': ['/usr/bin/rg']}})))
    async with await connect(runtime) as first, await connect(runtime) as second:
        shell = await ShellClient.open(first, 2)
        result = await shell.run('rg --version', 2)
        assert b'ripgrep 13.0.0' in result.body
        assert (await shell.run('which rg', 2)).body == b'/usr/bin/rg\n'
        assert b'rg\n' in (await shell.run('ls /usr/bin', 2)).body
        assert b'rg\n' not in (await second.run('ls /usr/bin')).stdout
        assert runtime.test_provider.complete.call_count == 1
        await shell.run('exit', 2)


@pytest.mark.asyncio
async def test_successful_unfamiliar_command_gains_consistent_private_discovery(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': 'Thu Oct 18 09:00:00 UTC 2019\n', 'exit_status': 0})))
    async with await connect(runtime) as client:
        shell = await ShellClient.open(client, 2)
        assert b'2019' in (await shell.run('date', 2)).body
        assert (await shell.run('which date', 2)).body == b'/usr/bin/date\n'
        assert b'date\n' in (await shell.run('ls /usr/bin', 2)).body
        assert runtime.test_provider.complete.call_count == 1
        await shell.run('exit', 2)


@pytest.mark.asyncio
async def test_model_which_claim_must_match_virtual_inventory(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': '/etc/passwd\n', 'exit_status': 0})))
    async with await connect(runtime) as client:
        result = await client.run('which novelcmd', check=False)
        assert result.exit_status == 1 and b'Session unavailable' in result.stderr
        listing = await client.run('ls /usr/bin', check=False)
        assert b'novelcmd\n' not in listing.stdout


@pytest.mark.asyncio
async def test_model_which_claim_registers_a_private_virtual_program(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': '/usr/bin/novelcmd\n', 'exit_status': 0})))
    async with await connect(runtime) as client:
        shell = await ShellClient.open(client, 2)
        assert (await shell.run('which novelcmd', 2)).body == b'/usr/bin/novelcmd\n'
        assert b'novelcmd\n' in (await shell.run('ls /usr/bin', 2)).body
        assert runtime.test_provider.complete.call_count == 1
        await shell.run('exit', 2)


@pytest.mark.asyncio
async def test_model_cannot_register_host_or_protected_paths(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': 'done\n', 'exit_status': 0,
        'effects': {'add_executables': ['/usr/bin/valid', '/etc/passwd']}})))
    async with await connect(runtime) as client:
        result = await client.run('unfamiliar --version', check=False)
        assert result.exit_status == 1 and b'Session unavailable' in result.stderr
        listing = await client.run('ls /usr/bin', check=False)
        assert b'valid\n' not in listing.stdout


@pytest.mark.asyncio
async def test_model_cannot_remove_deterministic_sudo_binary(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': 'removed\n', 'exit_status': 0,
        'effects': {'remove_executables': ['/usr/bin/sudo']}})))
    async with await connect(runtime) as client:
        result = await client.run('package-remove sudo', check=False)
        assert result.exit_status == 1 and b'Session unavailable' in result.stderr
        listing = await client.run('ls /usr/bin', check=False)
        assert b'sudo\n' in listing.stdout


@pytest.mark.asyncio
async def test_model_handles_unfamiliar_python_in_python_context(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'), model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        'stdout': '', 'exit_status': 0,
        'effects': {'write_files': {'/tmp/from-python': 'private\n'}}})))
    async with await connect(runtime) as client:
        process = await client.create_process(term_type='xterm', encoding=None)
        async def until(marker: bytes) -> bytes:
            return await asyncio.wait_for(process.stdout.readuntil(marker), 2)

        await until(b'guest@build-node-03:~$ ')
        process.stdin.write(b'python\n')
        await until(b'>>> ')
        process.stdin.write(b'value = 7\n')
        assert (await until(b'>>> ')).endswith(b'>>> ')
        prompt = runtime.test_provider.complete.call_args.args[0][0].content
        assert '"kind": "python"' in prompt
        process.stdin.write(b'os.system("id")\n')
        assert b'PermissionError' in await until(b'>>> ')
        assert runtime.test_provider.complete.call_count == 1
        process.stdin.write(b'exit()\n')
        await until(b'guest@build-node-03:~$ ')
        process.stdin.write(b'cat /tmp/from-python\n')
        assert b'private' in await until(b'guest@build-node-03:~$ ')
        process.stdin.write(b'exit\n')
        await process.wait_closed()
