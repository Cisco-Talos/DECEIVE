import asyncio
import asyncssh
import pytest

from deceive.clients import ShellClient
from deceive.config import load_profile
from deceive.behaviors import validate_behavior
from deceive.providers import ModelResult
from unittest.mock import AsyncMock


async def connection(runtime):
    port = next(iter(runtime.servers.values())).endpoints[0]['port']
    return await asyncssh.connect('127.0.0.1', port=port, username='guest',
                                  known_hosts=None, encoding=None)


@pytest.mark.asyncio
async def test_missing_file_and_directory_errors_use_stderr(runtime_factory):
    runtime = await runtime_factory('ssh', model=True)
    async with await connection(runtime) as client:
        result = await client.run('cat /etc/absent-file', check=False)
        assert result.stdout == b'' and result.exit_status == 1
        assert b'No such file' in result.stderr
    async with await connection(runtime) as client:
        result = await client.run('cd /absent-directory', check=False)
        assert result.stdout == b'' and result.exit_status == 1
        assert b'No such file' in result.stderr


@pytest.mark.asyncio
async def test_listing_sizes_names_and_contents_share_the_same_view(runtime_factory):
    runtime = await runtime_factory('ssh', model=True)
    async with await connection(runtime) as client:
        shell = await ShellClient.open(client, 2)
        long = (await shell.run('ls -la', 2)).body
        short = (await shell.run('ls /home/guest', 2)).body
        body = (await shell.run('cat README.txt', 2)).body
        row = next(line.split() for line in long.splitlines() if line.endswith(b'README.txt'))
        assert int(row[4]) == len(body)
        assert short == b'README.txt\n'
        assert b'.bashrc' in long and b'.ssh' not in long
        await shell.run('exit', 2)
    assert not runtime.test_provider.calls


@pytest.mark.asyncio
async def test_sudo_listing_uses_its_declared_stable_file_date(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('sudo-2019-14287'))
    async with await connection(runtime) as client:
        output = await client.run('ls -la')
        assert b'Oct 18  2019' in output.stdout
        assert b'Jan 15 09:00' not in output.stdout


def test_virtual_listing_date_rejects_terminal_control_sequences():
    profile = load_profile('sudo-2019-14287')
    listing = next(b for b in profile.behaviors if b.kind == 'virtual_files')
    listing.options['listing_time'] = 'Oct 18\nunauthorized'
    with pytest.raises(ValueError, match='listing_time'):
        validate_behavior(listing, profile)


@pytest.mark.asyncio
async def test_private_touch_write_read_list_remove_and_cwd(runtime_factory, tmp_path):
    runtime = await runtime_factory('ssh', model=True)
    # A real writable host path is still only a virtual name inside the simulation.
    host_path = str(tmp_path / 'must-not-exist')
    async with await connection(runtime) as first, await connection(runtime) as second:
        a, b = await ShellClient.open(first, 2), await ShellClient.open(second, 2)
        assert (await a.run('touch /tmp/sample', 2)).body == b''
        assert (await a.run('cat /tmp/./sample', 2)).body == b''
        listed = (await a.run('ls -l /tmp/sample', 2)).body
        assert b'/tmp/sample' in listed and listed.split()[2:5] == [b'guest', b'guest', b'0']
        assert b'No such file' in (await b.run('cat /tmp/sample', 2)).body
        assert (await a.run('mkdir /tmp/work', 2)).body == b''
        await a.run('cd /tmp/work', 2)
        assert (await a.run('pwd', 2)).body == b'/tmp/work\n'
        await a.run('echo orchid > note', 2)
        assert (await a.run('cat note', 2)).body == b'orchid\n'
        await a.run('echo second >> note', 2)
        assert (await a.run('cat note', 2)).body == b'orchid\nsecond\n'
        await a.run('touch ' + host_path, 2)
        assert not (tmp_path / 'must-not-exist').exists()
        await a.run('rm note', 2)
        assert b'No such file' in (await a.run('cat note', 2)).body
        assert (await b.run('pwd', 2)).body == b'/home/guest\n'
        await a.run('exit', 2)
        await b.run('exit', 2)
    assert not runtime.test_provider.calls
    await asyncio.sleep(.05)  # Connection summary follows channel shutdown.
    assert not runtime.sessions


@pytest.mark.asyncio
async def test_overwritten_baseline_is_private_and_double_slash_is_virtual(runtime_factory):
    runtime = await runtime_factory('ssh', model=True)
    async with await connection(runtime) as first, await connection(runtime) as second:
        a, b = await ShellClient.open(first, 2), await ShellClient.open(second, 2)
        original = (await b.run('cat README.txt', 2)).body
        await a.run('echo replacement > README.txt', 2)
        assert (await a.run('cat README.txt', 2)).body == b'replacement\n'
        assert (await b.run('cat README.txt', 2)).body == original
        await a.run('touch //tmp/slashes', 2)
        assert b'/tmp/slashes' in (await a.run('ls -l /tmp/slashes', 2)).body
        await a.run('exit', 2)
        await b.run('exit', 2)


@pytest.mark.asyncio
async def test_session_view_is_given_to_generative_fallback_and_is_bounded(runtime_factory):
    runtime = await runtime_factory('ssh', model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult('{"stdout":"ok","exit_status":0}'))
    async with await connection(runtime) as client:
        shell = await ShellClient.open(client, 2)
        await shell.run('echo private-value > /tmp/model-context', 2)
        await shell.run('some-generative-command', 2)
        assert '/tmp/model-context' in runtime.test_provider.complete.call_args.args[0][0].content
        assert 'private-value' in runtime.test_provider.complete.call_args.args[0][0].content
        # More virtual nodes than the per-session cap must fail without host side effects.
        result = await shell.run('touch ' + ' '.join('/tmp/f' + str(i) for i in range(130)), 2)
        assert b'No space left' in result.body
        assert (await shell.run('ls /tmp', 2)).body == b'model-context\n'
        await shell.run('exit', 2)
