import pytest

from deceive.interaction import Interaction
from test_behavior_contracts import make_runtime


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['cmd', 'powershell-5.1', 'powershell-7'])
async def test_wrappers_preserve_apostrophe_paths_and_empty_arguments(tmp_path, dialect):
    runtime, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect=dialect,
        files={r"C:\Temp\O'Brien.txt": 'stored\r\n'},
        programs=[{'name': 'sample', 'path': r'C:\Tools\sample.exe'}],
        contracts=[{'id': 'echo', 'command': {'program': 'sample', 'args': ['echo', '{value}']},
                    'reply': {'body': '${command.value}\n'}}])
    async def run(text):
        return await runtime.respond(session, Interaction(protocol='ssh', command=text))
    assert (await run('cmd /d /c type "C:\\Temp\\O\'Brien.txt"')).body == b'stored\r\n'
    result = await run('cmd /d /c sample echo ""')
    assert result.exit_status == 0 and result.body == b'\n' and result.stderr == b''
    assert (await run('cmd /d /c sample echo "left|right"')).body == b'left|right\n'
    await runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['cmd', 'powershell-5.1', 'powershell-7'])
async def test_adjacent_redirection_and_quoted_operator_data(tmp_path, dialect):
    runtime, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect=dialect)
    async def run(text):
        return await runtime.respond(session, Interaction(protocol='ssh', command=text))
    program = 'echo' if dialect == 'cmd' else 'Write-Output'
    assert (await run(program + r' first>C:\Temp\adjacent')).exit_status == 0
    assert (await run(program + r' second>>C:\Temp\adjacent')).exit_status == 0
    reader = 'type' if dialect == 'cmd' else 'Get-Content'
    assert (await run(reader + r' C:\Temp\adjacent')).body == b'first\r\nsecond\r\n'
    before = session.virtual_files.copy()
    assert (await run(program + ' ">" literal')).body == b'> literal\r\n'
    assert (await run(program + ' "left|right"')).body == b'left|right\r\n'
    assert session.virtual_files == before
    for command in (program + r' first>C:\Temp\a>C:\Temp\b',
                    program + r' first 2>C:\Temp\a'):
        assert (await run(command)).exit_status != 0
        assert session.virtual_files == before
    await runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('dialect', ['powershell-5.1', 'powershell-7'])
async def test_powershell_discovers_its_type_alias(tmp_path, dialect):
    runtime, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect=dialect)
    response = await runtime.respond(session, Interaction(protocol='ssh', command='Get-Command type'))
    assert response.exit_status == 0 and b'Get-Content' in response.body
    await runtime.close()
