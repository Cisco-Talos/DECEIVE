import json

import pytest

from deceive.config import load_profile
from deceive.interaction import Interaction, Session
from deceive.providers import Message
from deceive.virtual_files import respond
from test_behavior_contracts import make_runtime


def virtual(command, session=None, *, interactive=False):
    profile = load_profile('linux-ssh')
    behavior = next(b for b in profile.behaviors if b.kind == 'virtual_files')
    return respond(profile, behavior, Interaction(protocol='ssh', command=command,
        interactive=interactive), session or Session('literal', 'test', 'guest', {}))


@pytest.mark.parametrize('command,body,status', [
    ("printf 'unfinished%'", b'unfinished', 1),
    ("/usr/bin/printf 'different %%%'", b'different %', 1),
    ("/bin/printf '%'", b'', 1),
    ("printf 'café%%'", 'café%'.encode(), 0),
    ("printf 'plain text'", b'plain text', 0),
    ("printf ''", b'', 0),
    ("printf '%%x%%'", b'%x%', 0),
])
def test_literal_printf_preserves_prefix_and_rejects_incomplete_conversion(command, body, status):
    result = virtual(command)
    assert result is not None
    assert result.body == body and result.exit_status == status
    assert bool(result.stderr) == bool(status)
    if status:
        assert b'invalid conversion' in result.stderr


@pytest.mark.parametrize('command', [
    "printf '%s' value", "printf '%d' bad", r"printf 'line\n'",
    "printf --help", "printf -- 'word%'", "printf '$HOME%'",
    "printf word% > /tmp/output", "printf word%; hostname", "history -c",
])
def test_unclaimed_printf_and_history_forms_keep_fallback(command):
    assert virtual(command) is None


def test_history_uses_only_own_bounded_interactive_user_transcript():
    session = Session('owner', 'test', 'guest', {}, input_count=4)
    session.history = [Message('user', 'pwd'), Message('assistant', 'OUTPUT_NOT_A_COMMAND'),
                       Message('user', 'echo PRIVATE > /tmp/marker')]
    result = virtual('history', session, interactive=True)
    assert result is not None and result.exit_status == 0 and not result.stderr
    assert b'pwd\n' in result.body and b'echo PRIVATE > /tmp/marker\n' in result.body
    assert b'history\n' in result.body and b'OUTPUT_NOT_A_COMMAND' not in result.body
    other = virtual('history', interactive=True)
    assert other.exit_status == 0 and b'PRIVATE' not in other.body
    assert virtual('history', session).body == b''
    assert virtual('history', session).exit_status == 0
    assert session.state == {} and session.virtual_files == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('protocol', ['ssh', 'http'])
async def test_shared_linux_literal_output_and_fresh_web_history(tmp_path, protocol):
    contracts = [{'id': 'exec', 'http': {'path': '/exec'},
                  'endpoint': {'source': 'json'}}] if protocol == 'http' else []
    runtime, session, provider, _ = make_runtime(tmp_path, protocol=protocol,
        dialect='linux', contracts=contracts)
    async def run(command):
        interaction = Interaction(protocol='ssh', command=command) if protocol == 'ssh' else Interaction(
            protocol='http', method='GET', path='/exec', body=json.dumps({'command': command}).encode())
        result = await runtime.respond(session, interaction)
        return (result.body, result.stderr, result.exit_status) if protocol == 'ssh' else (
            json.loads(result.body)['stdout'].encode(), json.loads(result.body)['stderr'].encode(),
            json.loads(result.body)['exit_status'])
    try:
        body, stderr, status = await run("printf 'sibling%'")
        assert body == b'sibling' and status == 1 and b'invalid conversion' in stderr
        assert await run('history') == (b'', b'', 0)
        if protocol == 'ssh':
            assert (await run('which printf'))[0] == b'/usr/bin/printf\n'
        provider.complete.assert_not_awaited()
    finally:
        await runtime.close()
