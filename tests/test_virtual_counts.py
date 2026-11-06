import pytest

from deceive.config import load_profile
from deceive.interaction import Interaction, Session
from deceive.virtual_files import respond
from test_behavior_contracts import make_runtime


def virtual():
    profile = load_profile('linux-ssh')
    behavior = next(b for b in profile.behaviors if b.kind == 'virtual_files')
    session = Session('count', 'linux-ssh', 'guest', {})
    def run(command, client=session):
        return respond(profile, behavior, Interaction(protocol='ssh', command=command), client)
    return session, run


def test_byte_count_tracks_private_writes_and_utf8_bytes():
    session, run = virtual()
    run('echo FIRST01 > /tmp/report')
    run('echo SECOND01 >> /tmp/report')
    assert run('wc -c /tmp/report').body == b'17 /tmp/report\n'
    run('echo -n café > /tmp/report')
    assert run('/usr/bin/wc --bytes /tmp/report').body == b'5 /tmp/report\n'
    other = Session('other', 'linux-ssh', 'guest', {})
    assert run('wc -c /tmp/report', other).exit_status == 1
    run('rm /tmp/report')
    result = run('wc -c /tmp/report')
    assert result.exit_status == 1 and result.body == b'' and b'No such file' in result.stderr
    assert '/tmp/report' not in session.virtual_files


def test_byte_count_reads_only_virtual_content_including_binary(tmp_path):
    session, run = virtual()
    secret = tmp_path / 'host-only'
    secret.write_text('HOST ONLY')
    result = run('wc -c ' + str(secret))
    assert result.exit_status == 1 and result.body == b''
    session.virtual_files['/tmp/binary'] = b'\x00\xff\x80A'
    assert run('wc -c /tmp/binary').body == b'4 /tmp/binary\n'


@pytest.mark.asyncio
async def test_shared_linux_service_discovers_and_counts_virtual_files(tmp_path):
    runtime, session, _, _ = make_runtime(tmp_path, protocol='ssh', dialect='linux',
                                         files={'/tmp/file': 'café\n'})
    result = await runtime.respond(session, Interaction(protocol='ssh', command='wc -c /tmp/file'))
    assert result.body == b'6 /tmp/file\n' and result.origin == 'deterministic'
    discovery = await runtime.respond(session, Interaction(protocol='ssh', command='which wc'))
    assert discovery.body == b'/usr/bin/wc\n'
    await runtime.close()
