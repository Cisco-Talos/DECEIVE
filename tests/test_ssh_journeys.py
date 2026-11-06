"""Real OpenSSH terminal journeys with profile-owned expectations."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import time

import pytest
import yaml

from deceive.catalog import profiles
from deceive.config import load_profile


JOURNEYS = yaml.safe_load((Path(__file__).parent / 'fixtures/ssh_journeys.yaml').read_text())


def test_each_bundled_ssh_profile_has_a_terminal_journey():
    assert JOURNEYS['schema_version'] == 1
    expected = {item['id'] for item in profiles() if item['protocol'] == 'ssh'}
    selected = [item['profile'] for item in JOURNEYS['journeys']]
    assert len(selected) == len(set(selected))
    assert set(selected) == expected


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which('ssh') is None, reason='OpenSSH client is unavailable')
@pytest.mark.parametrize('journey', JOURNEYS['journeys'], ids=lambda item: item['profile'])
async def test_real_terminal_journey(runtime_factory, tmp_path, journey):
    profile = load_profile(journey['profile'])
    runtime = await runtime_factory('ssh', profile=profile,
                                    model=journey.get('fake_provider', False))
    port = next(iter(runtime.servers.values())).endpoints[0]['port']
    prompt = journey['prompt'].encode()
    password_spec = journey.get('password')
    askpass = None
    if password_spec:
        password = password_spec['repeat'] * password_spec['count']
        askpass = tmp_path / 'askpass.sh'
        askpass.write_text("#!/bin/sh\nprintf '%s' '" + password + "'\n")
        askpass.chmod(0o700)

    def interact() -> None:
        master, slave = pty.openpty()
        options = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                   '-o', 'LogLevel=ERROR', '-o', 'PubkeyAuthentication=no']
        if password_spec:
            options.extend(['-o', 'PreferredAuthentications=password',
                            '-o', 'NumberOfPasswordPrompts=1'])
        else:
            options.extend(['-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=none'])
        environment = os.environ.copy()
        if askpass:
            environment.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY=':0')
        process = subprocess.Popen(
            ['ssh', '-F', '/dev/null', '-tt', '-p', str(port), *options,
             f"{journey['username']}@127.0.0.1"],
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
            env=environment)
        os.close(slave)

        def read_until(token: bytes) -> bytes:
            output = bytearray()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len(output) < 65536:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        break
                    if token in output:
                        return bytes(output)
            raise AssertionError(f"{journey['profile']}: terminal response missing {token!r}: {bytes(output)!r}")

        try:
            banner = read_until(prompt)
            assert banner.endswith(b'\r\n' + prompt), banner
            for fragment in journey['banner_contains']:
                assert fragment.encode() in banner, (journey['profile'], fragment, banner)
            for step in journey['steps']:
                os.write(master, step['send'].encode())
                observed = read_until(prompt)
                assert observed.endswith(b'\r\n' + prompt), (journey['profile'], step, observed)
                # The command echo is the first line; checks inspect the actual response.
                body = observed.split(b'\r\n', 1)[1][:-len(prompt)]
                for fragment in step.get('contains', []):
                    assert fragment.encode() in body, (journey['profile'], step, observed)
                for fragment in step.get('excludes', []):
                    assert fragment.encode() not in body, (journey['profile'], step, observed)
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            os.close(master)

    await asyncio.to_thread(interact)
    if journey.get('fake_provider'):
        assert not runtime.test_provider.calls
