"""Real OpenSSH journey runner shared by checkout and installed artifact checks."""
from __future__ import annotations

import base64
import json
import os
import pty
import select
import shutil
import subprocess
import time


def run_openssh(port: int, journey: dict) -> dict:
    if shutil.which('ssh') is None:
        raise RuntimeError('OpenSSH client is required for device acceptance')
    master, slave = pty.openpty()
    process = subprocess.Popen(['ssh', '-F', '/dev/null', '-tt', '-p', str(port),
        '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=none',
        '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR', 'guest@127.0.0.1'],
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
        env=dict(os.environ, TERM=journey.get('term', 'xterm')))
    os.close(slave)
    transcript = []
    started = time.monotonic()

    def read_until(expected: str) -> bytes:
        raw = bytearray()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(raw) < 1048576:
            if select.select([master], [], [], .02)[0]:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    break
                if not data:
                    break
                raw.extend(data)
            elif raw.endswith(expected.encode()):
                return bytes(raw)
        raise AssertionError(f'{journey["id"]}: missing {expected!r}: {bytes(raw)!r}')

    try:
        transcript.append({'login': base64.b64encode(read_until(journey['prompt'])).decode()})
        for step in journey['steps']:
            tick = time.monotonic()
            os.write(master, step.get('send', step.get('command', '') + '\r').encode())
            raw = read_until(step.get('prompt', journey['prompt']))
            # Commands are echoed by the terminal; observations exclude that line.
            body = raw.split(b'\r\n', 1)[-1]
            for text in step.get('contains', []):
                assert text.encode() in body, (journey['id'], step, raw)
            for text in step.get('excludes', []):
                assert text.encode() not in body, (journey['id'], step, raw)
            transcript.append({'action': step, 'raw_base64': base64.b64encode(raw).decode(),
                               'seconds': time.monotonic() - tick})
        os.write(master, b'exit\r')
        return {'id': journey['id'], 'profile': journey['profile'], 'passed': True,
                'goals_completed': len(journey['steps']), 'seconds': time.monotonic() - started,
                'transcript': transcript}
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        os.close(master)
