"""Installed-package screen/state checks using a real SSH client and pyte."""
from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
import tempfile

import asyncssh
import pyte

from deceive.config import load_profile
from deceive.models import Deployment, Listener
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


async def exercise(root: Path) -> dict:
    profile=load_profile('linux-device')
    listener=Listener(name='screen',protocol='ssh',profile=profile.id,host='127.0.0.1',port=0,
                      accounts={'guest':''})
    runtime=Runtime(Deployment(data_dir=root,listeners=[listener]),profiles={'screen':profile},
                    telemetry=Telemetry('screen',stream=io.StringIO()))
    await runtime.start()
    try:
        async with asyncssh.connect('127.0.0.1',port=runtime.servers['screen'].endpoints[0]['port'],
                                    username='guest',known_hosts=None,encoding=None) as client:
            p=await client.create_process(term_type='xterm')
            await asyncio.wait_for(p.stdout.readuntil(b'$ '),3)
            screen=pyte.Screen(80,24); stream=pyte.ByteStream(screen)
            p.stdin.write(b'vi /tmp/installed\n')
            stream.feed(await asyncio.wait_for(p.stdout.readuntil(b'\x1b[?25h'),3))
            assert '/tmp/installed' in '\n'.join(screen.display)
            p.stdin.write(b'iartifact')
            await asyncio.sleep(.08)
            p.stdin.write(b'\x1b')
            await asyncio.sleep(.08)
            p.stdin.write(b':wq\r')
            await asyncio.wait_for(p.stdout.readuntil(b'$ '),3)
            p.stdin.write(b'cat /tmp/installed\n')
            assert (await asyncio.wait_for(p.stdout.readuntil(b'$ '),3)).startswith(b'artifact')
            for app,marker in [(b'less notes.txt',b'notes.txt'),(b'top',b'q quit | s delay'),
                               (b'device-menu',b'Arrows select')]:
                p.stdin.write(app+b'\n')
                raw=await asyncio.wait_for(p.stdout.readuntil(marker),3)
                assert b'\x1b[?1049h' in raw
                p.stdin.write(b'q')
                await asyncio.wait_for(p.stdout.readuntil(b'$ '),3)
            p.stdin.write(b'exit\n')
            await asyncio.wait_for(p.wait_closed(),3)
    finally:
        await runtime.close()
    assert not runtime.channels and not runtime.sessions
    return {'passed':True,'applications':4,'live_model_calls':0}


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        print(json.dumps(asyncio.run(exercise(Path(directory)))))


if __name__=='__main__':
    main()
