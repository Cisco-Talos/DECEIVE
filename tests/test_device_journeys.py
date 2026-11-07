"""Extended OpenSSH journeys are shared with installed artifact verification."""
import asyncio
from importlib.resources import files
import shutil

import pytest
import yaml

from deceive.config import load_profile
from deceive.device.journeys import run_openssh

JOURNEYS = yaml.safe_load(files('deceive').joinpath('journeys/devices.yaml').read_text())['journeys']


def test_journey_coverage():
    assert shutil.which('ssh'), 'OpenSSH must be installed for acceptance'
    assert len(JOURNEYS) == 13
    assert all(len(j['steps']) >= 20 for j in JOURNEYS)
    assert {j['profile'] for j in JOURNEYS} == {
        'sudo-2019-14287', 'linux-device', 'macos-device', 'freebsd-device', 'ios-device'}


@pytest.mark.asyncio
@pytest.mark.parametrize('journey', JOURNEYS, ids=lambda j:j['id'])
async def test_extended_openssh_journey(runtime_factory, journey):
    runtime = await runtime_factory('ssh', profile=load_profile(journey['profile']))
    endpoint = next(iter(runtime.servers.values())).endpoints[0]
    result = await asyncio.to_thread(run_openssh, endpoint['port'], journey)
    assert result['passed'] and result['goals_completed'] >= 20


@pytest.mark.asyncio
async def test_native_openssh_fullscreen_lifecycle(runtime_factory):
    journey={'id':'native-applications','profile':'linux-device','prompt':'guest@build-node-03:~$ ',
             'steps':[
        {'command':'vi /tmp/native','prompt':'\x1b[?25h','contains':['/tmp/native']},
        {'send':'ihello','prompt':'\x1b[?25h','contains':['hello']},
        {'send':'\x1b:wq\r','contains':[]},
        {'command':'cat /tmp/native','contains':['hello']},
        {'command':'less notes.txt','prompt':'\x1b[0m','contains':['alpha','beta']},
        {'send':'q','contains':[]},
        {'command':'top','prompt':'\x1b[0m','contains':['worker']},
        {'send':'q','contains':[]},
        {'command':'device-menu','prompt':'\x1b[0m','contains':['Device configuration']},
        {'send':'q','contains':[]},
        {'command':'pwd','contains':['/home/guest']} ]}
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'))
    port=next(iter(runtime.servers.values())).endpoints[0]['port']
    result=await asyncio.to_thread(run_openssh,port,journey)
    assert result['passed']
