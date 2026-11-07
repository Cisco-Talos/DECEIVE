import base64
from importlib.resources import files

import pytest

from deceive.assessment.drivers import Drivers
from deceive.assessment.models import ProbeAction
from deceive.config import load_profile
from deceive.evaluate import evaluate_external


@pytest.mark.asyncio
async def test_driver_declared_password_continuations_preserve_dialogue(runtime_factory):
    runtime = await runtime_factory('ssh', profile=load_profile('ios-device'))
    driver = Drivers()
    target = endpoint(runtime, 'ssh', [])
    target['timeout'] = .4
    try:
        result = await driver.execute(target, ProbeAction(operation='commands', session='dialogue',
            parameters={'continuation_prompts': ['Password: '], 'commands': [
                'en', 'bad', 'enable', 'fixture-enable', 'show running-config']}), ('dialogue',))
        outputs = result['facts']['outputs']
        assert len(outputs) == 5
        assert base64.b64decode(outputs[0]['prompt_base64']) == b'Password: '
        assert base64.b64decode(outputs[2]['prompt_base64']) == b'Password: '
        assert b'fixture-enable' not in base64.b64decode(outputs[3]['raw_base64'])
        assert b'hostname edge-router-01' in base64.b64decode(outputs[4]['body_base64'])
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_terminal_wait_uses_output_drained_in_same_observation(runtime_factory):
    import asyncio
    import json
    from deceive.providers import ModelResult
    runtime = await runtime_factory('ssh', profile=load_profile('linux-device'), model=True)
    delivered = asyncio.Event()
    async def delayed(messages):
        await asyncio.sleep(.15)
        delivered.set()
        return ModelResult(json.dumps({'stdout':'READY\n','exit_status':0}))
    runtime.test_provider.complete = delayed
    driver = Drivers()
    target = endpoint(runtime, 'ssh', [])
    target['timeout'] = .3
    key = ('wait-race',)
    try:
        await driver.execute(target, ProbeAction(operation='terminal', session='screen',
            parameters={'events':[{'send':'uptime\r'}]}), key)
        await asyncio.wait_for(delivered.wait(), 1)
        await asyncio.sleep(.03)
        result = await driver.execute(target, ProbeAction(operation='terminal', session='screen',
            parameters={'events':[{'wait':'guest@build-node-03:~$ '}]}), key)
        raw = b''.join(base64.b64decode(c['raw_base64']) for c in result['facts']['terminal'])
        assert raw.count(b'READY') == 1
        assert raw.count(b'guest@build-node-03:~$ ') == 1
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_terminal_literal_wait_matches_across_drained_fragments():
    import asyncio
    import asyncssh
    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False
    async def handle(process):
        process.stdout.write(b'RE')
        await asyncio.sleep(.12)
        process.stdout.write(b'ADY> ')
        await process.stdin.read()
    server = await asyncssh.create_server(Server, '127.0.0.1', 0,
        server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')],
        process_factory=handle, encoding=None)
    driver = Drivers()
    target = {'protocol':'ssh','ports':{'tcp':{'host':server.get_port()}},'timeout':.4}
    try:
        result = await driver.execute(target, ProbeAction(operation='terminal',session='fragments',
            parameters={'events':[{'wait':'READY> '}]}), ('fragments',))
        raw = b''.join(base64.b64decode(c['raw_base64']) for c in result['facts']['terminal'])
        assert raw == b'READY> '
    finally:
        await driver.close()
        server.close()
        await server.wait_closed()


def endpoint(runtime, protocol, versions):
    endpoints = next(iter(runtime.servers.values())).endpoints
    return {"protocol": protocol, "versions": versions, "ports": {
        e["transport"]: {"host": e["port"]} for e in endpoints}, "username": "guest", "password": ""}


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["1.1", "2", "3"])
async def test_driver_http_negotiation_binary_and_path_boundary(runtime_factory, version):
    protocol = "http" if version == "1.1" else "https"
    runtime = await runtime_factory(protocol, versions=[version])
    driver = Drivers()
    try:
        result = await driver.execute(endpoint(runtime, protocol, [version]),
            ProbeAction(operation="request", parameters={"path": "/download"}), ("role", "target", "s"))
        assert result["version"] == version and base64.b64decode(result["body_base64"]) == b"\x00\xff\x80A"
        with pytest.raises(ValueError, match="target-relative"):
            await driver.execute(endpoint(runtime, protocol, [version]),
                ProbeAction(operation="request", parameters={"path": "https://example.com/"}), ("x",))
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_driver_ssh_real_session_and_external_accepted_assertions(runtime_factory):
    runtime = await runtime_factory("ssh", profile=load_profile("sudo-2019-14287"))
    driver = Drivers()
    target = endpoint(runtime, "ssh", ["1.1"])

    async def execute(action):
        parsed = ProbeAction.model_validate(action)
        return await driver.execute(target, parsed, ("acceptance", parsed.session or "one-off"))

    try:
        report = await evaluate_external(files("deceive").joinpath("acceptance/sudo-2019-14287.yaml"),
                                         "ssh", "ssh", execute)
        assert report["external_passed"], report
        assert not report["passed"]  # Explicit protected variants still need separate deployments.
        assert any(c["backend"] == "requires_variant" for c in report["cases"])
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_driver_bounded_wire_operations(runtime_factory):
    runtime = await runtime_factory("https", versions=["2", "3"])
    driver = Drivers()
    target = endpoint(runtime, "https", ["2", "3"])
    try:
        rejected = await driver.execute(target, ProbeAction(operation="h2_method", parameters={
            "method": "GET\r\nX-Probe: local"}), ("wire",))
        assert rejected["facts"]["termination_code"] == 1
        ordinary = await driver.execute(target, ProbeAction(operation="h2_resets"), ("wire",))
        assert ordinary["facts"]["status"] == 200
        fin = await driver.execute(target, ProbeAction(operation="h3_fin", parameters={
            "content_length": 3, "body": ""}), ("wire",))
        assert fin["facts"]["termination_code"] == 270
        valid = await driver.execute(target, ProbeAction(operation="h3_fin", parameters={
            "content_length": 2, "body": "ab"}), ("wire",))
        assert valid["facts"]["status"] == 200
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_external_acceptance_preserves_optional_held_out_semantics(tmp_path):
    suite = tmp_path / "suite.yaml"
    suite.write_text('id: optional\ncases:\n'
                     '  - id: required\n    steps: [{path: /, expect: {status: 200}}]\n'
                     '  - id: variation\n    group: held_out\n'
                     '    steps: [{path: /other, expect: {status: 404}}]\n')

    async def execute(action):
        return {"version": "1.1", "facts": {"status": 200}}

    report = await evaluate_external(suite, "http", "1.1", execute)
    assert report["external_passed"]
    suite.write_text(suite.read_text() + 'held_out_min_pass_rate: 1.0\n')
    assert not (await evaluate_external(suite, "http", "1.1", execute))["external_passed"]


@pytest.mark.asyncio
async def test_named_http3_client_reconnects_without_losing_cookie_state(runtime_factory):
    import asyncio
    from deceive.models import Behavior

    profile = load_profile("demo-http")
    profile.stateful = True
    profile.behaviors = [
        Behavior(id="set", match={"path": "/set"}, transition={"flag": "yes"}, reply={"body": "set"}),
        Behavior(id="flag", match={"path": "/flag", "state": {"flag": "yes"}}, reply={"body": "yes"}),
    ]
    runtime = await runtime_factory("https", profile=profile, versions=["3"])
    driver = Drivers()
    target = endpoint(runtime, "https", ["3"])
    key = ("review", "target", "service-1", "visit")
    try:
        first = await driver.execute(target, ProbeAction(operation="request", session="visit", parameters={"path": "/set"}), key)
        transport = driver.registry["https"].sessions[key + ("3",)]["client"]
        transport.close()
        await asyncio.wait_for(transport.wait_closed(), 5)
        async with asyncio.timeout(2):
            result = await driver.execute(target, ProbeAction(operation="request", session="visit", parameters={"path": "/flag"}), key)
        assert base64.b64decode(result["body_base64"]) == b"yes"
        assert result["session_id"] == first["session_id"] and result["facts"]["transport_reconnected"]
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_terminal_screen_driver_and_wire_audit(runtime_factory):
    from deceive.assessment.telemetry import audit
    import json
    runtime=await runtime_factory('ssh',profile=load_profile('linux-device'))
    drivers=Drivers(); target=endpoint(runtime,'ssh',['1.1']); key=('screen',)
    action=ProbeAction(operation='terminal',session='screen',parameters={
        'wait':'$ ', 'events':[{'send':'top\r','wait':'q quit | s delay'},
                              {'resize':[100,30]}]})
    try:
        result=await drivers.execute(target,action,key)
        assert 'worker' in '\n'.join(result['facts']['screen'])
        assert len(result['facts']['screen'])==30
        await drivers.execute(target,ProbeAction(operation='terminal',session='screen',parameters={
            'events':[{'send':'q','wait':'$ '}]}),key)
    finally:
        await drivers.close()
    import asyncio
    await asyncio.sleep(.05)
    records=[json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    observation=result|{'protocol':'ssh','action':action.model_dump()}
    assert audit(records,[observation],{'linux-device'})['status']=='passed'
    assert audit(records,[observation,observation],{'linux-device'})['status']=='failed'
