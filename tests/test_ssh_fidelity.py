import asyncio
import base64
import json
from unittest.mock import AsyncMock

import asyncssh
import pytest

from deceive.providers import ModelResult


async def connect(runtime):
    endpoint = next(iter(runtime.servers.values())).endpoints[0]
    return await asyncssh.connect("127.0.0.1", port=endpoint["port"], username="guest",
                                  known_hosts=None, encoding=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload,stdout,stderr,code", [
    ({"stdout": "plain", "stderr": "", "exit_status": 0}, b"plain", b"", 0),
    ({"stdout": "line\n", "stderr": "", "exit_status": 0}, b"line\n", b"", 0),
    ({"stdout": "two\n\n", "stderr": "problem\n", "exit_status": 7}, b"two\n\n", b"problem\n", 7),
    ({"stdout": "\u03bb\x00\r\n", "stderr": "", "exit_status": 0}, "\u03bb\x00\r\n".encode(), b"", 0),
    ({"stdout_base64": "/wA=", "stderr_base64": "gAo=", "exit_status": 2}, b"\xff\x00", b"\x80\n", 2),
    ({"stdout": "", "stderr": "", "exit_status": "1"}, b"", b"", 1),
    ({"stdout": "plain", "exit_status": "255"}, b"plain", b"", 255),
])
async def test_generated_exec_preserves_stream_bytes_status_and_model_log(runtime_factory, payload, stdout, stderr, code):
    runtime = await runtime_factory("ssh", model=True)
    raw = json.dumps(payload)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(raw))
    async with await connect(runtime) as connection:
        result = await connection.run("generated-command", check=False)
    assert (result.stdout, result.stderr, result.exit_status) == (stdout, stderr, code)
    await asyncio.sleep(.05)  # Summaries are connection-owned, after channel closure.
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    response = next(r for r in records if r["message"] == "LLM response")
    assert base64.b64decode(response["details"]) == raw.encode()
    assert base64.b64decode(response["ssh_stdout"]) == stdout
    assert base64.b64decode(response["ssh_stderr"]) == stderr
    assert response["ssh_exit_status"] == code and response["interactive"] is False
    assert len([r for r in records if r["message"] == "Session summary"]) == 1


@pytest.mark.asyncio
async def test_interactive_status_query_and_bare_exit_follow_last_command(runtime_factory):
    runtime = await runtime_factory("ssh", model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        "stdout": "partial", "stderr": "failed\n", "exit_status": 7})))
    prompt = b"guest@build-node-03:~$ "
    async with await connect(runtime) as connection:
        process = await connection.create_process(term_type="xterm")
        await asyncio.wait_for(process.stdout.readuntil(prompt), 2)
        process.stdin.write(b"generated-failure\n")
        assert await asyncio.wait_for(process.stdout.readuntil(prompt), 2) == b"partialfailed\n" + prompt
        process.stdin.write(b"\n")
        assert await asyncio.wait_for(process.stdout.readuntil(prompt), 2) == prompt
        process.stdin.write(b"echo $?\n")
        assert await asyncio.wait_for(process.stdout.readuntil(prompt), 2) == b"7\n" + prompt
        process.stdin.write(b"pwd\n")
        await asyncio.wait_for(process.stdout.readuntil(prompt), 2)
        process.stdin.write(b"echo $?\n")
        assert await asyncio.wait_for(process.stdout.readuntil(prompt), 2) == b"0\n" + prompt
        process.stdin.write(b"generated-failure\n")
        await asyncio.wait_for(process.stdout.readuntil(prompt), 2)
        process.stdin.write(b"exit\n")
        await asyncio.wait_for(process.wait_closed(), 2)
        assert process.exit_status == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", ['{"stdout":"private-marker"}',
    '{"stdout":"private-marker","exit_status":true}',
    '{"stdout":"private-marker","exit_status":256}',
    '{"stdout":"private-marker","exit_status":0,"body_file":"/private-marker"}',
    '{"stdout_base64":"not-base64","exit_status":0}',
    '{"stdout":"private-marker","exit_status":0,"exit_status":7}',
    '{"stdout":"private-marker","exit_status":0,"close":"false"}',
    '{"exit_status":"01"}', '{"exit_status":"1.0"}', '{"exit_status":"+1"}',
    '{"exit_status":" 1"}', '{"exit_status":"256"}', '{"exit_status":"١"}',
    'Explanation\n```json\n{"stdout":"private-marker","exit_status":0}\n```'])
async def test_invalid_generated_shell_reply_fails_without_exposing_wrapper(runtime_factory, raw):
    runtime = await runtime_factory("ssh", model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(raw))
    async with await connect(runtime) as connection:
        result = await connection.run("generated-command", check=False)
    assert result.exit_status == 1 and result.stdout == b""
    assert result.stderr == b"Session unavailable.\n"
    assert b"private-marker" not in result.stdout + result.stderr
    await asyncio.sleep(.05)  # Summaries are connection-owned, after channel closure.
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    failed = [r for r in records if r["message"] == "LLM response"]
    assert len(failed) == 1 and failed[0]["ssh_response_error"] == "invalid_format"
    assert base64.b64decode(failed[0]["details"]) == raw.encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("interactive", [False, True])
async def test_rejected_model_reply_records_attempt_and_actual_failure(runtime_factory, interactive):
    from deceive.assessment.telemetry import audit
    from deceive.clients import ShellClient

    runtime = await runtime_factory("ssh", model=True)
    raw = '{"stdout":"untrusted output"}'
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(raw))
    async with await connect(runtime) as connection:
        if interactive:
            shell = await ShellClient.open(connection, 2)
            result = await shell.run("generated-command", 2)
            body, stderr, status = result.body, b"", None
        else:
            result = await connection.run("generated-command", check=False)
            body, stderr, status = result.stdout, result.stderr, result.exit_status
    await asyncio.sleep(0)
    await asyncio.sleep(.05)  # Summaries are connection-owned, after channel closure.
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    attempted = [r for r in records if r.get("response_stage") == "attempt"]
    final = [r for r in records if r.get("response_stage") == "final"]
    assert len(attempted) == len(final) == 1
    assert attempted[0]["message"] == "LLM response"
    assert base64.b64decode(attempted[0]["details"]).decode() == raw
    assert final[0]["message"] == "Deception response"
    assert final[0]["request_id"] == attempted[0]["request_id"]
    assert base64.b64decode(final[0]["ssh_stdout"]) == b""
    assert base64.b64decode(final[0]["ssh_stderr"]) == b"Session unavailable.\n"
    observation = {"protocol": "ssh", "action": {"operation": "exec", "parameters": {},
        **({"session": "terminal"} if interactive else {})}, "facts": {"outputs": [{
        "command": "generated-command", "body_base64": base64.b64encode(body).decode(),
        "stderr_base64": base64.b64encode(stderr).decode(), "exit_status": status}]}}
    assert audit(records, [observation], {runtime.profiles[next(iter(runtime.listeners))].id})["status"] == "passed"
    assert len([r for r in records if r["message"] == "Session summary"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fence", ["```json\n", "```\n"])
async def test_single_json_envelope_preserves_raw_model_and_wire_bytes(runtime_factory, fence):
    runtime = await runtime_factory("ssh", model=True)
    raw = fence + '{"stdout":"plain","stderr":"error\\n","exit_status":7}\n```'
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(raw))
    async with await connect(runtime) as connection:
        result = await connection.run("generated-command", check=False)
    assert (result.stdout, result.stderr, result.exit_status) == (b"plain", b"error\n", 7)
    await asyncio.sleep(.05)  # Summaries are connection-owned, after channel closure.
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    response = next(r for r in records if r["message"] == "LLM response")
    assert base64.b64decode(response["details"]).decode() == raw


@pytest.mark.asyncio
async def test_sentinel_inside_structured_stdout_is_literal_output(runtime_factory):
    runtime = await runtime_factory("ssh", model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        "stdout": "YYY-END-OF-SESSION-YYY", "exit_status": 0})))
    async with await connect(runtime) as connection:
        from deceive.clients import ShellClient

        shell = await ShellClient.open(connection, 2)
        result = await shell.run("generated-command", 2)
        assert result.body == b"YYY-END-OF-SESSION-YYY" and result.prompt
        assert (await shell.run("exit", 2)).exit_status == 0


@pytest.mark.asyncio
async def test_literal_printf_and_private_history_need_no_model(runtime_factory):
    from deceive.clients import ShellClient

    runtime = await runtime_factory('ssh', model=True)
    runtime.test_provider.complete = AsyncMock(side_effect=AssertionError('Unexpected model call'))
    async with await connect(runtime) as connection:
        result = await connection.run("printf 'wire%%%'")
        assert (result.stdout, result.exit_status) == (b'wire%', 1)
        assert b'invalid conversion' in result.stderr
    async with await connect(runtime) as connection:
        owner = await ShellClient.open(connection, 2)
        await owner.run('echo PRIVATE_LITERAL > /tmp/history-marker', 2)
        history = await owner.run('history', 2)
        assert b'echo PRIVATE_LITERAL > /tmp/history-marker' in history.body
        assert b'history\n' in history.body
        await owner.run('exit', 2)
    async with await connect(runtime) as connection:
        other = await ShellClient.open(connection, 2)
        history = await other.run('history', 2)
        assert history.body == b'    1  history\n'
        await other.run('exit', 2)
    async with await connect(runtime) as connection:
        result = await connection.run('history')
        assert (result.stdout, result.stderr, result.exit_status) == (b'', b'', 0)
    runtime.test_provider.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_live_evaluation_respects_configured_output_limits(tmp_path, monkeypatch):
    from deceive.evaluate import evaluate

    class FakeSDK:
        def __init__(self, *args):
            pass

        async def complete(self, messages):
            return ModelResult(json.dumps({"stdout": "x" * 200, "exit_status": 0}))

        async def close(self):
            pass

    monkeypatch.setattr("deceive.runtime.SDKProvider", FakeSDK)
    config = tmp_path / "deployment.json"
    config.write_text(json.dumps({"limits": {"output_bytes": 128}, "providers": {
        "fake": {"kind": "openai", "model": "offline-fixture"}}, "listeners": [
        {"name": "unused", "protocol": "http", "profile": "demo-http"}]}))
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"id": "bounded", "cases": [{"id": "overflow", "steps": [
        {"command": "generated-command", "expect": {"body": "x" * 200, "exit_status": 0}}]}]}))
    report = await evaluate("linux-ssh", suite, tmp_path / "report", config_path=config,
                            live_model=True)
    assert not report["passed"]
    observed = report["cases"][0]["runs"][0][0]
    assert base64.b64decode(observed["body_base64"]) == b""
    assert base64.b64decode(observed["stderr_base64"]) == b"Session unavailable.\n"


@pytest.mark.asyncio
async def test_assessment_driver_keeps_unterminated_output_and_stderr(runtime_factory):
    from deceive.assessment.drivers import Drivers
    from deceive.assessment.models import ProbeAction

    runtime = await runtime_factory("ssh", model=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
        "stdout": "price $ 5", "stderr": "", "exit_status": 7})))
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    endpoint = {"protocol": "ssh", "ports": {"tcp": {"host": port}}}
    drivers = Drivers()
    try:
        value = await drivers.execute(endpoint, ProbeAction(operation="exec", session="terminal",
            parameters={"command": "generated-command"}), ("test", "terminal"))
        assert base64.b64decode(value["body_base64"]) == b"price $ 5"
        connection = drivers.registry["ssh"].sessions[("test", "terminal")]["connection"]
        value = await drivers.execute(endpoint, ProbeAction(operation="exec", session="terminal",
            parameters={"command": "exit"}), ("test", "terminal"))
        assert value["facts"]["outputs"][0]["exit_status"] == 7
        assert connection.is_closed()
        runtime.test_provider.complete = AsyncMock(return_value=ModelResult(json.dumps({
            "stdout": "ok", "stderr": "error\n", "exit_status": 2})))
        value = await drivers.execute(endpoint, ProbeAction(operation="exec", parameters={
            "command": "generated-command"}), ("test", "exec"))
        assert base64.b64decode(value["facts"]["outputs"][0]["stderr_base64"]) == b"error\n"
    finally:
        await drivers.close()


@pytest.mark.asyncio
async def test_evaluator_keeps_binary_and_unterminated_interactive_output(tmp_path):
    from deceive.config import load_profile
    from deceive.evaluate import evaluate

    profile = load_profile("linux-ssh").model_dump(mode="json")
    profile["fallback"] = "reject"
    profile["behaviors"].insert(0, {"id": "bytes", "match": {"command": "bytes"},
        "reply": {"body_base64": "/wAkIGJ5dGVz", "exit_status": 0}})
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"id": "wire-bytes", "cases": [{"id": "interactive", "steps": [
        {"command": "bytes", "expect": {"body_base64": "/wAkIGJ5dGVz"}},
        {"command": "exit", "expect": {"body": "", "exit_status": 0}}]}]}))
    result = await evaluate(str(path), suite, tmp_path / "results")
    assert result["passed"], result


@pytest.mark.asyncio
async def test_legacy_text_mode_remains_explicit_and_does_not_decode_json(runtime_factory):
    from deceive.config import load_profile

    profile = load_profile("linux-ssh")
    profile.ssh_response_format = "text"
    runtime = await runtime_factory("ssh", profile=profile, model=True)
    literal = '{"stdout":"ordinary file content","exit_status":7}\n'
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(literal))
    async with await connect(runtime) as connection:
        result = await connection.run("generated-command", check=False)
    assert result.stdout == literal.encode() and result.exit_status == 0


@pytest.mark.asyncio
async def test_stdout_and_stderr_share_the_configured_output_bound(runtime_factory):
    from deceive.config import load_profile
    from deceive.models import Behavior

    profile = load_profile("linux-ssh")
    profile.fallback = "reject"
    profile.behaviors.insert(0, Behavior(id="large", match={"command": "large"},
        reply={"body": "a" * 80, "stderr": "b" * 80}))
    runtime = await runtime_factory("ssh", profile=profile, limits={"output_bytes": 128})
    async with await connect(runtime) as connection:
        result = await connection.run("large", check=False)
    assert result.exit_status == 1 and result.stdout == b""
    assert result.stderr == b"Session unavailable.\n"


def test_response_format_inheritance_and_protocol_validation(tmp_path):
    from deceive.composition import _compose
    from deceive.models import Profile

    base = tmp_path / "base.json"
    base.write_text(json.dumps({"id": "base", "protocol": "ssh", "ssh_response_format": "json"}))
    child = {"id": "child", "requirements": {"protocol": "ssh", "base_profile": str(base), "base_version": "1"}}
    assert _compose([Profile.model_validate(child)])[0].ssh_response_format == "json"
    with pytest.raises(ValueError, match="ssh_response_format"):
        _compose([Profile.model_validate(child | {"ssh_response_format": "text"})])
    with pytest.raises(ValueError, match="only supported for SSH"):
        Profile(id="web", protocol="http", ssh_response_format="json")
    with pytest.raises(ValueError, match="only supported for SSH"):
        Profile(id="web", protocol="http", fallback_reply={"stderr": "wrong protocol"})


@pytest.mark.asyncio
async def test_evaluator_asserts_separate_exec_stderr(tmp_path):
    from deceive.evaluate import evaluate

    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"id": "streams", "protocol": "ssh", "behaviors": [{
        "id": "output", "reply": {"body": "out", "stderr_base64": "/wo=", "exit_status": 2}}]}))
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"id": "streams", "cases": [{"id": "exec", "steps": [
        {"command": "output", "expect": {"body": "out", "stderr_base64": "/wo=", "exit_status": 2}}]}]}))
    report = await evaluate(str(profile), suite, tmp_path / "results")
    assert report["passed"], report
    assert report["cases"][0]["runs"][0][0]["stderr_base64"] == "/wo="
    assert report["cases"][0]["runs"][0][0]["exit_status"] == 2
