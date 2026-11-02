import asyncio
from base64 import b64decode
import json

import asyncssh
import pytest


async def connect(runtime, username="guest", password=None):
    name = next(iter(runtime.listeners))
    return await asyncssh.connect("127.0.0.1", port=runtime.servers[name].endpoints[0]["port"],
                                  username=username, password=password, known_hosts=None)


@pytest.mark.asyncio
async def test_noninteractive_prompt_and_log_contract(runtime_factory):
    runtime = await runtime_factory("ssh")
    async with await connect(runtime) as connection:
        result = await connection.run("pwd")
        assert result.stdout == "/home/guest\n"
        assert "$ " not in result.stdout and "Welcome" not in result.stdout
    await asyncio.sleep(0.02)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    inputs = [r for r in records if r["message"] == "User input"]
    assert len(inputs) == 1
    assert b64decode(inputs[0]["details"]) == b"pwd"
    assert inputs[0]["interactive"] is False
    assert len({r["task_name"] for r in records if r["task_name"] != "-"}) == 1
    summaries = [r for r in records if r["message"] == "Session summary"]
    assert len(summaries) == 1 and summaries[0]["judgement"] == "UNKNOWN"


@pytest.mark.asyncio
@pytest.mark.parametrize("username,password", [("guest", None), ("user1", "secret"),
                                               ("root", "anything"), ("root", ""),
                                               ("intruder", ""), ("intruder", "supplied")])
async def test_authentication_modes(runtime_factory, username, password):
    runtime = await runtime_factory("ssh")
    async with await connect(runtime, username, password) as connection:
        result = await connection.run("whoami")
        assert result.stdout == username + "\n"


@pytest.mark.asyncio
async def test_wrong_password_logged_and_rejected(runtime_factory):
    runtime = await runtime_factory("ssh")
    with pytest.raises(asyncssh.PermissionDenied):
        await connect(runtime, "user1", "wrong")
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    failures = [r for r in records if r["message"] == "Authentication failed"]
    assert failures and failures[0]["password"] == "wrong"


@pytest.mark.asyncio
async def test_interactive_state_is_private_and_identity_consistent(runtime_factory):
    runtime = await runtime_factory("ssh")
    async with await connect(runtime) as first, await connect(runtime) as second:
        a = await first.create_process(term_type="xterm")
        b = await second.create_process(term_type="xterm")
        for process in (a, b):
            banner = await asyncio.wait_for(process.stdout.readuntil("$ "), 2)
            assert "Welcome" in banner and "build-node-03" in banner
            process.stdin.write("hostname\n")
            output = await asyncio.wait_for(process.stdout.readuntil("$ "), 2)
            assert output.startswith("build-node-03\n")
        a.stdin.write("cd /etc\n")
        assert "/etc$ " in await asyncio.wait_for(a.stdout.readuntil("$ "), 2)
        b.stdin.write("pwd\n")
        assert (await asyncio.wait_for(b.stdout.readuntil("$ "), 2)).startswith("/home/guest\n")
        for process in (a, b):
            process.stdin.write("exit\n")
            await asyncio.wait_for(process.wait_closed(), 2)


@pytest.mark.asyncio
async def test_source_ports_keys_and_virtual_files(runtime_factory, tmp_path):
    runtime = await runtime_factory("ssh", name="stable")
    key_path = runtime.config.data_dir / "keys/stable-ssh-key"
    key = key_path.read_bytes()
    secret = tmp_path / "HOST-SECRET"
    secret.write_text("host data must not escape")
    async with await connect(runtime) as first, await connect(runtime) as second:
        ports = [c.get_extra_info("sockname")[1] for c in (first, second)]
        outputs = await asyncio.gather(first.run("cat " + str(secret)), second.run("hostname"))
        assert "host data" not in outputs[0].stdout
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    assert {r["src_port"] for r in records if r["message"] == "User input"} == set(ports)
    await runtime.close()
    restarted = await runtime_factory("ssh", name="stable")
    assert key_path.read_bytes() == key
    async with await connect(restarted) as connection:
        assert (await connection.run("hostname")).stdout == "build-node-03\n"


@pytest.mark.asyncio
async def test_input_limit_and_idle_timeout(runtime_factory):
    runtime = await runtime_factory("ssh", limits={"input_bytes": 128, "idle_seconds": 0.2})
    async with await connect(runtime) as connection:
        process = await connection.create_process(term_type="xterm")
        await asyncio.wait_for(process.stdout.readuntil("$ "), 2)
        process.stdin.write("a" * 129)
        await asyncio.wait_for(process.wait_closed(), 2)
    async with await connect(runtime) as connection:
        process = await connection.create_process(term_type="xterm")
        await asyncio.wait_for(process.wait_closed(), 2)
    assert not runtime.sessions


@pytest.mark.asyncio
async def test_idle_connection_without_channel_is_closed(runtime_factory):
    runtime = await runtime_factory("ssh", limits={"idle_seconds": 0.1})
    connection = await connect(runtime)
    await asyncio.wait_for(connection.wait_closed(), 1)
    assert not runtime.sessions
