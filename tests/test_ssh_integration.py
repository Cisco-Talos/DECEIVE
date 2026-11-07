import asyncio
from base64 import b64decode
import json
import os
import pty
import select
import shutil
import subprocess
import time

import asyncssh
import pytest

from deceive.config import load_profile
from deceive.clients import ShellClient


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
            assert "Ubuntu 22.04.5 LTS" in banner and "build-node-03" in banner
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
@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client is unavailable")
async def test_openssh_terminal_accepts_enter_and_echoes_input(runtime_factory):
    runtime = await runtime_factory("ssh", profile=load_profile("sudo-2019-14287"))
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]

    def interact() -> tuple[bytes, bytes, bytes, bytes, bytes]:
        master, slave = pty.openpty()
        process = subprocess.Popen([
            "ssh", "-F", "/dev/null", "-tt", "-p", str(port),
            "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "guest@127.0.0.1",
        ], stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)

        def read_prompt(timeout: float) -> bytes:
            output = bytearray()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        break
                    if b"guest@build-node-03:~$ " in output:
                        break
            return bytes(output)

        try:
            banner = read_prompt(3)
            assert b"guest@build-node-03:~$ " in banner
            os.write(master, b"whoami\r")
            first = read_prompt(3)
            os.write(master, b"whoamx\x7fi\r")
            edited = read_prompt(3)
            os.write(master, b"sudo -u#-1 id\r")
            bypass = read_prompt(3)
            os.write(master, b"ls -la\r")
            listing = read_prompt(3)
            return banner, first, edited, bypass, listing
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            os.close(master)

    banner, first, edited, bypass, listing = await asyncio.to_thread(interact)
    assert b"Debian GNU/Linux 10 (buster)\r\n" in banner
    assert banner.endswith(b"\r\nguest@build-node-03:~$ ")
    for output in (first, edited):
        assert b"whoami" in output or b"whoamx\x08 \x08i" in output
        assert b"guest\r\nguest@build-node-03:~$ " in output
        assert output.endswith(b"guest@build-node-03:~$ ")
    assert b"sudo -u#-1 id" in bypass
    assert b"uid=0(root)" in bypass
    assert bypass.endswith(b"guest@build-node-03:~$ ")
    assert b"ls -la\r\n" in listing
    assert b".bashrc" in listing and b"README.txt" in listing
    assert b"sh: command not found" not in listing
    assert listing.endswith(b"guest@build-node-03:~$ ")


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
async def test_sudo_keeps_deterministic_baseline_and_uses_optional_model_for_unfamiliar_commands(runtime_factory):
    profile = load_profile("sudo-2019-14287")
    assert profile.fallback == "llm_if_available"
    local = await runtime_factory("ssh", profile=profile)
    async with await connect(local) as connection:
        listing = await connection.run("ls -la")
        assert ".bashrc" in listing.stdout and "README.txt" in listing.stdout
        assert listing.exit_status == 0

    modeled = await runtime_factory("ssh", profile=profile, model=True)
    port = next(iter(modeled.servers.values())).endpoints[0]["port"]
    async with await asyncssh.connect("127.0.0.1", port=port, username="guest",
                                     known_hosts=None, encoding=None) as connection:
        shell = await ShellClient.open(connection, 2)
        known = await shell.run("sudo -u#-1 id", 2)
        assert b"uid=0(root)" in known.body
        assert not modeled.test_provider.calls
        unknown = await shell.run("unfamiliar-command", 2)
        assert unknown.body == b"simulated output\n"
        assert len(modeled.test_provider.calls) == 1
        await shell.run("exit", 2)


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
    await asyncio.sleep(.05)
    assert not runtime.sessions


@pytest.mark.asyncio
async def test_idle_connection_without_channel_is_closed(runtime_factory):
    runtime = await runtime_factory("ssh", limits={"idle_seconds": 0.1})
    connection = await connect(runtime)
    await asyncio.wait_for(connection.wait_closed(), 1)
    await asyncio.sleep(.05)
    assert not runtime.sessions
