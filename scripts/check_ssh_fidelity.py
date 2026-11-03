"""Exercise installed SSH output contracts without credentials or live inference."""
from __future__ import annotations

import asyncio
import base64
import io
import json
from pathlib import Path
import tempfile

import asyncssh

from deceive.clients import ShellClient
from deceive.models import Deployment, Listener, ProviderConfig
from deceive.providers import Message, ModelResult
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


class FixtureProvider:
    async def complete(self, messages: list[Message]) -> ModelResult:
        assert "SSH response format: json" in messages[0].content
        return ModelResult(json.dumps({"stdout_base64": "/wBwbGFpbg==",
                                       "stderr": "failed\n", "exit_status": "7"}))

    async def close(self) -> None:
        pass


async def exercise(root: Path) -> dict:
    output = io.StringIO()
    config = Deployment(data_dir=root / "data",
        providers={"fixture": ProviderConfig(kind="openai", model="offline-fixture")},
        listeners=[Listener(name="ssh", protocol="ssh", profile="linux-ssh",
                            host="127.0.0.1", port=0, provider="fixture")])
    runtime = Runtime(config, providers={"fixture": FixtureProvider()},
                      telemetry=Telemetry("artifact", stream=output))
    try:
        await runtime.start()
        port = runtime.servers["ssh"].endpoints[0]["port"]

        async def connection():
            return await asyncssh.connect("127.0.0.1", port=port, username="guest",
                                          known_hosts=None, encoding=None)

        async with await connection() as client:
            result = await client.run("fixture-command", check=False)
            assert (result.stdout, result.stderr, result.exit_status) == (
                b"\xff\x00plain", b"failed\n", 7)
        async with await connection() as client:
            shell = await ShellClient.open(client, 5)
            result = await shell.run("fixture-command", 5)
            assert result.body == b"\xff\x00plainfailed\n"
            assert (await shell.run("echo $?", 5)).body == b"7\n"
            assert (await shell.run("touch /tmp/artifact-private", 5)).body == b""
            assert (await shell.run("cat /tmp/artifact-private", 5)).body == b""
            listing = (await shell.run("ls -l /tmp/artifact-private", 5)).body
            assert listing.split()[2:5] == [b"guest", b"guest", b"0"]
            await shell.run("echo saved > /tmp/artifact-private", 5)
            assert (await shell.run("cat /tmp/artifact-private", 5)).body == b"saved\n"
            await shell.run("fixture-command", 5)
            assert (await shell.run("exit", 5)).exit_status == 7
        async with await connection() as client:
            result = await client.run("echo $?", check=False)
            assert (result.stdout, result.exit_status) == (b"0\n", 0)
        async with await connection() as client:
            result = await client.run("cat /tmp/artifact-private", check=False)
            assert result.stdout == b"" and b"No such file" in result.stderr and result.exit_status == 1
    finally:
        await runtime.close()
    records = [json.loads(line) for line in output.getvalue().splitlines()]
    summaries = [r for r in records if r["message"] == "Session summary"]
    assert len(summaries) == len({r["task_name"] for r in summaries}) == 4
    replies = [r for r in records if r["message"] == "LLM response"]
    assert len(replies) == 3
    assert all(base64.b64decode(r["ssh_stdout"]) == b"\xff\x00plain" for r in replies)
    assert all(json.loads(base64.b64decode(r["details"]))["exit_status"] == "7" for r in replies)
    return {"passed": True, "sessions": 4, "live_model_calls": 0,
            "binary_streams": True, "exit_status": True, "private_status": True,
            "private_files": True}


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        print(json.dumps(asyncio.run(exercise(Path(directory)))))


if __name__ == "__main__":
    main()
