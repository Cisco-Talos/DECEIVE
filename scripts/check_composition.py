"""Run against installed package contents, including inside an offline container."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile

import httpx

from deceive.cli import deployment_from_args, main as cli, parser
from deceive.clients import h3_connect
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


async def exercise(flags: list[str]) -> dict:
    config = deployment_from_args(parser().parse_args(["serve", *flags]))
    runtime = Runtime(config, telemetry=Telemetry("artifact", stream=io.StringIO()))
    try:
        await runtime.start()
        assert len(runtime.servers) == 1
        endpoints = runtime.servers["web"].endpoints
        tcp = next(e["port"] for e in endpoints if e["transport"] == "tcp")
        udp = next(e["port"] for e in endpoints if e["transport"] == "udp")
        async with httpx.AsyncClient(base_url=f"https://127.0.0.1:{tcp}", verify=False,
                                     http1=False, http2=True, trust_env=False) as client:
            responses = await asyncio.gather(*(client.get("/" + name) for name in ("one", "two")))
            assert [r.text for r in responses] == ["one", "two"]
            assert all(r.http_version == "HTTP/2" for r in responses)
        async with h3_connect(udp) as client:
            responses = await asyncio.gather(*(client.request("GET", "/" + name) for name in ("one", "two")))
            assert [r.body for r in responses] == [b"one", b"two"]
            assert all(r.version == "3" for r in responses)
    finally:
        await runtime.close()
    return {"profiles": 2, "listeners": 1, "versions": ["2", "3"], "passed": True}


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ("one", "two"):
            (root / (name + ".yaml")).write_text(json.dumps({
                "id": name, "requirements": {"protocol": "https", "http_versions": ["2", "3"],
                    "base_profile": "demo-http", "base_version": "1"},
                "behaviors": [{"id": "response", "match": {"path": "/" + name},
                               "reply": {"body": name}}]}))
        path = root / "deployment.yaml"
        path.write_text(json.dumps({"data_dir": "data", "log_file": "unused.jsonl", "listeners": [
            {"name": "web", "protocol": "https", "profile": "demo-http", "host": "127.0.0.1",
             "port": 0, "quic_port": 0, "versions": ["2", "3"]}],
            "deceptions": [{"profile": "one.yaml"}]}))
        flags = ["--config", str(path), "--deception", str(root / "two.yaml")]
        with redirect_stdout(io.StringIO()):
            assert cli(["config", "validate", "--offline", *flags]) == 0
        assert not (root / "data").exists() and not (root / "unused.jsonl").exists()
        print(json.dumps(asyncio.run(exercise(flags))))


if __name__ == "__main__":
    main()
