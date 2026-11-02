import asyncio
import io
from pathlib import Path

import pytest
import pytest_asyncio

from deceive.config import load_profile
from deceive.models import Deployment, Listener, ProviderConfig
from deceive.providers import ModelResult
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


class FakeProvider:
    def __init__(self):
        self.calls = []

    async def complete(self, messages):
        self.calls.append(messages)
        if messages[0].content.startswith("Summarize"):
            return ModelResult("The user inspected the build server. Judgement: BENIGN")
        if messages[-1].content == "exit-shell":
            return ModelResult("YYY-END-OF-SESSION-YYY")
        return ModelResult("simulated output\n")

    async def close(self):
        pass


@pytest_asyncio.fixture
async def runtime_factory(tmp_path):
    runtimes = []

    async def create(protocol="http", *, profile=None, versions=None, limits=None, model=False,
                     analyze=False, accounts=None, name=None):
        name = name or f"instance{len(runtimes)}"
        if profile is None:
            profile = load_profile("linux-ssh" if protocol == "ssh" else "demo-http")
            if not model:
                profile.fallback = "reject"
        listener = Listener(name=name, protocol=protocol, profile=profile.id, host="127.0.0.1",
                            port=0, quic_port=0, versions=versions or ["1.1"],
                            accounts=accounts or {"guest": "", "user1": "secret", "root": "*"},
                            provider="fake" if model else None, analyze=analyze)
        config = Deployment(data_dir=tmp_path / name, listeners=[listener],
                            providers={"fake": ProviderConfig(kind="openai", model="fake")}
                            if model else {}, limits=limits or {})
        stream = io.StringIO()
        provider = FakeProvider()
        runtime = Runtime(config, profiles={name: profile},
                          providers={"fake": provider} if model else {},
                          telemetry=Telemetry("test", stream=stream))
        runtimes.append(runtime)
        runtime.test_stream = stream
        runtime.test_provider = provider
        await runtime.start()
        return runtime

    yield create
    for runtime in reversed(runtimes):
        await asyncio.wait_for(runtime.close(), timeout=10)
