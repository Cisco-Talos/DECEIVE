import asyncio
import io
import json
import socket

import pytest

from deceive.cli import healthcheck
from deceive.config import load_profile
from deceive.interaction import Interaction
from deceive.models import Deployment, Listener
from deceive.runtime import CapacityError, Runtime
from deceive.telemetry import Telemetry


@pytest.mark.asyncio
async def test_session_capacity_and_health_lifecycle(runtime_factory):
    runtime = await runtime_factory(limits={"sessions": 1})
    listener = next(iter(runtime.listeners.values()))
    session = runtime.new_session(listener)
    with pytest.raises(CapacityError):
        runtime.new_session(listener)
    assert healthcheck(runtime.config.data_dir)
    await runtime.end_session(session)
    runtime.new_session(listener)
    await runtime.close()
    assert not healthcheck(runtime.config.data_dir)


@pytest.mark.asyncio
async def test_failed_start_rolls_back_and_data_lease_is_preserved(runtime_factory):
    runtime = await runtime_factory()
    profile = load_profile("demo-http")
    config = runtime.config.model_copy(deep=True)
    duplicate = Runtime(config, profiles={config.listeners[0].name: profile},
                        telemetry=Telemetry("test", stream=io.StringIO()))
    with pytest.raises(ValueError, match="already in use"):
        await duplicate.start()
    assert healthcheck(runtime.config.data_dir)


@pytest.mark.asyncio
async def test_failure_on_second_listener_closes_first(tmp_path):
    listeners = [Listener(name="first", protocol="http", profile="demo-http", host="127.0.0.1", port=0),
                 Listener(name="second", protocol="ssh", profile="linux-ssh", host="127.0.0.1",
                          port=0, host_key=tmp_path / "missing")]
    profile = load_profile("linux-ssh")
    profile.fallback = "reject"
    runtime = Runtime(Deployment(data_dir=tmp_path / "data", listeners=listeners),
                      profiles={"first": load_profile("demo-http"), "second": profile},
                      telemetry=Telemetry("test", stream=io.StringIO()))
    with pytest.raises(ValueError, match="host key"):
        await runtime.start()
    port = runtime.servers["first"].endpoints[0]["port"]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))
    assert not healthcheck(runtime.config.data_dir)


@pytest.mark.asyncio
async def test_observer_failure_and_queue_overflow_do_not_block(runtime_factory):
    runtime = await runtime_factory()

    class FailingObserver:
        api_version = 1

        async def observe(self, event):
            raise RuntimeError("private-provider-secret")

    runtime.extensions.observers.append(FailingObserver())
    runtime.extensions.start()
    runtime.telemetry.emit("Example event")
    await asyncio.sleep(0.01)
    assert "Observer failed" in runtime.test_stream.getvalue()
    assert "private-provider-secret" not in runtime.test_stream.getvalue()
    for _ in range(runtime.limits.observer_queue + 1):
        runtime.telemetry.emit("Fill queue")
    assert "Observer queue full" in runtime.test_stream.getvalue()
    listener = next(iter(runtime.listeners.values()))
    session = runtime.new_session(listener)
    result = await runtime.respond(session, Interaction("http", path="/"))
    assert result.status == 200


@pytest.mark.asyncio
async def test_output_limit_and_raw_ssh_bytes(runtime_factory):
    runtime = await runtime_factory("ssh", limits={"output_bytes": 128})
    listener = next(iter(runtime.listeners.values()))
    session = runtime.new_session(listener, username="guest")
    await runtime.respond(session, Interaction("ssh", command="replacement", raw_input=b"\xff\x00"))
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    assert next(r for r in records if r["message"] == "User input")["details"] == "/wA="
    profile = runtime.profiles[listener.name]
    profile.fallback_reply.body = "x" * 129
    with pytest.raises(ValueError, match="Response exceeds"):
        await runtime.respond(session, Interaction("ssh", command="unknown"))


@pytest.mark.asyncio
async def test_installed_extension_is_allowlisted_and_versioned(monkeypatch, tmp_path):
    import deceive.extensions as module

    loaded = []

    class Observer:
        api_version = 99

    class Entry:
        name = "example"

        def load(self):
            loaded.append(self.name)
            return Observer

    monkeypatch.setattr(module, "entry_points", lambda **kw: [Entry()])
    config = Deployment(data_dir=tmp_path, listeners=[Listener(protocol="http", profile="demo-http")])
    runtime = Runtime(config, telemetry=Telemetry("test", stream=io.StringIO()))
    assert not loaded
    await runtime.close()
    config.extensions = {"observers": ["example"]}
    with pytest.raises(ValueError, match="Unsupported extension API"):
        Runtime(config, telemetry=Telemetry("test", stream=io.StringIO()))
    assert loaded == ["example"]


@pytest.mark.asyncio
async def test_pathological_command_pattern_has_a_deadline(runtime_factory):
    from deceive.models import Behavior

    runtime = await runtime_factory("ssh")
    listener = next(iter(runtime.listeners.values()))
    runtime.profiles[listener.name].behaviors = [
        Behavior(id="bounded", match={"command_regex": "(a|aa)+$"})]
    session = runtime.new_session(listener, username="guest")
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(runtime.respond(session, Interaction("ssh", command="a" * 4096 + "!")), 1)
    assert runtime.active_requests == 0
