import asyncio
import io
import json

import httpx
import pytest
import yaml

from deceive.cli import deployment_from_args, main, parser
from deceive.composition import resolve
from deceive.config import load_deployment, load_profile
from deceive.interaction import Interaction
from deceive.models import Deployment, Listener
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def write_profile(tmp_path, name, **changes):
    value = {
        "id": name,
        "requirements": {"protocol": "https", "http_versions": ["2", "3"],
                         "base_profile": "demo-http", "base_version": "1",
                         "capabilities": ["http.raw_path", "behavior:rule"]},
        "behaviors": [{"id": "response", "match": {"path": "/" + name},
                       "reply": {"body": name}}],
    }
    value.update(changes)
    path = tmp_path / (name + ".yaml")
    path.write_text(yaml.safe_dump(value))
    return path


def runtime(config):
    return Runtime(config, telemetry=Telemetry("test", stream=io.StringIO()))


def test_additive_selection_deduplicates_and_preserves_existing_listener(tmp_path):
    first = write_profile(tmp_path, "first")
    second = write_profile(tmp_path, "second")
    config = tmp_path / "deployment.yaml"
    config.write_text(yaml.safe_dump({"deceptions": [{"profile": first.name}]}))
    initial_name = resolve(load_deployment(config)).listeners[0].name
    args = parser().parse_args(["config", "validate", "--config", str(config),
                                "--profile", str(first), "--deception", str(second)])
    plan = resolve(deployment_from_args(args))
    assert len(plan.listeners) == 1
    assert plan.listeners[0].name == initial_name
    assert [p.id for p in next(iter(plan.members.values()))] == ["first", "second"]
    config.write_text(yaml.safe_dump({"listeners": [{"name": "existing", "protocol": "https",
        "profile": "demo-http", "port": 8443, "versions": ["2", "3"]}]}))
    args = parser().parse_args(["serve", "--config", str(config), "--profile", str(first),
                                "--profile", str(second)])
    plan = resolve(deployment_from_args(args))
    assert [l.name for l in plan.listeners] == ["existing"]
    assert [p.id for p in plan.members["existing"]] == ["first", "second"]


def test_cli_and_config_validation_are_read_only_and_match_serve(tmp_path, capsys, monkeypatch):
    first = write_profile(tmp_path, "first")
    data = tmp_path / "not-created"

    def no_start(*args, **kwargs):
        pytest.fail("Validation must not start listeners or initialize providers")

    monkeypatch.setattr(Runtime, "start", no_start)
    import deceive.runtime as module
    monkeypatch.setattr(module, "SDKProvider", no_start)
    flags = ["--profile", str(first), "--profile", str(first), "--data-dir", str(data)]
    assert main(["config", "validate", *flags]) == 0
    output = capsys.readouterr().out
    assert output.count("profiles=[first@1]") == 1
    assert not data.exists()
    duplicate = write_profile(tmp_path, "conflict", behaviors=[{
        "id": "duplicate", "match": {"path": "/first"}, "reply": {"body": "different"}}])
    for command in (["config", "validate"], ["serve"]):
        assert main([*command, *flags, "--profile", str(duplicate)]) == 2
        assert "Routing conflict" in capsys.readouterr().err
    assert not data.exists()


@pytest.mark.parametrize("change,message", [
    ({"identity": {"hostname": "another-host"}}, "identity.hostname"),
    ({"prompt": "incompatible", "fallback": "llm"}, "fallback"),
    ({"fallback_reply": {"body": "other"}}, "fallback_reply"),
    ({"files": {"/shared": "second"}}, "virtual file"),
    ({"cookie_name": "another"}, "cookie_name"),
    ({"behaviors": [{"id": "catch-all", "reply": {"body": "everything"}}]}, "routing match"),
])
def test_composition_rejects_conflicting_facts_and_ownership(tmp_path, change, message):
    first = write_profile(tmp_path, "first", files={"/shared": "first"})
    second = write_profile(tmp_path, "second", **change)
    config = Deployment(deceptions=[{"profile": str(first)}, {"profile": str(second)}])
    with pytest.raises(ValueError, match=message):
        runtime(config)


@pytest.mark.parametrize("requirement,message", [
    ({"base_version": "2"}, "base"),
    ({"capabilities": ["http2.raw_frames"]}, "unsupported capabilities"),
    ({"incompatible_with": ["first"]}, "incompatibility"),
    ({"scope": "connection"}, "exclusive listener"),
    ({"http_versions": ["1.1"]}, "HTTP version"),
    ({"required_port": 9443}, "requires port"),
])
def test_requirement_validation(tmp_path, requirement, message):
    first = write_profile(tmp_path, "first")
    value = yaml.safe_load(first.read_text())
    req = value["requirements"] | requirement
    second = write_profile(tmp_path, "second", requirements=req)
    config = Deployment(listeners=[Listener(name="web", protocol="https", profiles=[str(first), str(second)],
                                            port=8443, versions=["2", "3"])])
    with pytest.raises(ValueError, match=message):
        runtime(config)


def test_ambiguous_patterns_duplicate_headers_and_port_collisions(tmp_path):
    first = write_profile(tmp_path, "first", behaviors=[{
        "id": "one", "match": {"headers": {"x-target": "one"}}, "reply": {"body": "one"}}])
    second = write_profile(tmp_path, "second", behaviors=[{
        "id": "two", "match": {"headers": {"x-target": "two"}}, "reply": {"body": "two"}}])
    with pytest.raises(ValueError, match="Routing conflict"):
        resolve(Deployment(deceptions=[{"profile": str(first)}, {"profile": str(second)}]))
    config = Deployment(listeners=[Listener(name=name, protocol="http", profile="demo-http",
                                            port=8080, host=host)
                                   for name, host in [("one", "0.0.0.0"), ("two", "127.0.0.1")]])
    with pytest.raises(ValueError, match="Listener conflict"):
        runtime(config)
    config.listeners[1].port = 8081
    runtime(config)


def test_explicit_default_constraints_are_not_deduplicated_with_inheritance(tmp_path):
    first = write_profile(tmp_path, "first")
    value = yaml.safe_load(first.read_text())
    value["identity"] = {"hostname": "build-node-03"}
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(yaml.safe_dump(value))
    # Both parse to the same identity defaults, but only one requires them.
    assert load_profile(str(first)).identity == load_profile(str(duplicate)).identity
    with pytest.raises(ValueError, match="Conflicting definitions"):
        resolve(Deployment(deceptions=[{"profile": str(first)}, {"profile": str(duplicate)}]))


def test_settings_only_yaml_can_receive_all_selections_from_cli(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config = config_dir / "deployment.yaml"
    config.write_text("data_dir: ./data\ndeception_defaults: {host: 127.0.0.1}\n")
    path = write_profile(tmp_path, "first")
    monkeypatch.chdir(tmp_path)
    args = parser().parse_args(["serve", "--config", str(config), "--deception", path.name])
    deployment = deployment_from_args(args)
    plan = resolve(deployment)
    assert len(plan.listeners) == 1 and plan.listeners[0].host == "127.0.0.1"
    assert deployment.data_dir == config_dir / "data"
    assert next(iter(plan.members.values()))[0].id == "first"


def test_relative_base_assets_and_conflicting_profile_definitions(tmp_path, monkeypatch):
    base = tmp_path / "base.yaml"
    base.write_text("id: local-base\nprotocol: http\nhttp_versions: ['2', '3']\n")
    (tmp_path / "body.bin").write_bytes(b"\x00\xff")
    first = write_profile(tmp_path, "first", requirements={"protocol": "https",
        "http_versions": ["2", "3"], "base_profile": "base.yaml", "base_version": "1"},
        behaviors=[{"id": "binary", "match": {"path": "/binary"}, "reply": {"body_file": "body.bin"}}])
    config = tmp_path / "deployment.yaml"
    config.write_text("deceptions:\n  - profile: first.yaml\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    plan = resolve(load_deployment(config))
    assert next(iter(plan.profiles.values())).behaviors[0].reply.body_base64 == "AP8="
    duplicate = elsewhere / "duplicate.yaml"
    duplicate.write_text(first.read_text().replace("base.yaml", str(base)).replace("body.bin", str(tmp_path / "body.bin"))
                         .replace("/binary", "/different"))
    with pytest.raises(ValueError, match="Conflicting definitions"):
        resolve(Deployment(deceptions=[{"profile": str(first)}, {"profile": str(duplicate)}]))


@pytest.mark.asyncio
async def test_start_revalidates_before_creating_data_or_opening_sockets(tmp_path):
    config = Deployment(data_dir=tmp_path / "data", listeners=[
        Listener(name=name, protocol="http", profile="demo-http", port=port)
        for name, port in [("one", 8080), ("two", 8081)]])
    instance = runtime(config)
    instance.listeners["two"].port = 8080
    with pytest.raises(ValueError, match="Listener conflict"):
        await instance.start()
    assert not instance.servers
    assert not config.data_dir.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["2", "3"])
async def test_composed_profiles_share_real_multiplexed_listener(tmp_path, version):
    from deceive.clients import h3_connect

    profiles = [write_profile(tmp_path, name) for name in ("first", "second")]
    config = Deployment(data_dir=tmp_path / "data", listeners=[Listener(name="web", protocol="https",
        profiles=[str(p) for p in profiles], host="127.0.0.1", port=0, quic_port=0, versions=[version])])
    instance = runtime(config)
    try:
        await instance.start()
        endpoints = instance.servers["web"].endpoints
        if version == "3":
            port = next(e["port"] for e in endpoints if e["transport"] == "udp")
            async with h3_connect(port) as client:
                responses = await asyncio.gather(*(client.request("GET", path)
                    for path in ["/first", "/second", "/api/status", "/missing"]))
            assert [r.body for r in responses[:2]] == [b"first", b"second"]
            assert all(r.version == "3" for r in responses)
            assert responses[-1].status == 404
        else:
            port = next(e["port"] for e in endpoints if e["transport"] == "tcp")
            async with httpx.AsyncClient(base_url=f"https://127.0.0.1:{port}", http1=False, http2=True,
                                         verify=False, trust_env=False) as client:
                responses = await asyncio.gather(*(client.get(path)
                    for path in ["/first", "/second", "/api/status", "/missing"]))
            assert [r.content for r in responses[:2]] == [b"first", b"second"]
            assert all(r.http_version == "HTTP/2" for r in responses)
            assert responses[-1].status_code == 404
    finally:
        await instance.close()
    records = [json.loads(line) for line in instance.telemetry.stream.getvalue().splitlines()]
    outputs = [r for r in records if r["message"] == "Deception response"]
    by_path = {r["http_path"]: r for r in outputs}
    assert by_path["/first"]["deception_profile_id"] == "first"
    assert by_path["/second"]["deception_profile_id"] == "second"
    assert all(len(r["deception_profiles"]) == 2 for r in outputs)
    assert len([r for r in records if r["message"] == "Session summary"]) == 4


@pytest.mark.asyncio
async def test_profile_state_is_namespaced_and_sessions_remain_private(tmp_path):
    paths = []
    for name in ("first", "second"):
        paths.append(write_profile(tmp_path, name, stateful=True, behaviors=[
            {"id": "set", "match": {"path": f"/{name}/set"}, "transition": {"flag": "yes"}},
            {"id": "read", "match": {"path": f"/{name}/read", "state": {"flag": "yes"}},
             "reply": {"body": name}},
        ]))
    config = Deployment(data_dir=tmp_path / "data", listeners=[Listener(name="web", protocol="https",
        profiles=[str(p) for p in paths], port=0, host="127.0.0.1", versions=["2"])])
    instance = runtime(config)
    listener = instance.listeners["web"]
    try:
        one = instance.new_session(listener)
        await instance.respond(one, Interaction("http", path="/first/set"))
        assert (await instance.respond(one, Interaction("http", path="/first/read"))).body == b"first"
        assert (await instance.respond(one, Interaction("http", path="/second/read"))).status == 404
        two = instance.new_session(listener)
        assert (await instance.respond(two, Interaction("http", path="/first/read"))).status == 404
    finally:
        await instance.close()
