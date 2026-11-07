import json
from pathlib import Path
import subprocess

import pytest
import yaml

from deceive.managed import DeploymentManager, DockerCLI, snapshot_profile
from deceive.models import Deployment, Listener, ProviderConfig


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.environments = []
        self.resources = {}
        self.fail_health = False

    def preflight(self):
        self.calls.append(("preflight",))

    def inspect(self, kind, name):
        return self.resources.get((kind, name))

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "exec":
            return subprocess.CompletedProcess(args, int(self.fail_health))
        self.call(*args, **kwargs)
        return subprocess.CompletedProcess(args, 0)

    def call(self, *args, **kwargs):
        self.calls.append(args)
        self.environments.append(kwargs.get('env'))
        if args[:2] == ("image", "inspect"):
            return "sha256:fixture"
        if args[0] in {"volume", "network"}:
            kind, operation = args[:2]
            if operation == "create":
                labels = dict(args[index + 1].split("=", 1) for index, value in enumerate(args) if value == "--label")
                self.resources[kind, args[-1]] = {"Labels": labels}
            else:
                self.resources.pop((kind, args[-1]), None)
            return args[-1]
        if args[0] == "create":
            labels = dict(args[index + 1].split("=", 1) for index, value in enumerate(args) if value == "--label")
            ports = {}
            for index, value in enumerate(args):
                if value == "--publish":
                    host, external, internal = args[index + 1].split(":")
                    ports[internal] = [{"HostIp": host, "HostPort": external}]
            self.resources["container", "fixture-container"] = {"Config": {"Labels": labels},
                "State": {"Status": "created", "Running": False, "ExitCode": 0},
                "NetworkSettings": {"Ports": ports}}
            return "fixture-container"
        info = self.resources.get(("container", args[-1]))
        if args[0] in {"start", "stop"}:
            info["State"].update(Status="running" if args[0] == "start" else "exited",
                                 Running=args[0] == "start")
        if args[0] == "rm":
            self.resources.pop(("container", args[-1]), None)
        return ""


def config(**changes):
    return Deployment(listeners=[Listener(name="web", protocol="http", profile="demo-http", port=18080)], **changes)


def test_missing_network_is_distinct_from_a_missing_daemon(monkeypatch):
    docker = DockerCLI()
    monkeypatch.setattr(docker, "command", lambda *args: subprocess.CompletedProcess(args, 1,
        stdout="", stderr="Error response from daemon: network fixture-net not found"))
    assert docker.inspect("network", "fixture-net") is None
    monkeypatch.setattr(docker, "command", lambda *args: subprocess.CompletedProcess(args, 1,
        stdout="", stderr="Cannot connect to daemon: no such file or directory"))
    with pytest.raises(RuntimeError, match="inspection failed"):
        docker.inspect("network", "fixture-net")


@pytest.mark.asyncio
async def test_lifecycle_restart_and_ownership(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / "state", docker)
    started = await manager.start("portal", config())
    assert started["ready"] and started["listeners"][0]["host"] == "127.0.0.1"
    assert len(manager.list()) == 1
    with pytest.raises(ValueError, match="Stop"):
        manager.remove("portal", remove_data=True)
    with pytest.raises(ValueError, match="options changed"):
        await manager.start("portal", config(), publish=["web=19090"])
    assert manager.stop("portal")["state"] == "exited"
    restarted = await manager.start("portal", None)
    assert restarted["container"] == started["container"] and restarted["volume"] == started["volume"]
    assert sum(call[0] == "create" for call in docker.calls) == 1
    docker.resources["container", restarted["container"]]["Config"]["Labels"]["deceive.managed"] = "someone-else"
    with pytest.raises(ValueError, match="another deployment"):
        manager.stop("portal")


@pytest.mark.asyncio
async def test_changed_configuration_rejected_and_data_retained_on_removal(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path, docker)
    first = await manager.start("portal", config())
    changed = config(sensor_name="changed")
    with pytest.raises(ValueError, match="configuration changed"):
        await manager.start("portal", changed)
    manager.stop("portal")
    assert manager.remove("portal")["data_retained"]
    assert docker.inspect("volume", first["volume"])
    second = await manager.start("portal", changed)
    assert second["volume"] == first["volume"]
    manager.stop("portal")
    assert not manager.remove("portal", remove_data=True)["data_retained"]
    assert docker.inspect("volume", first["volume"]) is None


@pytest.mark.asyncio
async def test_failed_readiness_retains_evidence_and_stops_container(tmp_path):
    docker = FakeDocker()
    docker.fail_health = True
    manager = DeploymentManager(tmp_path, docker)
    with pytest.raises(RuntimeError, match="readiness timed out"):
        await manager.start("portal", config(), timeout=0.01)
    assert manager.status("portal")["state"] == "exited"
    manager.remove("portal", remove_data=True)
    assert not docker.resources


@pytest.mark.asyncio
async def test_failure_before_container_creation_is_still_cleanable(tmp_path, monkeypatch):
    docker = FakeDocker()
    original = docker.call

    def fail_create(*args, **kwargs):
        if args[0] == "create":
            raise RuntimeError("Container creation failed")
        return original(*args, **kwargs)

    monkeypatch.setattr(docker, "call", fail_create)
    manager = DeploymentManager(tmp_path, docker)
    with pytest.raises(RuntimeError, match="creation failed"):
        await manager.start("portal", config())
    assert manager.status("portal")["state"] == "missing"
    assert manager.record("portal")["container"] is None
    manager.remove("portal", remove_data=True)
    assert not docker.resources


@pytest.mark.asyncio
async def test_validation_precedes_docker_and_conflicting_host_translation(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / "state", docker)
    invalid = config()
    invalid.listeners.append(invalid.listeners[0].model_copy(update={"name": "conflict"}))
    with pytest.raises(ValueError, match="bind"):
        await manager.start("portal", invalid)
    assert not docker.calls and not manager.root.exists()
    with pytest.raises(ValueError, match="names must"):
        await manager.start("../escape", config())


def test_profile_snapshot_preserves_inheritance_and_embeds_relative_assets(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    source = tmp_path / "extension.yaml"
    (tmp_path / "asset.bin").write_bytes(b"\x00\xff")
    source.write_text(yaml.safe_dump({"id": "extra", "requirements": {"protocol": "https",
        "base_profile": "demo-http", "base_version": "1", "http_versions": ["2", "3"]},
        "behaviors": [{"id": "extra", "match": {"path": "/extra"}, "reply": {"body_file": "asset.bin"}}]}))
    reference = snapshot_profile(str(source), stage)
    raw = json.loads((stage / Path(reference).name).read_text())
    assert "identity" not in raw and "fallback" not in raw
    assert raw["behaviors"][0]["reply"]["body_base64"] == "AP8="
    assert raw["requirements"]["base_profile"].startswith("/config/profile-")
    assert len(list(stage.glob("profile-*.json"))) == 2


@pytest.mark.asyncio
async def test_provider_secrets_are_mounted_and_forwarded_by_name_only(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PROVIDER_KEY", "private-provider-value")
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / "state", docker)
    deployment = Deployment(providers={"model": ProviderConfig(kind="openai", model="configured-model",
        api_key_env="TEST_PROVIDER_KEY")}, listeners=[Listener(name="ssh", protocol="ssh", profile="linux-ssh",
            port=18022, provider="model")])
    await manager.start("host", deployment)
    command = next(call for call in docker.calls if call[0] == "create")
    assert "TEST_PROVIDER_KEY" in command and not any("private-provider-value" in word for word in command)
    assert all("private-provider-value" not in path.read_text() for path in manager.root.rglob("*.json"))
    manager.stop("host")
    manager.remove("host", remove_data=True)


@pytest.mark.asyncio
async def test_dotenv_and_literal_secrets_reach_only_selected_container(tmp_path):
    from deceive.credentials import literal_name
    from deceive.config import load_deployment

    (tmp_path / '.env').write_text('SELECTED=selected-secret\nUNUSED=unused-secret\nUNRELATED=other-secret\n')
    path = tmp_path / 'deployment.yaml'
    path.write_text(yaml.safe_dump({'env_file': '.env', 'providers': {
        'selected': {'kind': 'openai', 'model': 'model', 'api_key_env': 'SELECTED'},
        'literal': {'kind': 'openai', 'model': 'model', 'api_key': 'literal-secret'},
        'unused': {'kind': 'openai', 'model': 'model', 'api_key_env': 'UNUSED'}},
        'listeners': [{'name': name, 'protocol': 'ssh', 'profile': 'linux-ssh',
                       'port': 18022 + index, 'provider': name}
                      for index, name in enumerate(['selected', 'literal'])]}))
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / 'state', docker)
    await manager.start('host', load_deployment(path))
    command = next(call for call in docker.calls if call[0] == 'create')
    forwarded = {command[index + 1] for index, word in enumerate(command) if word == '--env'}
    assert forwarded == {'SELECTED', literal_name('literal')}
    environment = next(value for value in docker.environments if value is not None)
    assert environment['SELECTED'] == 'selected-secret'
    assert environment[literal_name('literal')] == 'literal-secret'
    assert 'UNUSED' not in environment and 'UNRELATED' not in environment
    snapshot = next(manager.directory('host').glob('snapshot-*/deployment.json'))
    data = json.loads(snapshot.read_text())
    assert set(data['providers']) == {'selected', 'literal'}
    assert data['providers']['selected']['env_file'] is None
    assert data['providers']['literal']['api_key_env'] == literal_name('literal')
    evidence = str(command) + ''.join(p.read_text() for p in manager.root.rglob('*.json'))
    assert all(value not in evidence for value in ('selected-secret', 'literal-secret', 'unused-secret'))
    assert '.env,' not in str(command)
    manager.stop('host')
    manager.remove('host', remove_data=True)


@pytest.mark.asyncio
async def test_named_aws_settings_and_secret_mounts_preserve_configuration(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / "state", docker)
    aws = tmp_path / "aws"
    aws.mkdir()
    (aws / "credentials").write_text("private-aws-content-not-copied")
    deployment = Deployment(providers={"model": ProviderConfig(kind="bedrock", model="configured-model",
        aws_profile="configured-profile", region="eu-west-1")}, listeners=[Listener(name="ssh", protocol="ssh",
        profile="linux-ssh", port=18022, provider="model")])
    with pytest.raises(ValueError, match="--aws-dir"):
        await manager.start("host", deployment)
    assert not docker.resources
    await manager.start("host", deployment, aws_dir=aws)
    snapshot = next(manager.directory("host").glob("snapshot-*/deployment.json"))
    selected = json.loads(snapshot.read_text())["providers"]["model"]
    assert (selected["aws_profile"], selected["region"], selected["model"]) == (
        "configured-profile", "eu-west-1", "configured-model")
    command = next(call for call in docker.calls if call[0] == "create")
    assert any("target=/home/deceive/.aws,readonly" in value for value in command)
    assert all("private-aws-content-not-copied" not in path.read_text() for path in manager.root.rglob("*.json"))
    manager.stop("host")
    manager.remove("host", remove_data=True)


@pytest.mark.asyncio
async def test_https3_mapping_and_advertisement_are_explicit(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / "state", docker)
    deployment = Deployment(listeners=[Listener(name="web", protocol="https", profile="demo-http",
        port=18443, versions=["2", "3"])])
    result = await manager.start("portal", deployment, publish=["web=19443"])
    assert {b["transport"] for b in result["listeners"][0]["bindings"]} == {"tcp", "udp"}
    snapshot = next(manager.directory("portal").glob("snapshot-*/deployment.json"))
    assert json.loads(snapshot.read_text())["listeners"][0]["advertised_port"] == 19443
    manager.stop("portal")
    manager.remove("portal", remove_data=True)


@pytest.mark.asyncio
async def test_start_defaults_to_in_container_preflight_and_skip_is_explicit(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / 'state', docker)
    await manager.start('checked', config())
    command = next(call for call in docker.calls if call[0] == 'create')
    assert '--preflight' in command
    assert sum(call[0] == 'start' for call in docker.calls) == 1
    await manager.start('checked', None)
    assert sum(call[0] == 'start' for call in docker.calls) == 1
    manager.stop('checked')
    await manager.start('checked', None)
    assert sum(call[0] == 'start' for call in docker.calls) == 2
    await manager.start('unchecked', config(), skip_preflight=True)
    command = [call for call in docker.calls if call[0] == 'create'][-1]
    assert '--preflight' not in command


@pytest.mark.asyncio
async def test_retained_preflight_policy_cannot_silently_change(tmp_path):
    docker = FakeDocker()
    manager = DeploymentManager(tmp_path / 'state', docker)
    await manager.start('checked', config())
    manager.stop('checked')
    with pytest.raises(ValueError, match='retains its preflight policy'):
        await manager.start('checked', None, skip_preflight=True)
    record = manager.record('checked')
    record['options'].pop('skip_preflight')
    from deceive.managed import write_json
    write_json(manager.directory('checked') / 'record.json', record)
    with pytest.raises(ValueError, match='predates startup preflight'):
        await manager.start('checked', None)
    assert sum(call[0] == 'start' for call in docker.calls) == 1
