from base64 import b64decode
import io
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from deceive.cli import deployment_from_args, main, parser
from deceive.config import load_deployment, load_profile, read_yaml
from deceive.interaction import Interaction
from deceive.migrate import migrate
from deceive.models import Deployment, Listener, Profile
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def test_yaml_assets_relative_and_duplicate_keys_rejected(tmp_path):
    (tmp_path / "prompt.txt").write_text("a fixed prompt")
    (tmp_path / "data.bin").write_bytes(b"\x00\xff")
    path = tmp_path / "profile.yaml"
    path.write_text("id: assets\nprotocol: http\nprompt_file: prompt.txt\nbehaviors:\n"
                    "  - id: binary\n    reply: {body_file: data.bin}\n"
                    "fallback_reply: {body_file: data.bin}\n")
    profile = load_profile(str(path))
    assert profile.prompt == "a fixed prompt"
    assert b64decode(profile.behaviors[0].reply.body_base64) == b"\x00\xff"
    assert b64decode(profile.fallback_reply.body_base64) == b"\x00\xff"
    path.write_text("id: first\nid: second\nprotocol: http\n")
    with pytest.raises(ValueError, match="duplicate"):
        read_yaml(path)
    path.write_text("id: unsafe\nprotocol: http\nunknown: secret\n")
    with pytest.raises(ValidationError):
        load_profile(str(path))


def test_yaml_rejects_executable_tags(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("!!python/object/apply:os.system ['touch should-not-exist']")
    with pytest.raises(ValueError):
        read_yaml(path)
    assert not (tmp_path / "should-not-exist").exists()


def test_migration_preserves_accounts_paths_and_reports_changes(tmp_path):
    path = tmp_path / "legacy.ini"
    text = """[ssh]
port = 0
host_priv_key = host_key
listen_host = 127.0.0.1
[honeypot]
log_file = logs/activity.log
[llm]
llm_provider = AWS
model_name = configured-model
temperature = 0.3
trimmer_max_tokens = 64000
api_key = DO-NOT-COPY
[user_accounts]
guest =
root = *
user1 = secret
"""
    path.write_text(text)
    (tmp_path / "prompt.txt").write_text("Fixed legacy persona")
    output = tmp_path / "converted"
    report = migrate(path, output)
    deployment = load_deployment(output / "deployment.yaml")
    assert path.read_text() == text
    assert deployment.log_file == tmp_path / "logs/activity.log"
    assert deployment.listeners[0].host_key == tmp_path / "host_key"
    assert deployment.listeners[0].accounts == {"guest": "", "root": "*", "user1": "secret"}
    assert deployment.providers["default"].kind == "bedrock"
    assert "Fixed legacy persona" in load_profile(deployment.listeners[0].profile).prompt
    assert any("semantics changed" in note for note in report)
    assert "DO-NOT-COPY" not in (output / "deployment.yaml").read_text()
    assert (output / "deployment.yaml").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exist"):
        migrate(path, output)


def test_cli_defaults_and_validation_are_actionable(capsys):
    args = parser().parse_args(["serve"])
    config = deployment_from_args(args)
    assert config.listeners[0].profile == "demo-http"
    assert config.log_file is None
    assert not config.providers
    assert main(["profile", "validate", "demo-http"]) == 0
    assert main(["serve", "--profile", "linux-ssh"]) == 2
    assert "requires a provider" in capsys.readouterr().err


def test_log_shape_base64_and_millisecond_precision():
    stream = io.StringIO()
    telemetry = Telemetry("sensor", stream=stream)
    telemetry.emit("User input", task_name="session-1", details="AP8=")
    record = json.loads(stream.getvalue())
    assert record["timestamp"].endswith("+00:00")
    assert len(record["timestamp"].split(".")[1].split("+")[0]) == 3
    assert {"src_ip", "src_port", "dst_ip", "dst_port", "sensor_protocol", "sensor_name",
            "level", "message", "task_name"} <= record.keys()
    assert b64decode(record["details"]) == b"\x00\xff"


@pytest.mark.asyncio
async def test_summary_race_and_history_cleanup(runtime_factory):
    import asyncio

    runtime = await runtime_factory("ssh", model=True, analyze=True)
    listener = next(iter(runtime.listeners.values()))
    session = runtime.new_session(listener, username="guest")
    await runtime.respond(session, Interaction("ssh", command="hostname"))
    await asyncio.gather(runtime.end_session(session), runtime.end_session(session))
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    summaries = [r for r in records if r["message"] == "Session summary"]
    assert len(summaries) == 1
    assert summaries[0]["judgement"] == "BENIGN"
    assert not session.history and session.id not in runtime.sessions
    assert len(runtime.test_provider.calls) == 1


@pytest.mark.asyncio
async def test_model_history_contains_deterministic_inputs_and_is_bounded(runtime_factory):
    runtime = await runtime_factory("ssh", model=True, limits={"history_turns": 2})
    listener = next(iter(runtime.listeners.values()))
    session = runtime.new_session(listener, username="guest")
    await runtime.respond(session, Interaction("ssh", command="hostname"))
    result = await runtime.respond(session, Interaction("ssh", command="unknown-command"))
    assert result.origin == "llm"
    assert "build-node-03" in runtime.test_provider.calls[0][2].content
    for _ in range(5):
        await runtime.respond(session, Interaction("ssh", command="pwd"))
    assert len(session.history) <= 4


def test_protocol_version_and_unknown_capability_validation(tmp_path):
    with pytest.raises(ValidationError, match="HTTP/3 requires"):
        Listener(protocol="http", profile="demo-http", versions=["3"])
    profile = Profile(id="invalid", protocol="http", behaviors=[{"id": "x", "kind": "no-engine"}])
    with pytest.raises(ValueError, match="Unsupported behavior"):
        Runtime(Deployment(data_dir=tmp_path, listeners=[Listener(protocol="http", profile="invalid")]),
                profiles={"main": profile}, telemetry=Telemetry("test", stream=io.StringIO()))
