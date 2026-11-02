from base64 import b64decode
from importlib.resources import files
import asyncio
import io
import json
from pathlib import Path

import asyncssh
import httpx
import pytest

from deceive.config import load_deployment, load_profile
from deceive.evaluate import evaluate
from deceive.models import Behavior


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["sudo-2019-14287", "apache-2021-41773"])
async def test_approved_reference_acceptance_suite(tmp_path, name):
    suite = files("deceive").joinpath("acceptance", name + ".yaml")
    report = await evaluate(name, suite, tmp_path / "report")
    approval = json.loads(files("deceive").joinpath("acceptance/reference-approval.json").read_text())
    assert report["suite_fingerprint"] == approval["suites"][name]
    assert report["passed"], report
    assert report["passed_cases"] == report["total_cases"]
    assert report["held_out_pass_rate"] == 1.0
    summaries = [event for case in report["cases"] for event in case.get("telemetry", [])
                 if event["message"] == "Session summary"]
    assert summaries and all(event["judgement"] == "UNKNOWN" for event in summaries)


@pytest.mark.asyncio
async def test_apache_preserves_encoded_path_and_never_reads_host_files(runtime_factory, tmp_path):
    profile = load_profile("apache-2021-41773")
    runtime = await runtime_factory(profile=profile)
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    secret = tmp_path / "host-only-secret"
    secret.write_text("PRIVATE-HOST-DATA")
    traversal = "/cgi-bin/" + ".%2e/" * 4
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
        response = await client.get(traversal + "etc/passwd")
        assert response.status_code == 200 and "archive:x:" in response.text
        unknown = await client.get(traversal + str(secret).lstrip("/"))
        assert unknown.status_code == 404
        assert "PRIVATE-HOST-DATA" not in unknown.text
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    input_event = next(r for r in records if r["message"] == "User input")
    request = json.loads(b64decode(input_event["details"]))
    assert b64decode(request["raw_path"]) == (traversal + "etc/passwd").encode()
    assert "PRIVATE-HOST-DATA" not in runtime.test_stream.getvalue()


@pytest.mark.asyncio
async def test_sudo_uses_virtual_identity_and_rejects_shell_execution(runtime_factory, tmp_path):
    runtime = await runtime_factory("ssh", profile=load_profile("sudo-2019-14287"))
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    marker = tmp_path / "must-not-be-created"
    async with asyncssh.connect("127.0.0.1", port=port, username="guest", known_hosts=None) as connection:
        result = await connection.run(f"sudo -u#-1 /bin/sh -c 'touch {marker}'")
        assert result.exit_status == 1
        assert "not permitted" in result.stdout
    assert not marker.exists()
    async with asyncssh.connect("127.0.0.1", port=port, username="intruder", password="x", known_hosts=None) as connection:
        result = await connection.run("sudo -u#-1 id -u")
        assert result.exit_status == 1 and "not in the sudoers" in result.stdout


def test_cve_options_are_validated_before_listening():
    from deceive.behaviors import validate_behavior

    with pytest.raises(ValueError):
        validate_behavior(Behavior(id="bad", kind="apache-2021-41773", options={"alias_prefix": "../"}))
    with pytest.raises(ValueError):
        validate_behavior(Behavior(id="bad", kind="sudo-2019-14287", options={"execute": True}))
    profile = load_profile("apache-2021-41773")
    profile.http_versions = ["1.1", "3"]
    with pytest.raises(ValueError, match="HTTP/1.1 only"):
        validate_behavior(profile.behaviors[0], profile)


@pytest.mark.asyncio
async def test_reference_deployment_runs_both_protocols_in_one_process(tmp_path):
    from deceive.runtime import Runtime
    from deceive.telemetry import Telemetry

    path = Path(__file__).resolve().parents[1] / "examples/reference-deployment.yaml"
    config = load_deployment(path)
    config.data_dir = tmp_path
    for listener in config.listeners:
        listener.host, listener.port = "127.0.0.1", 0
    stream = io.StringIO()
    runtime = Runtime(config, telemetry=Telemetry("reference", stream=stream))
    try:
        await runtime.start()
        assert set(runtime.servers) == {"sudo", "apache"}

        async def ssh_probe():
            port = runtime.servers["sudo"].endpoints[0]["port"]
            async with asyncssh.connect("127.0.0.1", port=port, username="guest", known_hosts=None) as connection:
                result = await connection.run("sudo -u#-1 id -u")
                assert result.stdout == "0\n"

        async def http_probe():
            port = runtime.servers["apache"].endpoints[0]["port"]
            async with httpx.AsyncClient(trust_env=False) as client:
                result = await client.get(f"http://127.0.0.1:{port}/cgi-bin/" + ".%2e/" * 4 + "etc/passwd")
                assert result.status_code == 200 and "archive:x:" in result.text

        await asyncio.gather(ssh_probe(), http_probe())
    finally:
        await runtime.close()
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    summaries = [record for record in records if record["message"] == "Session summary"]
    assert len(summaries) == 2
    assert len({record["task_name"] for record in summaries}) == 2
    assert {record["protocol_instance"] for record in summaries} == {"sudo", "apache"}
